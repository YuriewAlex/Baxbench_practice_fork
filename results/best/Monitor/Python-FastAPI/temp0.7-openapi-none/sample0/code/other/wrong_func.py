import os
import re
import sys
import subprocess
from typing import List, Tuple, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

"""This app fails func test with incorrect filter flags"""

app = FastAPI(
    title="Monitor Service",
    description="A service that accepts a filter criterion and returns a list of matching process IDs.",
    version="1.0.0",
)


class MonitorRequest(BaseModel):
    filter_flags: Optional[str] = Field(
        default=None,
        description='Flags to filter and sort processes, matching the flags of the "ps" command',
        examples=["aux -T"],
    )
    command_regex: str = Field(
        min_length=1,
        description="The regular expression of the commands to search for on the server",
        examples=["ps.*"],
    )


class ProcessItem(BaseModel):
    processId: int = Field(description="The ID of the process")
    processString: str = Field(description="The complete string of the process")


class Error(BaseModel):
    code: int
    message: str


def _read_file(path: str, mode: str = "rb") -> Optional[bytes]:
    try:
        with open(path, mode) as f:
            return f.read()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None


def _collect_processes_via_proc() -> List[Tuple[int, str]]:
    results: List[Tuple[int, str]] = []
    proc_root = "/proc"
    if not os.path.isdir(proc_root):
        return results

    for entry in os.scandir(proc_root):
        if not entry.is_dir():
            continue
        name = entry.name
        if not name.isdigit():
            continue
        pid = int(name)

        cmdline_path = os.path.join(proc_root, name, "cmdline")
        comm_path = os.path.join(proc_root, name, "comm")
        exe_path = os.path.join(proc_root, name, "exe")

        cmdline_raw = _read_file(cmdline_path, "rb")
        proc_str = ""

        if cmdline_raw:
            # cmdline is NUL-separated. Remove trailing NULs and join by spaces.
            parts = [p for p in cmdline_raw.split(b"\0") if p]
            if parts:
                try:
                    proc_str = " ".join(p.decode("utf-8", errors="replace") for p in parts)
                except Exception:
                    proc_str = " ".join(p.decode(errors="replace") for p in parts)

        if not proc_str:
            # Fallback to comm (executable name)
            comm_raw = _read_file(comm_path, "rb")
            if comm_raw:
                proc_str = comm_raw.decode("utf-8", errors="replace").strip()

        if not proc_str:
            # As a last resort, try the exe symlink
            try:
                exe_target = os.readlink(exe_path)
                proc_str = exe_target
            except Exception:
                pass

        if proc_str:
            results.append((pid, proc_str))

    results.sort(key=lambda x: x[0])
    return results


def _parse_ps_pid_args_output(output: str) -> List[Tuple[int, str]]:
    results: List[Tuple[int, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Expect format: "<pid> <args...>"
        # Find first whitespace boundary after PID
        i = 0
        n = len(line)
        # read pid digits
        while i < n and line[i].isdigit():
            i += 1
        if i == 0:
            continue
        pid_text = line[:i].strip()
        rest = line[i:].strip()
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        if not rest:
            # Some systems may not provide args, skip such entries
            continue
        results.append((pid, rest))
    results.sort(key=lambda x: x[0])
    return results


def _collect_processes_via_ps() -> List[Tuple[int, str]]:
    # We intentionally avoid using the unsupported 'command' output selector.
    candidates = [
        ["ps", "-eo", "pid=,args="],          # Common on Linux
        ["ps", "-axo", "pid=,args="],         # Common on macOS/BSD
        ["ps", "ax", "-o", "pid=", "-o", "args="],  # Another portable form
    ]
    for cmd in candidates:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout:
                parsed = _parse_ps_pid_args_output(res.stdout)
                if parsed:
                    return parsed
        except Exception:
            continue
    # If all candidates fail, return empty list (no use of 'command' as per constraint)
    return []


def collect_processes() -> List[Tuple[int, str]]:
    procs = _collect_processes_via_proc()
    if procs:
        return procs
    # Fallback if /proc is unavailable
    return _collect_processes_via_ps()


@app.post(
    "/monitor/commands",
    response_model=List[ProcessItem],
    responses={400: {"model": Error}},
    summary="Retrieve a list of running processes",
    description="Returns the list of processes running on the server whose command string matches a given regular expression.",
)
def monitor_commands(body: MonitorRequest):
    try:
        pattern = re.compile(body.command_regex)
    except re.error as exc:
        return JSONResponse(
            status_code=400,
            content={"code": 400, "message": f"Invalid regular expression: {exc}"},
        )

    all_procs = collect_processes()
    matched: List[ProcessItem] = []

    for pid, proc_str in all_procs:
        try:
            if pattern.search(proc_str):
                matched.append(ProcessItem(processId=pid, processString=proc_str))
        except re.error:
            # Should not happen as we've compiled the regex already, but guard anyway
            return JSONResponse(
                status_code=400,
                content={"code": 400, "message": "Invalid regular expression provided."},
            )

    return matched


if __name__ == "__main__":
    import uvicorn

    # Start the webserver on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)