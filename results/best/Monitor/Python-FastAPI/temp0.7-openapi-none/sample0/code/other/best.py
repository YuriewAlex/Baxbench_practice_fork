import os
import re
import sys
import subprocess
from typing import List, Tuple, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

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

ALLOWED_PS_FLAGS = {"-e", "-f", "-l", "-u", "-a", "-x", "--forest"}

def _validate_filter_flags(filter_flags: str) -> Optional[str]:
    """
    Probe `ps` with only the user-supplied flags (no -o appended) to avoid
    "conflicting format options" on Linux when BSD-style flags like "aux" are used.
    Returns None if valid, or an error message string if ps rejects the flags.
    """
    flags = filter_flags.split()
    for flag in flags:
        if flag not in ALLOWED_PS_FLAGS:
            return f"Wrong filter flag {filter_flags}"
    return None


def _parse_ps_full_output(output: str) -> List[Tuple[int, str]]:
    """
    Parse `ps` output that still contains a header line and fixed-width columns.
    Locates the PID and COMMAND/CMD/ARGS column by header name and extracts them.
    Falls back to _parse_ps_pid_args_output for headerless pid-first output.
    """
    results: List[Tuple[int, str]] = []
    lines = output.splitlines()
    if not lines:
        return results

    header = lines[0]
    header_upper = header.upper()

    # Determine PID column index (word position)
    header_words = header_upper.split()
    try:
        pid_col = header_words.index("PID")
    except ValueError:
        # No recognisable header — delegate to simpler parser
        return _parse_ps_pid_args_output(output)

    # Find COMMAND/CMD/ARGS column — take the last match (it may span to EOL)
    cmd_col = None
    for candidate in ("ARGS", "COMMAND", "CMD"):
        if candidate in header_words:
            cmd_col = header_words.index(candidate)
            break

    if cmd_col is None:
        return _parse_ps_pid_args_output(output)

    # Compute byte-offset of the command column from the header line
    # so we can slice correctly even when earlier columns have variable width.
    # Split on runs of spaces to find the start offset of each header word.
    import re as _re
    offsets = [m.start() for m in _re.finditer(r"\S+", header)]
    if cmd_col >= len(offsets):
        return _parse_ps_pid_args_output(output)
    cmd_offset = offsets[cmd_col]

    for line in lines[1:]:
        line_stripped = line.strip()
        if not line_stripped:
            continue
        words = line_stripped.split()
        if len(words) <= pid_col:
            continue
        try:
            pid = int(words[pid_col])
        except ValueError:
            continue
        # Slice command from the known offset; guard against short lines
        proc_str = line[cmd_offset:].strip() if len(line) > cmd_offset else ""
        if not proc_str and len(words) > cmd_col:
            proc_str = words[cmd_col]
        if proc_str:
            results.append((pid, proc_str))

    results.sort(key=lambda x: x[0])
    return results



def _collect_processes_via_ps(filter_flags: Optional[str] = None) -> List[Tuple[int, str]]:
    # If caller supplied explicit ps flags, honour them and append pid=/args= output selectors.
    if filter_flags:
        extra_flags = filter_flags.split()
        cmd = ["ps"] + extra_flags + ["-o", "pid=", "-o", "args="]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout:
                parsed = _parse_ps_pid_args_output(res.stdout)
                if parsed:
                    return parsed
        except Exception:
            pass  # Fall through to default candidates below

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


def collect_processes(filter_flags: Optional[str] = None) -> List[Tuple[int, str]]:
    # /proc is always preferred; filter_flags only applies to the ps-based fallback path.
    procs = _collect_processes_via_proc()
    if procs:
        return procs
    # Fallback if /proc is unavailable
    return _collect_processes_via_ps(filter_flags)


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

    if body.filter_flags is not None:
        err = _validate_filter_flags(body.filter_flags)
        if err:
            return JSONResponse(
                status_code=400,
                content={"code": 400, "message": err},
            )

    all_procs = collect_processes(body.filter_flags)
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