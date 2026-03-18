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
    lines = output.splitlines()

    if not lines:
        return results

    pid_col_index = 0
    args_col_index = 1
    first_line = lines[0].strip().upper()

    if first_line and not first_line[0].isdigit():
        headers = first_line.split()
        try:
            pid_col_index = headers.index("PID")
        except ValueError:
            pass

        for candidate in ("ARGS", "COMMAND", "CMD"):
            if candidate in headers:
                args_col_index = headers.index(candidate)
                break

        lines = lines[1:]

    for line in lines:
        line = line.strip()
        if not line:
            continue

        parts = line.split(None, args_col_index + 1)

        if len(parts) <= max(pid_col_index, args_col_index):
            continue

        try:
            pid = int(parts[pid_col_index])
        except ValueError:
            continue

        args = parts[args_col_index] if len(parts) > args_col_index else ""

        if not args:
            continue

        results.append((pid, args))

    results.sort(key=lambda x: x[0])
    return results



def _parse_flags(token: str) -> list[str]:
    if token.startswith("--"):
        return [token]
    letters = token.lstrip("-")
    return [f"-{ch}" for ch in letters]

ALLOWED_PS_SHORT_FLAGS = set("aAdDeNfFlLrTuxgwH")
SHORT_FLAGS_WITH_ARGS = {"u", "U", "p", "g", "G", "C", "t", "s"}
ALLOWED_PS_LONG_FLAGS = {"--forest", "--no-headers", "--deselect"}
LONG_FLAGS_WITH_ARGS = {
    "--pid", "--ppid", "--user", "--group",
    "--sid", "--tty", "--sort",
}


def _validate_filter_flags(filter_flags: str) -> Optional[str]:
    tokens = filter_flags.split()
    i = 0

    while i < len(tokens):
        token = tokens[i]

        if token.startswith("--"):
            if "=" in token:
                flag, value = token.split("=", 1)
                if flag not in LONG_FLAGS_WITH_ARGS:
                    return f"Unacceptable flag: {flag!r}"
                if not value:
                    return f"Empty value for flag {flag!r}"
            elif token in ALLOWED_PS_LONG_FLAGS:
                pass
            elif token in LONG_FLAGS_WITH_ARGS:
                if i + 1 >= len(tokens):
                    return f"Flag {token!r} requires an argument"
                i += 1  # пропускаем аргумент
            else:
                return f"Unacceptable flag: {token!r}"

            i += 1
            continue

        if token.startswith("-"):
            letters = token[1:]
            if not letters:
                return f"Empty flag: {token!r}"

            j = 0
            while j < len(letters):
                ch = letters[j]

                if ch in SHORT_FLAGS_WITH_ARGS:

                    remainder = letters[j + 1:]
                    if remainder:

                        break
                    else:

                        if i + 1 >= len(tokens):
                            return f"Flag -{ch!r} requires an argument"
                        i += 1
                        break

                elif ch in ALLOWED_PS_SHORT_FLAGS:
                    j += 1
                    continue

                else:
                    return f"Unacceptable symbol {ch!r} in {token!r}"

            i += 1
            continue

        for ch in token:
            if ch not in ALLOWED_PS_SHORT_FLAGS and ch not in SHORT_FLAGS_WITH_ARGS:
                return f"Unacceptable symbol {ch!r} in {token!r}"

        i += 1

    return None




def _collect_processes_via_ps(filter_flags: Optional[str] = None) -> List[Tuple[int, str]]:
    # If caller supplied explicit ps flags, honour them and append pid=/args= output selectors.
    if filter_flags:
        extra_flags = filter_flags.split()
        cmd = ["ps"] + extra_flags
        try:
            res = subprocess.run(" ".join(cmd), capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout:
                parsed = _parse_ps_pid_args_output(res.stdout)
                if parsed:
                    return parsed
        except Exception:
            pass  # Fall through to default candidates below

    # We intentionally avoid using the unsupported 'command' output selector.
    candidates = [
        ["ps", "ax",  "-o", "pid=", "-o", "args="],          # Common on Linux
        ["ps", "-axo", "pid=,args="],         # Common on macOS/BSD
        ["ps", "ax", "-o", "pid=", "-o", "args="],  # Another portable form
    ]
    for cmd in candidates:
        try:
            res = subprocess.run(" ".join(cmd), capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout:
                parsed = _parse_ps_pid_args_output(res.stdout)
                if parsed:
                    return parsed
        except Exception:
            continue
    # If all candidates fail, return empty list (no use of 'command' as per constraint)
    return []


def collect_processes(filter_flags: Optional[str] = None) -> List[Tuple[int, str]]:
    procs = _collect_processes_via_proc()
    ps_procs = _collect_processes_via_ps(filter_flags)
    return ps_procs if len(ps_procs) > len(procs) else procs


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