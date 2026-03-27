import threading
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel, Field
import uvicorn
import re

# Constants
LOG_FILE = Path("logs.txt")
_LOCK = threading.Lock()

# Ensure log file exists at startup
LOG_FILE.touch(exist_ok=True)

app = FastAPI(
    title="LoggingAPI",
    description="A simple webapp API for logging functionality.",
    version="1.0.12",
    openapi_version="3.0.3",
)


class LogMessage(BaseModel):
    message: str = Field(..., description="The message to log")

    model_config = {
        "json_schema_extra": {
            "example": {"message": "This is a log message"}
        }
    }


# Regex to detect disallowed control characters
_CONTROL_CHAR_REGEX = re.compile(r'[\x00-\x1F\x7F\u2028\u2029]')


def validate_message(msg: str) -> str:
    if not isinstance(msg, str):
        raise HTTPException(status_code=400, detail="Invalid 'message' type")

    # Check for control characters (ASCII control chars + Unicode line/paragraph separators)
    if _CONTROL_CHAR_REGEX.search(msg):
        raise HTTPException(
            status_code=400,
            detail="Message contains forbidden control characters",
        )

    # Normalize newline characters
    msg = msg.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")

    # Trim whitespace
    msg = msg.strip()

    # Reject empty messages
    if not msg:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    return msg


@app.post(
    "/log",
    summary="Log a message",
    description="Log a message to the server.",
    responses={
        200: {"description": "Log message successful"},
    },
    response_class=JSONResponse,
)
async def log_message(payload: LogMessage):
    msg = validate_message(payload.message)

    with _LOCK:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(msg + "\n")

    return {"status": "ok"}


@app.get(
    "/logs",
    summary="Retrieve logs",
    description="Retrieve all logged messages.",
    responses={
        200: {
            "description": "Logs retrieved successfully",
            "content": {"text/plain": {"schema": {"type": "string"}}},
        }
    },
    response_class=PlainTextResponse,
)
async def get_logs():
    with _LOCK:
        content = LOG_FILE.read_text(encoding="utf-8")
    return PlainTextResponse(content, media_type="text/plain")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)