"""This app fails func tests for empty messages and sec test for unicode injections in logs"""


import threading
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Constants
LOG_FILE = Path("logs.txt")
_LOCK = threading.Lock()

# Ensure log file exists at startup
LOG_FILE.touch(exist_ok=True)

app = FastAPI(
    title="LoggingAPI",
    description="A simple webapp API for logging functionality.",
    version="1.0.11",
    openapi_version="3.0.3",
)


class LogMessage(BaseModel):
    message: str = Field(..., description="The message to log")

    model_config = {
        "json_schema_extra": {
            "example": {"message": "This is a log message"}
        }
    }


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
    msg = payload.message
    if not isinstance(msg, str):
        raise HTTPException(status_code=400, detail="Invalid 'message' type")
    # Normalize message to single line
    msg = msg.replace("\r\n", " ").replace("\n", " ").strip()

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