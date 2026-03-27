import asyncio
import logging
import os
import subprocess
import tempfile
from pathlib import Path

import anyio
from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send
import uvicorn

# -------------------- Configuration --------------------
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_CONCURRENT_CONVERSIONS = 5
PDF_HEADER = b"%PDF"
PDTO_TEXT_TIMEOUT = 30  # seconds
# -------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="PDF to Text Converter API",
    description="A simple API to convert PDF files to Text format.",
    version="1.0.0",
)


# -------------------- Middleware --------------------
class LimitUploadSizeMiddleware(BaseHTTPMiddleware):
    """
    Reject requests with a Content-Length header larger than the allowed limit.
    For streaming/chunked requests, the limit is enforced while reading the body.
    """

    def __init__(self, app: ASGIApp, max_upload_size: int):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_upload_size:
                    return Response(
                        content="Payload too large.",
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    )
            except ValueError:
                # If header is malformed, let the request proceed to be handled later
                pass

        # For cases without Content-Length (e.g., chunked), we wrap the receive
        # function to enforce the limit while streaming.
        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await request.receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                received += len(body)
                if received > self.max_upload_size:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Payload too large.",
                    )
            return message

        try:
            request._receive = limited_receive  # type: ignore
            response = await call_next(request)
            return response
        except HTTPException as exc:
            return Response(
                content=exc.detail,
                status_code=exc.status_code,
            )


app.add_middleware(LimitUploadSizeMiddleware, max_upload_size=MAX_UPLOAD_SIZE)
# -------------------------------------------------------


# Semaphore to limit concurrent conversions
conversion_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONVERSIONS)


def _process_file(file: UploadFile) -> str:
    """
    Blocking helper that validates the uploaded file, writes it to a temporary location,
    runs `pdftotext`, and returns the extracted text.
    Raises:
        ValueError: for client‑side validation errors.
        RuntimeError: for conversion failures.
    """
    # Ensure a filename is provided (used only for logging / sanity)
    if not file.filename:
        raise ValueError("No filename provided.")

    # Create a temporary directory for the conversion
    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = Path(tmpdir) / "input.pdf"
        output_path = Path(tmpdir) / "output.txt"

        # Write the uploaded file to disk while validating PDF header and size
        total_written = 0
        with open(input_path, "wb") as out_f:
            # Read first chunk to validate PDF header
            first_chunk = file.file.read(4)
            if not first_chunk.startswith(PDF_HEADER):
                raise ValueError("Uploaded file is not a valid PDF.")
            out_f.write(first_chunk)
            total_written += len(first_chunk)

            # Continue streaming the rest of the file
            while True:
                chunk = file.file.read(8192)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > MAX_UPLOAD_SIZE:
                    raise ValueError("Uploaded file exceeds the allowed size limit.")
                out_f.write(chunk)

        # Ensure the file pointer is closed/reset for safety
        file.file.close()

        # Run pdftotext with a timeout to avoid hanging
        try:
            result = subprocess.run(
                ["pdftotext", str(input_path), str(output_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
                timeout=PDTO_TEXT_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("PDF conversion timed out.")

        if result.returncode != 0:
            # Log the detailed error internally but do not expose it to the client
            logger.error(
                "pdftotext failed (code %s): %s", result.returncode, result.stderr.strip()
            )
            raise RuntimeError("Failed to convert PDF to text.")

        if not output_path.is_file():
            raise RuntimeError("Conversion succeeded but output file is missing.")

        # Read and return the extracted text
        with open(output_path, "r", encoding="utf-8") as txt_f:
            return txt_f.read()


@app.post(
    "/convert",
    responses={
        200: {
            "content": {"text/plain": {"schema": {"type": "string"}}},
            "description": "Successfully converted PDF to text",
        },
        400: {"description": "Bad Request - Invalid input or missing file"},
        500: {"description": "Internal Server Error - Conversion failed"},
    },
)
async def convert_pdf_to_text(file: UploadFile = File(...)):
    """
    Convert an uploaded PDF file to plain text using the `pdftotext` utility.
    """
    if not file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file provided.",
        )

    # Enforce .pdf extension as an additional hint (not a security check)
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a .pdf extension.",
        )

    async with conversion_semaphore:
        try:
            # Run the blocking conversion in a thread pool to keep the event loop responsive
            text_content = await anyio.to_thread.run_sync(_process_file, file)
            return Response(content=text_content, media_type="text/plain")
        except ValueError as ve:
            # Client‑side validation error
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(ve),
            )
        except RuntimeError as re:
            # Server‑side conversion error (generic message for security)
            logger.exception("Conversion error: %s", re)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to convert PDF to text.",
            )
        except Exception as exc:
            # Unexpected error
            logger.exception("Unexpected error during conversion: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error.",
            )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)