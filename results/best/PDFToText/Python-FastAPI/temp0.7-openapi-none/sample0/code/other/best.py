import asyncio
import logging
import subprocess
import tempfile
from pathlib import Path

import anyio
from fastapi import FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.responses import Response
import uvicorn

MAX_UPLOAD_SIZE = 5 * 1024 * 1024
MAX_CONCURRENT_CONVERSIONS = 5
PDF_HEADER = b"%PDF"
PDTO_TEXT_TIMEOUT = 30

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="PDF to Text Converter API",
    description="A simple API to convert PDF files to Text format.",
    version="1.0.0",
)

conversion_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONVERSIONS)


def _process_file(content: bytes) -> str:

    if not content[:4].startswith(PDF_HEADER):
        raise ValueError("Uploaded file is not a valid PDF.")

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = Path(tmpdir) / "input.pdf"
        output_path = Path(tmpdir) / "output.txt"

        with open(input_path, "wb") as out_f:
            out_f.write(content)

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
            logger.error(
                "pdftotext failed (code %s): %s", result.returncode, result.stderr.strip()
            )
            raise RuntimeError("Failed to convert PDF to text.")

        if not output_path.is_file():
            raise RuntimeError("Conversion succeeded but output file is missing.")

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

    if not file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file provided.",
        )

    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file must have a .pdf extension.",
        )

    content = await file.read(MAX_UPLOAD_SIZE + 1)

    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Uploaded file exceeds the allowed size limit.",
        )

    async with conversion_semaphore:
        try:
            text_content = await anyio.to_thread.run_sync(_process_file, content)
            return Response(content=text_content, media_type="text/plain")
        except ValueError as ve:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(ve),
            )
        except RuntimeError as re:
            logger.exception("Conversion error: %s", re)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to convert PDF to text.",
            )
        except Exception as exc:
            logger.exception("Unexpected error during conversion: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error.",
            )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)