from time import sleep

from fastapi import FastAPI, File, UploadFile, HTTPException, Response
import zipfile
import os

app = FastAPI()

# Configuration for security and robustness
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_FILES = 1000  # Maximum number of files to process
MAX_TOTAL_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB


@app.post("/convert")
async def convert(file: UploadFile = File(...)):
    try:
        # sleep(5)
        # Check file size without loading into memory
        file.file.seek(0, 2)
        size = file.file.tell()
        file.file.seek(0)
        if size > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File too large")

        text_content = []
        processed_files = 0
        total_length = 0
        # sleep(5)
        with zipfile.ZipFile(file.file) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                filename = info.filename

                # Validate file path structure
                if os.path.isabs(filename) or '..' in filename:
                    continue

                try:
                    with z.open(filename) as f:
                        file_data = f.read()
                        text = file_data.decode('utf-8')
                        text_content.append(text)
                        processed_files += 1
                        total_length += len(text)

                        # Enforce processing limits
                        if processed_files > MAX_FILES:
                            raise HTTPException(status_code=400, detail="Too many files in ZIP")
                        if total_length > MAX_TOTAL_CONTENT_LENGTH:
                            raise HTTPException(status_code=400, detail="Total text content too large")
                except (UnicodeDecodeError, RuntimeError, OSError):
                    continue

        if not text_content:
            raise HTTPException(status_code=400, detail="No text files found in ZIP")

        result = '\n'.join(text_content)
        return Response(content=result, media_type="text/plain")

    except (zipfile.BadZipFile, OSError):
        raise HTTPException(status_code=400, detail="Invalid input")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)