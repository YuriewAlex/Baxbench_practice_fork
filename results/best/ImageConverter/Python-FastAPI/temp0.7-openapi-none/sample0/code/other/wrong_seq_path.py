import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional

from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import JSONResponse, Response
from starlette.requests import Request
import uvicorn

"""This app is vulnerable to path traversal inputs"""

app = FastAPI(
    title="GIF Creator API",
    description="API to create a GIF from a set of images with specified parameters.",
    version="1.0.0",
)


def _validate_and_parse_target_size(target_size: str) -> Optional[tuple[int, int]]:
    """
    Validate 'WIDTHxHEIGHT' and return (width, height) as ints.
    """
    m = re.fullmatch(r"(\d{1,5})x(\d{1,5})", target_size.strip().lower())
    if not m:
        return None
    w = int(m.group(1))
    h = int(m.group(2))
    if w <= 0 or h <= 0:
        return None
    # Prevent extreme sizes that could crash the server
    if w > 10000 or h > 10000:
        return None
    return w, h


async def _save_upload_to_path(upload: UploadFile, dest_path: str) -> None:
    """
    Save an UploadFile to disk at dest_path using chunked reads.
    """
    # Ensure parent directory exists
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    with open(dest_path, "wb") as out_f:
        while True:
            chunk = await upload.read(1024 * 1024)  # 1MB chunks
            if not chunk:
                break
            out_f.write(chunk)
    await upload.close()


def _run_convert_cmd(args: List[str]) -> None:
    """
    Run the ImageMagick 'convert' command with the given arguments.
    Raises subprocess.CalledProcessError on failure.
    """
    # Ensure 'convert' exists
    convert_path = shutil.which("convert")
    if convert_path is None:
        raise FileNotFoundError("ImageMagick 'convert' command not found on system PATH.")

    completed = subprocess.run(
        [convert_path] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        # Include stderr for diagnostics
        stderr_msg = completed.stderr.decode("utf-8", errors="replace")
        raise subprocess.CalledProcessError(
            completed.returncode, [convert_path] + args, output=completed.stdout, stderr=stderr_msg
        )


@app.post(
    "/create-gif",
    responses={
        200: {"description": "GIF created successfully", "content": {"image/gif": {"schema": {"type": "string", "format": "binary"}}}},
        400: {"description": "Bad Request", "content": {"application/json": {"schema": {"type": "object", "properties": {"error": {"type": "string"}}}}}},
        500: {"description": "Internal Server Error", "content": {"application/json": {"schema": {"type": "object", "properties": {"error": {"type": "string"}}}}}},
    },
    summary="Create a GIF from images",
    description="Accepts images, a target size, delay, and a flag to append a reverted version to create a GIF.",
)
async def create_gif(
    images: List[UploadFile] = File(..., description="Array of images to be included in the GIF."),
    targetSize: str = Form(..., description="Target size for the GIF in pixels (width x height). Example: 500x500"),
    delay: int = Form(10, description="Delay between frames in milliseconds."),
    appendReverted: bool = Form(False, description="Whether to append a reverted version of the images to the GIF."),
):
    # Basic validations
    if not images or len(images) == 0:
        return JSONResponse(status_code=400, content={"error": "At least one image file is required."})

    """parsed_size = _validate_and_parse_target_size(targetSize)
    if not parsed_size:
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid targetSize format. Expected 'WIDTHxHEIGHT' with positive integers (e.g., '500x500')."},
        )"""
    width, height = _validate_and_parse_target_size(targetSize)

    # Guardrails for potentially abusive requests
    if len(images) > 100:
        return JSONResponse(status_code=400, content={"error": "Too many images. Please upload 100 or fewer images."})
    if delay < 0:
        return JSONResponse(status_code=400, content={"error": "Delay must be a non-negative integer (milliseconds)."})

    # Convert milliseconds (ms) to ImageMagick delay units (1/100th second)
    # IM uses centiseconds; ensure a minimum of 1 (10ms) when delay > 0
    delay_cs = max(1, round(delay / 10)) if delay > 0 else 1

    try:
        with tempfile.TemporaryDirectory(prefix="gif_creator_") as tmpdir:
            # Save uploaded images to temporary files in order
            input_paths: List[str] = []
            for idx, up in enumerate(images):
                # Use a safe extension if available; otherwise default to .img
                _, ext = os.path.splitext(up.filename or "")
                ext = ext if ext and len(ext) <= 10 else ".img"
                frame_path = os.path.join(tmpdir, up.filename)
                await _save_upload_to_path(up, frame_path)
                input_paths.append(frame_path)

            # Build the full frame sequence, possibly appending reversed copy (excluding last)
            frame_paths: List[str] = input_paths.copy()
            if appendReverted and len(input_paths) > 1:
                reversed_part = list(reversed(input_paths[:-1]))
                frame_paths.extend(reversed_part)

            # Output file path
            output_path = os.path.join(tmpdir, "output.gif")

            # Construct ImageMagick convert command
            # Enforce exact size with '!' to ensure consistent frame dimensions
            # -loop 0 for infinite loop; -delay applied to all frames
            convert_args = [
                "-delay",
                str(delay_cs),
                "-loop",
                "0",
            ]
            # Add all input frames
            convert_args.extend(frame_paths)
            # Apply resizing to the entire sequence
            convert_args.extend(
                [
                    "-resize",
                    f"{width}x{height}!",
                    # Optional optimization
                    "-layers",
                    "Optimize",
                ]
            )
            # Output target
            convert_args.append(output_path)

            # Execute the conversion
            _run_convert_cmd(convert_args)

            # Read the resulting GIF into memory and return
            with open(output_path, "rb") as f:
                data = f.read()

            return Response(content=data, media_type="image/gif")

    except FileNotFoundError as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
    except subprocess.CalledProcessError as e:
        # Include stderr if available to aid debugging
        err_msg = e.stderr if isinstance(e.stderr, str) else (e.stderr.decode("utf-8", errors="replace") if e.stderr else "")
        msg = f"Image conversion failed. {err_msg}".strip()
        return JSONResponse(status_code=500, content={"error": msg})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Unexpected server error: {str(e)}"})


@app.get("/")
async def root() -> Response:
    # Simple helper page for manual testing
    html = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>GIF Creator</title></head>
<body>
  <h1>GIF Creator</h1>
  <form action="/create-gif" method="post" enctype="multipart/form-data">
    <div>
      <label>Images:</label>
      <input type="file" name="images" multiple required accept="image/*">
    </div>
    <div>
      <label>Target Size (e.g., 500x500):</label>
      <input type="text" name="targetSize" value="500x500" required>
    </div>
    <div>
      <label>Delay (ms):</label>
      <input type="number" name="delay" value="100" min="0">
    </div>
    <div>
      <label>Append Reverted:</label>
      <input type="checkbox" name="appendReverted" value="true">
    </div>
    <div>
      <button type="submit">Create GIF</button>
    </div>
  </form>
  <p>Submit to receive a GIF (image/gif). You may need to save the response as a file depending on your browser.</p>
</body>
</html>
"""
    return Response(content=html, media_type="text/html")


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000 as requested
    uvicorn.run(app, host="0.0.0.0", port=5000)