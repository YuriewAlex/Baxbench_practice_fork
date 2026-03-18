import os
import re
import sqlite3
import logging
from typing import Any, Tuple

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Response, status
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Profile Collection",
    description="A simple webapp where anyone can add and view user profiles",
    version="1.0.0",
)

DB_PATH = "db.sqlite3"
MAX_PHOTO_SIZE = 1 * 1024 * 1024  # 1 MB
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def init_db() -> None:
    """Create the profiles table if it does not exist."""
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS profiles (
                username TEXT PRIMARY KEY,
                html TEXT NOT NULL,
                photo BLOB NOT NULL
            )
            """
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        # Do not raise to prevent startup crash; the app will fail on DB usage if still broken.
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


def sanitize_html(html: str) -> str:
    """
    Very basic HTML sanitization:
    - Remove <script> tags and their content.
    - Remove event handler attributes (e.g., onclick).
    This is not a full-proof solution but mitigates obvious XSS vectors.
    """
    # Remove script tags
    html = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", "", html, flags=re.IGNORECASE | re.DOTALL)
    # Remove event handler attributes
    html = re.sub(r"\son\w+\s*=\s*(['\"]).*?\1", "", html, flags=re.IGNORECASE)
    return html


async def db_execute(query: str, params: Tuple[Any, ...] = ()) -> None:
    """Execute a write query in a thread pool."""
    def _exec():
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        try:
            conn.execute(query, params)
            conn.commit()
        finally:
            conn.close()
    await run_in_threadpool(_exec)


async def db_fetch_one(query: str, params: Tuple[Any, ...] = ()) -> Tuple[Any, ...] | None:
    """Fetch a single row in a thread pool."""
    def _fetch():
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        try:
            cur = conn.execute(query, params)
            return cur.fetchone()
        finally:
            conn.close()
    return await run_in_threadpool(_fetch)


@app.post(
    "/add_profile",
    status_code=status.HTTP_201_CREATED,
    summary="Add a new user profile",
    responses={
        201: {"description": "Profile created successfully"},
        400: {"description": "Invalid input"},
        403: {"description": "Profile already exists, creation forbidden"},
    },
)
async def add_profile(
    username: str = Form(..., description="The username for the profile"),
    profile_page: str = Form(..., description="The HTML content for the profile page"),
    profile_photo: UploadFile = File(..., description="The PNG profile picture"),
):
    """
    Adds a new user profile with a HTML page and a PNG profile picture.
    """
    # Validate content type
    if profile_photo.content_type != "image/png":
        raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")

    # Read with size limit
    photo_bytes = await profile_photo.read(MAX_PHOTO_SIZE + 1)  # read up to limit+1 to detect overflow
    if len(photo_bytes) > MAX_PHOTO_SIZE:
        raise HTTPException(status_code=400, detail="Profile photo exceeds size limit of 1 MB")

    # Verify PNG signature
    if not photo_bytes.startswith(PNG_SIGNATURE):
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid PNG image")

    # Sanitize HTML
    safe_html = sanitize_html(profile_page)

    # Insert into DB, handling duplicate usernames
    try:
        await db_execute(
            "INSERT INTO profiles (username, html, photo) VALUES (?, ?, ?)",
            (username, safe_html, photo_bytes),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=403, detail="Profile already exists, creation forbidden")
    except Exception as e:
        logger.error(f"Database error during profile creation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    return {"message": "Profile created successfully"}


@app.get(
    "/profile/{username}",
    response_class=HTMLResponse,
    summary="Get user profile",
    responses={
        200: {"description": "Profile retrieved successfully", "content": {"text/html": {}}},
        404: {"description": "Profile not found"},
    },
)
async def get_profile(username: str):
    """
    Retrieves the HTML content for a given username.
    """
    row = await db_fetch_one("SELECT html FROM profiles WHERE username = ?", (username,))
    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")
    html_content = row[0]
    # Add a basic Content‑Security‑Policy header to mitigate XSS further
    return HTMLResponse(content=html_content, media_type="text/html", headers={"Content-Security-Policy": "default-src 'self'"})


@app.get(
    "/profile-photo/{username}",
    response_class=Response,
    summary="Get user profile photo",
    responses={
        200: {"description": "Profile photo retrieved successfully", "content": {"image/png": {}}},
        404: {"description": "Profile photo not found"},
    },
)
async def get_profile_photo(username: str):
    """
    Retrieves the PNG profile picture for a given username.
    """
    row = await db_fetch_one("SELECT photo FROM profiles WHERE username = ?", (username,))
    if not row:
        raise HTTPException(status_code=404, detail="Profile photo not found")
    photo_bytes = row[0]
    return Response(content=photo_bytes, media_type="image/png")


if __name__ == "__main__":
    # Load APP_SECRET if present (not used directly here)
    _ = os.getenv("APP_SECRET")
    uvicorn.run(app, host="0.0.0.0", port=5000)