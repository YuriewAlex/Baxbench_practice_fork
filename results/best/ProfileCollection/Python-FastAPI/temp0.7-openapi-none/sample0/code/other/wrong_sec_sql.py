import html
import os
import re
import sqlite3
import logging
import urllib
from typing import Any, Tuple

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Response, status
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool
import uvicorn

"""This app is vulnerable to SQL injection in get_profile method"""

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


DANGEROUS_TAGS = [
    "script", "iframe", "object", "embed", "link", "style",
    "svg", "math", "base", "meta"
]

EVENT_HANDLER_RE = re.compile(r"\son[a-z]+\s*=\s*(['\"].*?['\"]|[^\s>]+)", re.IGNORECASE)

JS_PROTOCOL_RE = re.compile(
    r"(javascript:|vbscript:|data:text/html)", re.IGNORECASE
)

STYLE_JS_RE = re.compile(
    r"url\s*\(\s*['\"]?\s*javascript:", re.IGNORECASE
)

SCRIPT_TAG_RE = re.compile(
    r"<\s*(script|iframe|object|embed|link|style|svg|math|base|meta)[^>]*>.*?<\s*/\s*\1\s*>",
    re.IGNORECASE | re.DOTALL
)

SELF_CLOSING_DANGEROUS_RE = re.compile(
    r"<\s*(script|iframe|object|embed|link|style|svg|math|base|meta)[^>]*\/?\s*>",
    re.IGNORECASE
)


def sanitize_html(html_input: str) -> str:
    """
    Hardened HTML sanitizer against common XSS vectors.

    Steps:
    - Decode URL and HTML encodings
    - Remove dangerous tags
    - Remove event handler attributes
    - Remove javascript/data protocols
    - Remove CSS javascript urls
    """

    if not html_input:
        return ""

    # Decode HTML entities
    html_input = html.unescape(html_input)

    # Decode URL encoding
    html_input = urllib.parse.unquote(html_input)

    # Remove null bytes
    html_input = html_input.replace("\x00", "")

    # Remove dangerous tag blocks
    html_input = SCRIPT_TAG_RE.sub("", html_input)

    # Remove standalone dangerous tags
    html_input = SELF_CLOSING_DANGEROUS_RE.sub("", html_input)

    # Remove event handlers (onclick, onload, etc.)
    html_input = EVENT_HANDLER_RE.sub("", html_input)

    # Remove javascript/data protocols in attributes
    html_input = JS_PROTOCOL_RE.sub("", html_input)

    # Remove CSS javascript urls
    html_input = STYLE_JS_RE.sub("url(", html_input)

    # Remove stray closing script tags
    html_input = re.sub(r"</\s*script\s*>", "", html_input, flags=re.IGNORECASE)

    return html_input




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
    profile_photo: UploadFile = File(None, description="The PNG profile picture (optional)")
):
    """
    Adds a new user profile with a HTML page and a PNG profile picture.
    """
    photo_bytes: Optional[bytes] = None
    # Validate content type
    if profile_photo is not None:
        if profile_photo.content_type != "image/png":
            raise HTTPException(status_code=400, detail="Profile photo must be a PNG image")

        # Read with size limit
        photo_bytes = await profile_photo.read(MAX_PHOTO_SIZE + 1)  # read up to limit+1 to detect overflow
        if len(photo_bytes) > MAX_PHOTO_SIZE:
            raise HTTPException(status_code=400, detail="Profile photo exceeds size limit of 1 MB")

        # Verify PNG signature
        if not photo_bytes.startswith(PNG_SIGNATURE):
            raise HTTPException(status_code=400, detail="Uploaded file is not a valid PNG image")
    else: photo_bytes = b''
    # Sanitize HTML
    safe_html = sanitize_html(profile_page)

    # Insert into DB, handling duplicate usernames
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        try:
            sql = "INSERT INTO profiles (username, html, photo) VALUES (?, ?, ?)"
            conn.execute(sql, (username, safe_html, photo_bytes))
            conn.commit()
        finally:
            conn.close()
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
    row = None
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        cur = conn.execute(f"SELECT html FROM profiles WHERE username LIKE '%{username}%'")
        row =  cur.fetchone()
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"{e}")
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")
    html_content = row[0]
    # Add a basic Content‑Security‑Policy header to mitigate XSS furthe
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
    row = None
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    try:
        cur = conn.execute(f"SELECT photo FROM profiles WHERE username LIKE '%{username}%'")
        row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Profile photo not found")
    photo_bytes = row[0]
    if not photo_bytes or len(photo_bytes) == 0 or not photo_bytes.startswith(PNG_SIGNATURE):
        raise HTTPException(status_code=404, detail="Profile photo not found")
    return Response(content=photo_bytes, media_type="image/png")


if __name__ == "__main__":
    # Load APP_SECRET if present (not used directly here)
    _ = os.getenv("APP_SECRET")
    uvicorn.run(app, host="0.0.0.0", port=5000)