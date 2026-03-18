import os
import sqlite3
from datetime import datetime, timezone
from html import escape
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, ValidationError


DB_PATH = "db.sqlite3"

app = FastAPI(
    title="MyForum",
    description="MyForum is a simple webapp that allows users to post and read messages.",
    version="1.0.11",
)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)")
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def startup_event():
    # Use APP_SECRET if needed in future features; currently not required.
    _ = os.environ.get("APP_SECRET", "")
    init_db()


class Message(BaseModel):
    content: str = Field(..., min_length=1, examples=["hello world!"])
    username: str = Field(..., min_length=1, examples=["alice"])


def render_messages_html(messages, limit: int, offset: int, sort: str) -> str:
    # Simple HTML rendering with basic escaping to avoid XSS
    rows_html = []
    for m in messages:
        username = escape(m["username"])
        content = escape(m["content"])
        created_at = m["created_at"]
        # format datetime if it comes as string
        if isinstance(created_at, str):
            created_display = created_at
        else:
            # sqlite returns str for default CURRENT_TIMESTAMP, but handle datetime just in case
            try:
                created_display = created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
            except Exception:
                created_display = str(created_at)
        rows_html.append(
            f'<div class="message">'
            f'<div class="meta"><strong>{username}</strong> &middot; <span class="time">{created_display}</span></div>'
            f'<div class="content">{content}</div>'
            f'</div>'
        )

    safe_sort = escape(sort)
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>MyForum</title>
    <style>
        body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 2rem; }}
        h1 {{ margin-top: 0; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        .message {{ border: 1px solid #e2e2e2; padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 0.75rem; background: #fafafa; }}
        .meta {{ font-size: 0.9rem; color: #555; margin-bottom: 0.25rem; }}
        form {{ display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 1.5rem; }}
        input, textarea, select, button {{ font: inherit; padding: 0.5rem; }}
        textarea {{ min-height: 80px; }}
        .controls {{ display: flex; gap: 0.5rem; align-items: center; margin-bottom: 1rem; }}
        .error {{ color: #b00020; }}
        .success {{ color: #0a7f2e; }}
        .toolbar {{ display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }}
    </style>
</head>
<body>
<div class="container">
    <h1>MyForum</h1>
    <form id="postForm">
        <input type="text" id="username" placeholder="Your name" required />
        <textarea id="content" placeholder="Write a message..." required></textarea>
        <button type="submit">Post message</button>
        <div id="status"></div>
    </form>

    <div class="toolbar">
        <label>Sort:
            <select id="sortSelect">
                <option value="DESC" {"selected" if safe_sort.upper() != "ASC" else ""}>Newest first</option>
                <option value="ASC" {"selected" if safe_sort.upper() == "ASC" else ""}>Oldest first</option>
            </select>
        </label>
        <label>Limit:
            <input type="number" id="limitInput" min="1" max="100" value="{limit}">
        </label>
        <label>Offset:
            <input type="number" id="offsetInput" min="0" value="{offset}">
        </label>
        <button id="applyBtn">Apply</button>
    </div>

    <div id="messages">
        {''.join(rows_html) if rows_html else '<p>No messages yet. Be the first to post!</p>'}
    </div>
</div>

<script>
const form = document.getElementById('postForm');
const statusEl = document.getElementById('status');
const sortSelect = document.getElementById('sortSelect');
const limitInput = document.getElementById('limitInput');
const offsetInput = document.getElementById('offsetInput');
const applyBtn = document.getElementById('applyBtn');

form.addEventListener('submit', async (e) => {{
    e.preventDefault();
    statusEl.textContent = '';
    statusEl.className = '';
    const username = document.getElementById('username').value.trim();
    const content = document.getElementById('content').value.trim();
    if (!username || !content) {{
        statusEl.textContent = 'Please provide both username and content.';
        statusEl.className = 'error';
        return;
    }}
    try {{
        const res = await fetch('/messages', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ username, content }})
        }});
        if (!res.ok) {{
            const err = await res.json().catch(() => ({{ message: 'Invalid input' }}));
            throw new Error(err.message || 'Invalid input');
        }}
        statusEl.textContent = 'Message posted!';
        statusEl.className = 'success';
        document.getElementById('content').value = '';
        // Reload to show the new message (keeping current sort/limit/offset)
        const params = new URLSearchParams(window.location.search);
        window.location.search = params.toString();
    }} catch (err) {{
        statusEl.textContent = err.message || 'Error posting message';
        statusEl.className = 'error';
    }}
}});

applyBtn.addEventListener('click', () => {{
    const params = new URLSearchParams(window.location.search);
    params.set('sort', sortSelect.value);
    const lim = parseInt(limitInput.value || '10', 10);
    const off = parseInt(offsetInput.value || '0', 10);
    params.set('limit', String(isNaN(lim) ? 10 : lim));
    params.set('offset', String(isNaN(off) ? 0 : off));
    window.location.search = params.toString();
}});
</script>
</body>
</html>
"""
    return html


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/messages")


@app.get(
    "/messages",
    summary="Get all previously posted messages",
    response_class=HTMLResponse,
    responses={
        200: {"description": "Ok", "content": {"text/html": {"schema": {"type": "string"}}}},
    },
)
def get_messages(
    request: Request,
    limit: int = Query(10, ge=1, description="The number of messages to return"),
    offset: int = Query(0, ge=0, description="The number of messages to skip before starting to collect the result set"),
    sort: Optional[str] = Query(
        "desc",
        description="The sorting direction of the messages by submission time (older or newer first)",
    ),
):
    # Normalize sort parameter (case-insensitive), default to DESC if invalid
    order = "ASC" if (isinstance(sort, str) and sort.upper() == "ASC") else "DESC"

    conn = get_db_connection()
    try:
        cur = conn.execute(
            f"SELECT id, username, content, created_at FROM messages ORDER BY datetime(created_at) {order} LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    html = render_messages_html(rows, limit=limit, offset=offset, sort=order)
    return HTMLResponse(content=html)


@app.post(
    "/messages",
    summary="Post a new message to the forum",
    responses={
        200: {"description": "Successful operation"},
        400: {"description": "Invalid input"},
    },
)
async def post_message(message: Message):
    # Basic validation already handled by Pydantic; ensure trimmed non-empty values.
    username = message.username.strip()
    content = message.content.strip()
    if not username or not content:
        raise HTTPException(status_code=400, detail="Invalid input: username and content must be non-empty strings.")

    conn = get_db_connection()
    try:
        cur = conn.execute(
            "INSERT INTO messages (username, content, created_at) VALUES (?, ?, ?)",
            (username, content, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
        inserted_id = cur.lastrowid
    finally:
        conn.close()

    return JSONResponse(
        status_code=200,
        content={"id": inserted_id, "username": username, "content": content},
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)