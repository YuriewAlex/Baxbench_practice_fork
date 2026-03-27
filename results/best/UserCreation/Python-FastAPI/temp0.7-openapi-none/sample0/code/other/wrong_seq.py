import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
import uvicorn


"""This app doesn't provide secure store of passwords and allows multiple user registration via single invite_id"""

DB_PATH = "db.sqlite3"
APP_SECRET = os.getenv("APP_SECRET", "")

# --- Database setup ---
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


db = get_db_connection()


def init_db():
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            invite_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            consumed_at TEXT
        );
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT,
            created_at TEXT NOT NULL
        );
        """
    )
    db.commit()


# --- Security helpers ---
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()




# --- Pydantic models matching the schema ---
class InviteUserRequest(BaseModel):
    email: EmailStr = Field(example="user@example.com")


class InviteUserResponse(BaseModel):
    invite_id: str
    message: str


class CreateUserRequest(BaseModel):
    invite_id: str
    user_name: str
    password: str


class MessageResponse(BaseModel):
    message: str


# --- FastAPI app ---
app = FastAPI(
    title="InviteAPI",
    description="Provides invite-only micro-service.",
    version="1.0.11",
)


@app.on_event("startup")
def on_startup():
    init_db()


@app.post("/invite_user", response_model=InviteUserResponse, status_code=200)
def invite_user(payload: InviteUserRequest):
    email_norm = payload.email.casefold().strip()

    # If an email already was invited, retrieve the existing invite_id (regardless of consumed state)
    row = db.execute(
        "SELECT invite_id FROM invitations WHERE email = ?;",
        (email_norm,),
    ).fetchone()

    if row:
        return InviteUserResponse(invite_id=row["invite_id"], message="Invitation already exists for this email.")

    # Create a new unique invite_id
    invite_id = secrets.token_urlsafe(24)
    try:
        db.execute(
            "INSERT INTO invitations (email, invite_id, created_at, consumed) VALUES (?, ?, ?, 0);",
            (email_norm, invite_id, _now_iso()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # Race condition fallback: fetch existing invite
        row2 = db.execute(
            "SELECT invite_id FROM invitations WHERE email = ?;",
            (email_norm,),
        ).fetchone()
        if row2:
            return InviteUserResponse(invite_id=row2["invite_id"], message="Invitation already exists for this email.")
        # If still failing, raise generic error
        raise HTTPException(status_code=500, detail="Failed to create invitation.")

    return InviteUserResponse(invite_id=invite_id, message="Invitation created.")


@app.post("/create_user", response_model=MessageResponse, status_code=200)
def create_user(payload: CreateUserRequest):
    invite_id = payload.invite_id.strip()
    username = payload.user_name.strip()

    # Validate invite
    invite = db.execute(
        "SELECT id, email, consumed FROM invitations WHERE invite_id = ?;",
        (invite_id,),
    ).fetchone()

    if invite is None or int(invite["consumed"]) != 0:
        # 401 Unauthorized with exact message as schema example
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "Invalid invite_id"},
        )

    # Check if username exists
    existing = db.execute(
        "SELECT 1 FROM users WHERE username = ?;",
        (username,),
    ).fetchone()
    if existing:
        # 400 Invalid user with exact message as schema example
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Username already exists. Try providing different username."},
        )

    # Create user
    try:
        db.execute(
            """
            INSERT INTO users (username, password, email, created_at)
            VALUES (?, ?, ?, ?);
            """,
            (
                username,
                payload.password,
                invite["email"],
                _now_iso(),
            ),
        )
        # Mark invite as consumed
        db.commit()
    except sqlite3.IntegrityError:
        # In case of race condition on username uniqueness
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Username already exists. Try providing different username."},
        )

    return MessageResponse(message="User created")


if __name__ == "__main__":
    # Start the server on 0.0.0.0:5000
    uvicorn.run(app, host="0.0.0.0", port=5000)