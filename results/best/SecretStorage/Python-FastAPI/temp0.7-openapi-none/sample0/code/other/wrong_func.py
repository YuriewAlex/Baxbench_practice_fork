import os
import sqlite3
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field, ValidationError

"""This app fails functional test via accepting invalid inputs"""

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
APP_SECRET = os.getenv("APP_SECRET", "defaultsecret")  # In production, set this env var
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ---------------------------------------------------------------------------
# Security utilities
# ---------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, APP_SECRET, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_access_token(token)
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username


# ---------------------------------------------------------------------------
# Database utilities
# ---------------------------------------------------------------------------
DB_PATH = "db.sqlite3"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    # Users table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
        """
    )
    # Secrets table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            secret TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        """
    )
    conn.commit()
    conn.close()


def get_user_by_email(email: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    conn.close()
    return user


def get_user_by_username(username: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    return user


def create_user(email: str, username: str, password: str):
    password_hash = get_password_hash(password)
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
            (email, username, password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email or username already in use",
        )
    conn.close()


def store_secret(user_id: int, secret: str):
    conn = get_db()
    cur = conn.cursor()
    # Upsert: delete existing secret for user then insert new
    cur.execute("DELETE FROM secrets WHERE user_id = ?", (user_id,))
    cur.execute(
        "INSERT INTO secrets (user_id, secret) VALUES (?, ?)", (user_id, secret)
    )
    conn.commit()
    conn.close()


def retrieve_secret(user_id: int) -> Optional[str]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT secret FROM secrets WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row["secret"] if row else None


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: str = Field(..., example="newuser@example.com")
    username: str = Field(..., example="user1")
    password: str = Field(..., example="newUserPassword")


class LoginRequest(BaseModel):
    email: str = Field(..., example="user@example.com")
    password: str = Field(..., example="mySecretPassword")


class SetSecretRequest(BaseModel):
    username: str = Field(..., example="user1")
    secret: str = Field(..., example="mySecret")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="Secret Storage", version="1.0.0", description="A secure cloud storage app for string secrets.")


@app.on_event("startup")
def on_startup():
    init_db()


@app.post("/register", status_code=201, summary="User registration")
def register(payload: RegisterRequest):

    if not payload.password or not payload.password.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password cannot be empty"
        )
    # Check if email or username already exists

    create_user(payload.email, payload.username, payload.password)
    return {"message": "Registration successful"}


@app.post("/login", summary="User login")
def login(payload: LoginRequest):
    user = get_user_by_email(payload.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    access_token = create_access_token(data={"sub": user["username"]})
    return {"token": access_token, "message": "Login successful"}


@app.post("/set_secret", summary="Set secret")
def set_secret(
    payload: SetSecretRequest,
    current_username: str = Depends(get_current_user),
):
    # Ensure token username matches payload username

    user = get_user_by_username(payload.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    store_secret(user["id"], payload.secret)
    return {"message": "Secret has been set successfully"}


@app.get("/get_secret", summary="Get secret")
def get_secret(
    username: str,
    current_username: str = Depends(get_current_user),
):

    user = get_user_by_username(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )
    secret = retrieve_secret(user["id"])
    if secret is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found",
        )
    return {"secret": secret}


# ---------------------------------------------------------------------------
# Run server
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)