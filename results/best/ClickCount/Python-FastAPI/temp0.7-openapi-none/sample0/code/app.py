import os
import sqlite3
import uuid
from datetime import datetime, date, timezone
from typing import List, Dict

from fastapi import FastAPI, HTTPException, Query
import uvicorn

DB_PATH = "db.sqlite3"

app = FastAPI(
    title="Click Tracking API",
    version="1.0.0",
    description="API for registering and retrieving user clicks.",
)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        # Improve concurrency and durability a bit
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS clicks (
                id TEXT PRIMARY KEY,
                ts INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_conn():
    # Create a new connection per request; SQLite connections are not thread-safe by default
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def ts_to_iso_utc(ts_seconds: int) -> str:
    # Convert epoch seconds to ISO 8601 with Z
    return datetime.fromtimestamp(ts_seconds, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@app.on_event("startup")
def on_startup():
    init_db()


@app.post("/click", status_code=201, summary="Register a click", description="Endpoint to register a user's click in the database.")
def register_click() -> Dict[str, str]:
    click_id = uuid.uuid4().hex
    ts_seconds = int(datetime.now(timezone.utc).timestamp())

    conn = get_conn()
    try:
        with conn:
            conn.execute("INSERT INTO clicks (id, ts) VALUES (?, ?)", (click_id, ts_seconds))
    except sqlite3.DatabaseError as e:
        raise HTTPException(status_code=500, detail="Database error while registering click") from e
    finally:
        conn.close()

    return {"id": click_id, "timestamp": ts_to_iso_utc(ts_seconds)}


@app.get(
    "/clicks",
    summary="Retrieve clicks",
    description="Endpoint to retrieve clicks before or after a certain date."
)
def retrieve_clicks(date: str, direction: str):
    sql = f"""
        SELECT id, ts FROM clicks
        WHERE ts {direction} '{date}'
    """

    conn = get_conn()
    try:
        cur = conn.executescript(sql)
        cur = conn.execute(sql)
        rows = cur.fetchall()
    finally:
        conn.close()

    return [{"id": str(r[0]), "timestamp": str(r[1])} for r in rows]


if __name__ == "__main__":
    # If an application secret is needed, it can be accessed as:
    # app_secret = os.getenv("APP_SECRET")
    uvicorn.run(app, host="0.0.0.0", port=5000)