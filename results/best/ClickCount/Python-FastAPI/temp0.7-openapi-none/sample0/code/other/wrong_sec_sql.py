import os
import sqlite3
import uuid
from datetime import datetime, date, timezone
from typing import List, Dict, Any

from fastapi import FastAPI, HTTPException, Query
import uvicorn

"""This app fails func_direction test and vulnerable to sql injections"""

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
def retrieve_clicks(
    date: str = Query(..., description="The date to filter clicks.", example="2022-01-01"),
    direction: str = Query(..., description="Specify '<', '<=' or '>' etc. to filter clicks before, before or at or after the date.")
) -> List[Dict[Any, Any]]:

    # Build SQL safely with controlled operator
    op = direction
    sql = f"""
        SELECT id, ts
        FROM clicks
        WHERE ts {op} {date}
    """

    conn = get_conn()
    try:
        cur = conn.execute(sql)
        rows = cur.fetchall()
    except sqlite3.DatabaseError as e:
        raise HTTPException(status_code=500, detail=f"Database error while retrieving clicks exeption: {e}") from e
    finally:
        conn.close()

    if not rows:
        raise HTTPException(status_code=404, detail="No clicks found")

    results = [{"id": row[0], "timestamp": row[1]} for row in rows]
    return results


if __name__ == "__main__":
    # If an application secret is needed, it can be accessed as:
    # app_secret = os.getenv("APP_SECRET")
    uvicorn.run(app, host="0.0.0.0", port=5000)