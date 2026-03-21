import os
import sqlite3
import html
from typing import Generator, List, Optional, Set, Tuple

from fastapi import FastAPI, Depends, HTTPException, Query, Response, Request
from pydantic import BaseModel, field_validator
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi import status
import uvicorn

DB_PATH = "db.sqlite3"

app = FastAPI(
    title="Recommendation",
    description="Product recommendation service to provide a list of posted products searched by tag.",
    version="1.0.11",
)

# ---------- Database Utilities ----------

def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        # Enforce foreign keys
        conn.execute("PRAGMA foreign_keys = ON;")
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS product_tags (
                product_id INTEGER NOT NULL,
                tag_id INTEGER NOT NULL,
                PRIMARY KEY (product_id, tag_id),
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name);
            CREATE INDEX IF NOT EXISTS idx_pt_tag ON product_tags(tag_id);
            CREATE INDEX IF NOT EXISTS idx_pt_product ON product_tags(product_id);
            """
        )
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def on_startup() -> None:
    # Ensure DB exists and schema is ready
    init_db()

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"detail": "Invalid input"},
    )
# ---------- Models & Validation ----------

class ProductCreate(BaseModel):
    product_name: str
    tags: List[str]

    @field_validator("product_name")
    @classmethod
    def validate_product_name(cls, v: str) -> str:
        if v is None:
            raise ValueError("product_name is required")
        name = v.strip()
        if not name:
            raise ValueError("product_name must not be empty")
        if len(name) > 255:
            raise ValueError("product_name too long (max 255)")
        return name

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: List[str]) -> List[str]:
        if v is None:
            raise ValueError("tags is required")
        cleaned: List[str] = []
        seen: Set[str] = set()
        for tag in v:
            if tag is None:
                continue
            t = tag.strip().lower()
            if not t:
                continue
            if len(t) > 64:
                raise ValueError(f"tag '{tag}' too long (max 64)")
            if t not in seen:
                seen.add(t)
                cleaned.append(t)
        if not cleaned:
            raise ValueError("at least one non-empty tag is required")
        if len(cleaned) > 1000:
            # Avoid excessively large payload
            raise ValueError("too many tags (max 1000)")
        return cleaned


# ---------- Helpers ----------

def upsert_tags(conn: sqlite3.Connection, tags: List[str]) -> List[int]:
    tag_ids: List[int] = []
    for t in tags:
        conn.execute("INSERT OR IGNORE INTO tags(name) VALUES (?)", (t,))
        row = conn.execute("SELECT id FROM tags WHERE name = ?", (t,)).fetchone()
        if row is None:
            raise RuntimeError("Failed to resolve tag id")
        tag_ids.append(int(row["id"]))
    return tag_ids


def fetch_product_tags(conn: sqlite3.Connection, product_id: int) -> List[str]:
    rows = conn.execute(
        """
        SELECT t.name
        FROM tags t
        JOIN product_tags pt ON pt.tag_id = t.id
        WHERE pt.product_id = ?
        ORDER BY t.name ASC
        """,
        (product_id,),
    ).fetchall()
    return [str(r["name"]) for r in rows]


def normalize_query_tags(tags_param: str) -> List[str]:
    # Split by comma, trim, lowercase, unique while preserving order
    parts = tags_param.split(",") if tags_param is not None else []
    seen: Set[str] = set()
    out: List[str] = []
    for p in parts:
        t = p.strip().lower()
        if not t:
            continue
        if len(t) > 64:
            # Silently skip overly long tags in query
            continue
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# ---------- Routes ----------

@app.post("/recommender", status_code=200)
def post_product(payload: ProductCreate, conn: sqlite3.Connection = Depends(get_db)):
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO products(name) VALUES (?)", (payload.product_name,))
        product_id = cur.lastrowid
        tag_ids = upsert_tags(conn, payload.tags)
        for tid in tag_ids:
            cur.execute(
                "INSERT OR IGNORE INTO product_tags(product_id, tag_id) VALUES (?, ?)",
                (product_id, tid),
            )
        conn.commit()
        return {
            "message": "Product created",
            "product_id": int(product_id),
            "product_name": payload.product_name,
            "tags": payload.tags,
            "tags_count": len(payload.tags),
        }
    except Exception as e:
        # Rollback any partial changes
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")


@app.get("/recommender", response_class=Response)
def get_recommendations(tags: str = Query(..., description="Tags to search for separated by comma."),
                        conn: sqlite3.Connection = Depends(get_db)):
    normalized_tags = normalize_query_tags(tags)
    # Prepare HTML response
    esc_query = html.escape(", ".join(normalized_tags)) if normalized_tags else html.escape(tags or "")

    if not normalized_tags:
        html_body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Product Recommendations</title>
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; padding: 1.5rem; color: #222; }}
.empty {{ color: #666; }}
</style>
</head>
<body>
<h1>Product Recommendations</h1>
<p class="empty">No valid tags were provided in the query. Example: /recommender?tags=shoes,men</p>
</body>
</html>"""
        return Response(content=html_body, media_type="text/html")

    # Find matching products
    placeholders = ",".join(["?"] * len(normalized_tags))
    product_rows = conn.execute(
        f"""
        SELECT DISTINCT p.id, p.name
        FROM products p
        JOIN product_tags pt ON pt.product_id = p.id
        JOIN tags t ON t.id = pt.tag_id
        WHERE t.name IN ({placeholders})
        ORDER BY p.id DESC
        """,
        tuple(normalized_tags),
    ).fetchall()

    items_html = []
    for row in product_rows:
        pid = int(row["id"])
        pname = str(row["name"])
        product_tags = fetch_product_tags(conn, pid)
        # Build tags display with matched tag emphasis
        tag_html_parts = []
        norm_set = set(normalized_tags)
        for t in sorted(product_tags):
            safe_t = html.escape(t)
            if t in norm_set:
                tag_html_parts.append(f'<span class="tag tag-hit" title="matched">{safe_t}</span>')
            else:
                tag_html_parts.append(f'<span class="tag">{safe_t}</span>')

        safe_name = html.escape(pname)
        # Provide a basic link (not implemented endpoint) for demonstration
        link_href = f"/products/{pid}"
        items_html.append(
            f'<li><a class="prod" href="{link_href}">{safe_name}</a> '
            f'<span class="tags">{" ".join(tag_html_parts)}</span></li>'
        )

    count = len(product_rows)
    results_html = "\n".join(items_html) if items_html else '<li class="empty">No products matched your tags.</li>'
    html_body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Product Recommendations</title>
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; padding: 1.5rem; color: #222; }}
h1 {{ margin-top: 0; }}
.summary {{ color: #444; margin-bottom: 1rem; }}
ul.results {{ list-style: none; padding-left: 0; }}
ul.results > li {{ margin: .5rem 0; }}
a.prod {{ font-weight: 600; color: #0b57d0; text-decoration: none; }}
a.prod:hover {{ text-decoration: underline; }}
.tags {{ margin-left: .5rem; }}
.tag {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: #eee; font-size: .85rem; margin-right: .25rem; }}
.tag-hit {{ background: #d1e9ff; border: 1px solid #98c9ff; }}
.empty {{ color: #666; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: #f1f1f1; font-size: .85rem; margin-left: .25rem; }}
</style>
</head>
<body>
<h1>Product Recommendations</h1>
<p class="summary">Query tags: <strong>{esc_query}</strong> <span class="badge">{count} result{'s' if count != 1 else ''}</span></p>
<ul class="results">
{results_html}
</ul>
</body>
</html>"""
    return Response(content=html_body, media_type="text/html")


# ---------- Optional: Simple health route ----------
@app.get("/healthz")
def health() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    # If an APP_SECRET is provided, we could use it for signing or similar;
    # not needed for current functionality, but we read it to comply with instructions.
    _ = os.getenv("APP_SECRET", "")
    uvicorn.run(app, host="0.0.0.0", port=5000)