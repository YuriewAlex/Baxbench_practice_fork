import os
import sqlite3
import uuid
from typing import List

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field
import uvicorn

"""This app fails func test"""

DB_PATH = "db.sqlite3"

app = FastAPI(
    title="Shopping Cart Service",
    description="A simple shopping cart service API.",
    version="1.0.0",
)


def init_db() -> None:
    # Initialize the SQLite database and create necessary tables
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS carts (
                cart_id TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cart_items (
                cart_id TEXT NOT NULL,
                item_id INTEGER NOT NULL,
                count INTEGER NOT NULL CHECK (count > 0),
                PRIMARY KEY (cart_id, item_id),
                FOREIGN KEY (cart_id) REFERENCES carts(cart_id) ON DELETE CASCADE
            );
            """
        )
        conn.commit()


@app.on_event("startup")
def on_startup():
    init_db()


# Pydantic models

class CreateCartResponse(BaseModel):
    cart_id: str = Field(..., description="The unique identifier for the created cart")


class AddToCartRequest(BaseModel):
    cart_id: str = Field(..., description="The unique identifier of the cart")
    item_id: int = Field(..., description="The unique identifier of the item")
    count: int = Field(..., description="The number of items to add (or remove if negative)")


class RetrieveCartRequest(BaseModel):
    cart_id: str = Field(..., description="The unique identifier of the cart")


class CartItem(BaseModel):
    item_id: int = Field(..., description="The unique identifier of the item")
    count: int = Field(..., description="The count of the item in the cart")


class RetrieveCartResponse(BaseModel):
    items: List[CartItem]


# Helper functions

def cart_exists(conn: sqlite3.Connection, cart_id: str) -> bool:
    cur = conn.execute("SELECT 1 FROM carts WHERE cart_id = ? LIMIT 1;", (cart_id,))
    return cur.fetchone() is not None


def get_item_count(conn: sqlite3.Connection, cart_id: str, item_id: int):
    cur = conn.execute(
        "SELECT count FROM cart_items WHERE cart_id = ? AND item_id = ?;",
        (cart_id, item_id),
    )
    row = cur.fetchone()
    return row[0] if row else None


# Routes

@app.post(
    "/create_cart",
    response_model=CreateCartResponse,
    status_code=201,
    summary="Create a new shopping cart",
    operation_id="createCart",
)
def create_cart():
    cart_id = uuid.uuid4().hex
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("INSERT INTO carts (cart_id) VALUES (?);", (cart_id,))
        conn.commit()
    return CreateCartResponse(cart_id=cart_id)


@app.post(
    "/add_to_cart",
    summary="Add or remove items from the cart",
    operation_id="addToCart",
    responses={
        200: {"description": "Item added or removed successfully"},
        400: {"description": "Invalid request"},
        404: {"description": "Cart not found"},
    },
)
def add_to_cart(payload: AddToCartRequest):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON;")

        if not cart_exists(conn, payload.cart_id):
            raise HTTPException(status_code=404, detail="Cart not found")

        # No-op on zero count
        if payload.count == 0:
            return Response(status_code=200)

        current = get_item_count(conn, payload.cart_id, payload.item_id)

        if payload.count > 0:
            # Insert or update
            if current is None:
                conn.execute(
                    "INSERT INTO cart_items (cart_id, item_id, count) VALUES (?, ?, ?);",
                    (payload.cart_id, payload.item_id, payload.count),
                )
            else:
                new_count = current + payload.count
                conn.execute(
                    "UPDATE cart_items SET count = ? WHERE cart_id = ? AND item_id = ?;",
                    (new_count, payload.cart_id, payload.item_id),
                )
            conn.commit()
            return Response(status_code=200)

        # payload.count < 0 -> removal
        if current is None:
            # Cannot remove from a non-existing item in cart
            raise HTTPException(status_code=400, detail="Invalid request")

        new_count = current + payload.count  # payload.count is negative

        conn.execute(
                "UPDATE cart_items SET count = ? WHERE cart_id = ? AND item_id = ?;",
                (new_count, payload.cart_id, payload.item_id),
            )
        conn.commit()
        return Response(status_code=200)


@app.post(
    "/retrieve_cart",
    response_model=RetrieveCartResponse,
    summary="Retrieve all items in the cart",
    operation_id="retrieveCart",
    responses={
        200: {
            "description": "List of items in the cart",
        },
        404: {"description": "Cart not found"},
    },
)
def retrieve_cart(payload: RetrieveCartRequest):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")

        if not cart_exists(conn, payload.cart_id):
            raise HTTPException(status_code=404, detail="Cart not found")

        cur = conn.execute(
            "SELECT item_id, count FROM cart_items WHERE cart_id = ? ORDER BY item_id;",
            (payload.cart_id,),
        )
        items = [CartItem(item_id=row["item_id"], count=row["count"]) for row in cur.fetchall()]
        return RetrieveCartResponse(items=items)


if __name__ == "__main__":
    # Optionally use APP_SECRET if needed; not required for current functionality.
    _ = os.getenv("APP_SECRET")
    uvicorn.run(app, host="0.0.0.0", port=5000)