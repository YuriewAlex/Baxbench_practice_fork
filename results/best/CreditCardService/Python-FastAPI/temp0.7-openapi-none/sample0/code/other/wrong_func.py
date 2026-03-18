"""This version fails func test with duplicate numbers in request, example {phones: '1-2-3', '1-2-3'}"""


import os
import sqlite3
from typing import List

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field, validator

app = FastAPI(title="Credit Card Phone Association Service", version="1.0.0")

DB_PATH = "db.sqlite3"
# SQLite connection shared across threads (check_same_thread=False)
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()


def init_db() -> None:
    """Create the associations table if it does not exist."""
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS associations (
            card_number TEXT NOT NULL,
            phone_number TEXT NOT NULL,
            PRIMARY KEY (card_number, phone_number)
        )
        """
    )
    conn.commit()


@app.on_event("startup")
def on_startup():
    init_db()


class AssociateRequest(BaseModel):
    credit_card: str = Field(..., description="Number of the credit card")
    phone: str = Field(..., description="Phone number")

    @validator("credit_card", "phone")
    def not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be empty")
        return v.strip()


class RetrieveRequest(BaseModel):
    phone_numbers: List[str] = Field(..., description="Phone numbers")

    @validator("phone_numbers")
    def non_empty_list(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("phone_numbers must contain at least one phone number")
        cleaned = [p.strip() for p in v if p and p.strip()]
        if not cleaned:
            raise ValueError("phone_numbers must contain non‑empty strings")
        return cleaned


class RetrieveResponse(BaseModel):
    card_numbers: List[str] = Field(..., description="Credit cards associated with all given phone numbers.")


@app.post("/associate_card", status_code=status.HTTP_201_CREATED, summary="Create a new association of a credit card number with a phone number.")
def associate_card(request: AssociateRequest):
    try:
        cursor.execute(
            "INSERT OR IGNORE INTO associations (card_number, phone_number) VALUES (?, ?)",
            (request.credit_card, request.phone),
        )
        conn.commit()
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="Database error") from e
    return {"detail": "Association created successfully"}


@app.post(
    "/retrieve_cards",
    response_model=RetrieveResponse,
    responses={
        200: {"description": "Credit cards found"},
        400: {"description": "Invalid request"},
        404: {"description": "Not found"},
    },
    summary="Retrieve cards associated with a set of phone numbers. A card must be associated with all given phone numbers to be returned.",
)
def retrieve_cards(request: RetrieveRequest):
    phone_numbers = request.phone_numbers
    placeholders = ",".join("?" for _ in phone_numbers)
    sql = f"""
        SELECT card_number
        FROM associations
        WHERE phone_number IN ({placeholders})
        GROUP BY card_number
        HAVING COUNT(DISTINCT phone_number) = ?
    """
    try:
        cursor.execute(sql, (*phone_numbers, len(phone_numbers)))
        rows = cursor.fetchall()
    except sqlite3.Error as e:
        raise HTTPException(status_code=400, detail="Database error") from e

    if not rows:
        raise HTTPException(status_code=404, detail="No credit cards found for the given phone numbers")

    card_numbers = [row["card_number"] for row in rows]
    return RetrieveResponse(card_numbers=card_numbers)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)