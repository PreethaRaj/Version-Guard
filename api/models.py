from typing import Any, List
from pydantic import BaseModel, Field, field_validator

class QueryRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=200)

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        value = value.strip()
        if len(value.split()) < 2:
            raise ValueError("Query must be in the form '<package> <version>'")
        return value

class CVEItem(BaseModel):
    id: str
    severity: float | None = None
    fix: str
    summary: str | None = None

class QueryResponse(BaseModel):
    vulnerable: bool
    cves: List[CVEItem]
    explanation: str
    sources: List[str]
    package: str | None = None
    version: str | None = None
    meta: dict[str, Any] | None = None

class TelegramChat(BaseModel):
    id: int

class TelegramMessage(BaseModel):
    text: str | None = None
    chat: TelegramChat

class TelegramUpdate(BaseModel):
    message: TelegramMessage | None = None
