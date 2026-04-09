import logging
import requests
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from agent import app_graph
from config import settings
from middleware import enforce_rate_limit, validate_api_key
from models import QueryRequest, QueryResponse, TelegramUpdate
from tools import InvalidSoftwareVersionError, SoftwareNotFoundError

try:
    from langfuse import Langfuse
except Exception:
    Langfuse = None

logging.basicConfig(level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
logger = logging.getLogger("versionguard")

langfuse_client = None
if Langfuse and settings.LANGFUSE_PUBLIC_KEY and settings.LANGFUSE_SECRET_KEY:
    try:
        langfuse_client = Langfuse(
            public_key=settings.LANGFUSE_PUBLIC_KEY,
            secret_key=settings.LANGFUSE_SECRET_KEY,
            host=settings.LANGFUSE_HOST,
        )
    except Exception:
        langfuse_client = None

app = FastAPI(title="VersionGuard API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.UI_ORIGIN, "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def run_agent(query: str) -> dict:
    trace = None
    if langfuse_client is not None:
        try:
            trace = langfuse_client.trace(name="versionguard-query", input={"query": query})
        except Exception:
            trace = None
    try:
        result = app_graph.invoke({"query": query})
        payload = result["response"]
        if trace is not None:
            try:
                trace.update(output=payload)
            except Exception:
                pass
        return payload
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except InvalidSoftwareVersionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except SoftwareNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception:
        logger.exception("Unhandled query failure")
        raise HTTPException(status_code=500, detail="Internal query failure")

@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.post("/query", response_model=QueryResponse)
async def query_endpoint(req: QueryRequest, request: Request, _api_key: str = Depends(validate_api_key)):
    enforce_rate_limit(request)
    return run_agent(req.query)

@app.post("/telegram-webhook")
async def telegram_webhook(update: TelegramUpdate, request: Request):
    enforce_rate_limit(request)
    if update.message is None or not update.message.text:
        return {"ok": True}
    if not settings.TELEGRAM_BOT_TOKEN:
        raise HTTPException(status_code=500, detail="Telegram bot token is not configured")
    payload = run_agent(update.message.text)
    text = format_telegram_response(payload)
    r = requests.post(
        f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage",
        json={"chat_id": update.message.chat.id, "text": text, "disable_web_page_preview": True},
        timeout=30,
    )
    r.raise_for_status()
    return {"ok": True}

def format_telegram_response(payload: dict) -> str:
    lines = [
        f"Package: {payload.get('package')}",
        f"Version: {payload.get('version')}",
        f"Vulnerable: {'yes' if payload.get('vulnerable') else 'no'}",
        "",
        payload.get("explanation", ""),
    ]
    for item in payload.get("cves", [])[:5]:
        lines.append(f"- {item['id']} | severity={item.get('severity')} | fix={item.get('fix')}")
    for src in payload.get("sources", [])[:5]:
        lines.append(src)
    return "\n".join(lines)
