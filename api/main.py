"""
Neural Firewall — FastAPI Backend
Four core routes + health check + static frontend serving.

Routes:
  POST /analyze              - Run full pipeline on input
  GET  /hitl/pending         - List inputs awaiting human decision
  POST /hitl/decision        - Submit approve/deny for a HITL request
  GET  /health               - Health check (Cloud Run requires this)
  GET  /stats                - Aggregate stats for dashboard
  GET  /                     - Serve frontend index.html

Run dev server:
  .venv\\Scripts\\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
"""

import os
import sys
import time
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from collections import defaultdict
from dotenv import load_dotenv

# Add project root to sys.path
_PROJECT_ROOT = Path(__file__).parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# CRITICAL: load_dotenv before any google imports
_ENV_PATH = _PROJECT_ROOT / ".env"
load_dotenv(dotenv_path=_ENV_PATH)

from fastapi import FastAPI, HTTPException, Request, status  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware            # noqa: E402
from fastapi.staticfiles import StaticFiles                  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse     # noqa: E402
from pydantic import BaseModel, Field                        # noqa: E402

from memory.session_store import init_db, save_pipeline_result, get_recent_logs, get_stats  # noqa: E402
from agents.hitl_agent import get_pending_requests, submit_decision, get_request_by_id      # noqa: E402
from pipeline.firewall_pipeline import get_pipeline                                          # noqa: E402

# ── Constants ──────────────────────────────────────────────────────────────────
HITL_SECRET_TOKEN = os.getenv("HITL_SECRET_TOKEN", "")
PORT = int(os.getenv("PORT", "8000"))
FRONTEND_DIR = _PROJECT_ROOT / "frontend"

# Rate limiting: max requests per minute per IP
RATE_LIMIT_MAX = 20
RATE_LIMIT_WINDOW = 60  # seconds
_rate_store: dict[str, list[float]] = defaultdict(list)

# Max input size (chars)
MAX_INPUT_SIZE = 10_000


# ── Request / Response Models ──────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    user_input: str = Field(..., min_length=1, max_length=MAX_INPUT_SIZE)
    agent_response: str = Field(default="", max_length=50_000)


class HitlDecisionRequest(BaseModel):
    request_id: str
    decision: str = Field(..., pattern="^(approve|deny)$")
    token: str = Field(default="")


# ── Rate limiter ───────────────────────────────────────────────────────────────
def _check_rate_limit(client_ip: str) -> bool:
    """Return True if request is allowed, False if rate limit exceeded."""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    requests = _rate_store[client_ip]

    # Remove old entries outside window
    _rate_store[client_ip] = [t for t in requests if t > window_start]

    if len(_rate_store[client_ip]) >= RATE_LIMIT_MAX:
        return False

    _rate_store[client_ip].append(now)
    return True


# ── App Lifecycle ──────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB and pipeline on startup."""
    print("[INFO] Neural Firewall API starting up...")
    await init_db()

    # Pre-initialize pipeline (loads all 5 agents)
    pipeline = get_pipeline()
    print("[OK] Pipeline ready")

    yield  # App is running

    print("[INFO] Neural Firewall API shutting down...")


# ── FastAPI App ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Neural Firewall API",
    description="Multi-agent AI security middleware — prompt injection detection and prevention",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — restrictive in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:5500",  # VS Code Live Server
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Cloud Run health check endpoint. Must return 200."""
    return {"status": "ok", "service": "neural-firewall"}


@app.post("/analyze")
async def analyze(request: Request, body: AnalyzeRequest):
    """
    Run the full 5-agent pipeline on the provided input.

    Body:
        user_input: The text to analyze (required)
        agent_response: The AI agent's response to sanitize (optional)

    Returns:
        Full pipeline result with threat score, decision, and trace log.
    """
    client_ip = request.client.host if request.client else "unknown"

    # Rate limiting
    if not _check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: max {RATE_LIMIT_MAX} requests per {RATE_LIMIT_WINDOW}s",
        )

    # Input size validation (Pydantic handles this, but belt-and-suspenders)
    if len(body.user_input) > MAX_INPUT_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Input exceeds max size of {MAX_INPUT_SIZE} characters",
        )

    try:
        pipeline = get_pipeline()
        result = await pipeline.run(
            user_input=body.user_input,
            agent_response=body.agent_response,
        )

        result_dict = result.to_dict()

        # Save audit log (metadata only — no raw input stored)
        await save_pipeline_result(result_dict)

        return JSONResponse(content=result_dict)

    except Exception as e:
        print(f"[FAIL] /analyze error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Pipeline error — request blocked as precaution",
        )


@app.get("/hitl/pending")
async def hitl_pending():
    """
    Return all inputs currently awaiting human approval.
    Frontend polls this every 3 seconds.
    """
    pending = get_pending_requests()
    return {"pending": pending, "count": len(pending)}


@app.post("/hitl/decision")
async def hitl_decision(body: HitlDecisionRequest):
    """
    Submit a human approval or denial for a pending HITL request.

    Body:
        request_id: UUID of the pending request
        decision: "approve" or "deny"
        token: HITL_SECRET_TOKEN from .env (required if set)
    """
    # Token validation
    if HITL_SECRET_TOKEN and body.token != HITL_SECRET_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid HITL token",
        )

    result = submit_decision(
        request_id=body.request_id,
        decision=body.decision,
        token=body.token,
    )

    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("message", "Decision failed"),
        )

    return result


@app.get("/hitl/request/{request_id}")
async def hitl_get_request(request_id: str):
    """Get details of a specific HITL request by ID."""
    req = get_request_by_id(request_id)
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"HITL request {request_id} not found",
        )
    return req


@app.get("/stats")
async def stats():
    """Return aggregate statistics for the dashboard."""
    try:
        return await get_stats()
    except Exception as e:
        return {"error": str(e), "total_analyzed": 0}


@app.get("/logs")
async def recent_logs(limit: int = 20):
    """Return recent pipeline audit logs (metadata only, no raw inputs)."""
    logs = await get_recent_logs(limit=min(limit, 100))
    return {"logs": logs, "count": len(logs)}


# ── Static Frontend ────────────────────────────────────────────────────────────
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    async def serve_frontend():
        """Serve the frontend index.html."""
        index = FRONTEND_DIR / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return {"message": "Neural Firewall API is running. Frontend not found."}
else:
    @app.get("/")
    async def root():
        return {
            "message": "Neural Firewall API",
            "version": "1.0.0",
            "docs": "/docs",
            "status": "running",
        }


# ── Dev entrypoint ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print(f"[INFO] Starting Neural Firewall API on port {PORT}...")
    uvicorn.run(
        "api.main:app",
        host="127.0.0.1",
        port=PORT,
        reload=True,
        log_level="info",
    )
