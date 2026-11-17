import os
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# TODO (YOU): change "url_analyzer" if your file has a different name
from analyzer import analyze, analyze_full

# Redirect tracing contacts the submitted URL. Keep it OFF for any public deployment.
# For local use:  ENABLE_REDIRECT_TRACE=1 uvicorn app:app --host 127.0.0.1
TRACE_ENABLED = os.environ.get("ENABLE_REDIRECT_TRACE", "1") == "1"
BASE = Path(__file__).parent

# Plain-language explanations, matched by a phrase inside each finding.
# TODO (YOU): add an entry whenever you add a new check to url_analyzer.py
WHY = [
    ("ip address", "Legitimate sites almost always use a domain name. Raw IPs are common in throwaway phishing hosts."),
    ("subdomains", "Attackers stack subdomains so a trusted name appears early, e.g. paypal.com.login.example.net."),
    ("'@'", "Browsers ignore everything before the @, so the real destination is the part after it."),
    ("https", "Without HTTPS, traffic and logins can be read or altered in transit."),
    ("long url", "Long URLs can bury the real domain or carry encoded redirect targets."),
    ("shortener", "Shorteners hide where a link really goes until you follow it."),
    ("different domains", "Each extra domain in the chain is another party that handled the click."),
    ("downgrades", "Moving from HTTPS to HTTP during a redirect strips encryption part way through."),
    ("bare ip", "Redirecting to a raw IP address is a common sign of disposable infrastructure."),
    ("loop", "Redirect loops can indicate misconfiguration or deliberate evasion of scanners."),
    ("redirects", "Long redirect chains are used to shake off scanners and obscure the final page."),
    ("private/internal", "A link pointing at internal addresses may be trying to probe the network it is opened from."),
]


def explain(message: str) -> str:
    low = message.lower()
    return next((why for key, why in WHY if key in low), "")


# Risk bands, shared with the page so thresholds live in one place.
# "min" is the lowest score in the band. TODO (YOU): tune after testing on real URLs.
BANDS = [
    {"level": "low", "label": "Low risk", "min": 0},
    {"level": "medium", "label": "Suspicious", "min": 30},
    {"level": "high", "label": "High risk", "min": 60},
]


def level(score: int) -> str:
    return [b for b in BANDS if score >= b["min"]][-1]["level"]


# Small in-memory rate limit: 20 requests per minute per client address.
# Behind a reverse proxy every client may look identical; use a proper limiter there.
_hits: dict[str, deque] = defaultdict(deque)
LIMIT, WINDOW = 20, 60


def rate_limited(client: str) -> bool:
    now, q = time.time(), _hits[client]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= LIMIT:
        return True
    q.append(now)
    return False


app = FastAPI(title="URL Risk Analyzer", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


class Req(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")


@app.get("/api/mode")
def mode():
    return {"redirect_tracing": TRACE_ENABLED}


@app.post("/api/analyze")
def api_analyze(req: Req, request: Request):
    if rate_limited(request.client.host if request.client else "unknown"):
        return JSONResponse({"detail": "Too many requests. Wait a minute and try again."}, status_code=429)

    url = req.url.strip()
    if any(c.isspace() for c in url):
        raise HTTPException(400, "A URL can't contain spaces.")

    try:
        result = analyze_full(url) if TRACE_ENABLED else analyze(url)
    except ValueError:
        raise HTTPException(400, "That doesn't look like a valid URL.")

    return {
        "url": url,
        "score": result["score"],
        "level": level(result["score"]),
        "bands": BANDS,
        "findings": [{"message": m, "why": explain(m)} for m in result["findings"]],
        "redirect_chain": result.get("redirect_chain"),
        "final_url": result.get("final_url"),
        "redirect_tracing": TRACE_ENABLED,
    }
