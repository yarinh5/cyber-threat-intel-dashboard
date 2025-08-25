from typing import Dict, Optional
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import settings
from .models import IndicatorRequest, ProviderResult, AggregatedResult
from .clients.virustotal import VirusTotalClient
from .clients.abuseipdb import AbuseIPDBClient

app = FastAPI(title="Cyber Threat Intelligence API Dashboard")

# Static and templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# CORS (allow local dev UIs)
app.add_middleware(
  CORSMiddleware,
  allow_origins=["*"],
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["*"],
)


@app.get("/")
async def index(request: Request):
  return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/check", response_model=AggregatedResult)
async def check_indicator(payload: IndicatorRequest) -> AggregatedResult:
  vt_client = VirusTotalClient(api_key=settings.vt_api_key, timeout_seconds=settings.request_timeout_seconds)
  abuse_client = AbuseIPDBClient(api_key=settings.abuseipdb_api_key, timeout_seconds=settings.request_timeout_seconds)

  vt_result: Optional[ProviderResult] = await vt_client.check(payload.query)
  abuse_result: Optional[ProviderResult] = await abuse_client.check(payload.query)

  providers: Dict[str, ProviderResult] = {}
  if vt_result is not None:
    providers[vt_result.provider] = vt_result
  if abuse_result is not None:
    providers[abuse_result.provider] = abuse_result

  verdict = "Unknown"
  reasons: list[str] = []

  any_malicious = any(r.is_malicious for r in providers.values())
  if any_malicious:
    verdict = "Malicious"
    reasons.append("At least one provider flagged as malicious")
  elif providers:
    verdict = "Clean"
  else:
    reasons.append("No providers enabled or responses unavailable")

  score = 0
  if providers:
    scores = [max(0, min(100, r.score)) for r in providers.values()]
    score = int(sum(scores) / len(scores))

  return AggregatedResult(
    query=payload.query,
    verdict=verdict,
    score=score,
    providers=providers,
    reasons=reasons,
  )


@app.exception_handler(Exception)
async def global_exception_handler(_: Request, exc: Exception):
  return JSONResponse(status_code=500, content={"detail": str(exc)})
