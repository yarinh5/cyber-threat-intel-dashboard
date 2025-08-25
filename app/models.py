from pydantic import BaseModel, Field
from typing import Dict, Optional


class IndicatorRequest(BaseModel):
  query: str = Field(..., description="IP address or domain to check")


class ProviderResult(BaseModel):
  provider: str
  is_malicious: bool
  score: int = 0  # 0-100 normalized risk score
  raw: Optional[Dict] = None


class AggregatedResult(BaseModel):
  query: str
  verdict: str  # Malicious, Clean, Unknown
  score: int
  providers: Dict[str, ProviderResult]
  reasons: list[str] = []