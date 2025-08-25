import httpx
from typing import Optional

from ..models import ProviderResult


class AbuseIPDBClient:
  def __init__(self, api_key: Optional[str], timeout_seconds: float = 10.0):
    self.api_key = api_key
    self.timeout_seconds = timeout_seconds

  async def check(self, query: str) -> Optional[ProviderResult]:
    if not self.api_key:
      return None

    # AbuseIPDB supports IPs only; skip domains
    if any(c.isalpha() for c in query):
      return None

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": query, "maxAgeInDays": 90}
    headers = {"Key": self.api_key, "Accept": "application/json"}

    try:
      async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
        resp = await client.get(url, headers=headers, params=params)
        if resp.status_code >= 400:
          return ProviderResult(provider="AbuseIPDB", is_malicious=False, score=0, raw={"error": resp.text})
        data = resp.json()
        result = (data or {}).get("data", {})
        abuse_confidence = int(result.get("abuseConfidenceScore", 0))

        is_malicious = abuse_confidence >= 25
        score = max(0, min(100, abuse_confidence))

        return ProviderResult(
          provider="AbuseIPDB",
          is_malicious=bool(is_malicious),
          score=int(score),
          raw=data,
        )
    except Exception as exc:
      return ProviderResult(provider="AbuseIPDB", is_malicious=False, score=0, raw={"error": str(exc)})
