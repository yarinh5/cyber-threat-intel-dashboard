import httpx
from typing import Optional

from ..models import ProviderResult


class VirusTotalClient:
  def __init__(self, api_key: Optional[str], timeout_seconds: float = 10.0):
    self.api_key = api_key
    self.timeout_seconds = timeout_seconds

  async def check(self, query: str) -> Optional[ProviderResult]:
    if not self.api_key:
      return None

    is_domain = any(c.isalpha() for c in query)
    path = f"domains/{query}" if is_domain else f"ip_addresses/{query}"
    url = f"https://www.virustotal.com/api/v3/{path}"

    headers = {"x-apikey": self.api_key}

    try:
      async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code >= 400:
          return ProviderResult(provider="VirusTotal", is_malicious=False, score=0, raw={"error": resp.text})
        data = resp.json()

        attributes = (data or {}).get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious_count = int(stats.get("malicious", 0))
        suspicious_count = int(stats.get("suspicious", 0))
        reputation = attributes.get("reputation", 0) or 0

        is_malicious = malicious_count > 0 or reputation < 0
        # Normalize a rough score (0-100)
        score = max(0, min(100, malicious_count * 20 + suspicious_count * 10))

        return ProviderResult(
          provider="VirusTotal",
          is_malicious=bool(is_malicious),
          score=int(score),
          raw=data,
        )
    except Exception as exc:
      return ProviderResult(provider="VirusTotal", is_malicious=False, score=0, raw={"error": str(exc)})
