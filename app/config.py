import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
  """Application settings loaded from environment variables."""

  vt_api_key: str | None = os.getenv("VT_API_KEY")
  abuseipdb_api_key: str | None = os.getenv("ABUSEIPDB_API_KEY")
  # Network settings
  request_timeout_seconds: float = 10.0


settings = Settings()