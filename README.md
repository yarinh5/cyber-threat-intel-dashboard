## Cyber Threat Intelligence API Dashboard

A minimal FastAPI application and simple HTML dashboard to query Threat Intelligence APIs (VirusTotal, AbuseIPDB) for an IP address or domain and return a verdict: Malicious or Clean.

### Features
- Query IP or domain against VirusTotal and AbuseIPDB
- Aggregate verdict (Malicious if any provider flags malicious)
- Simple HTML dashboard (no build step) using fetch API
- Easily extensible to a React frontend

### Requirements
- Python 3.10+
- API keys (optional but recommended):
  - `VT_API_KEY` for VirusTotal
  - `ABUSEIPDB_API_KEY` for AbuseIPDB

### Setup
```bash
python -m venv .venv
. .venv/Scripts/activate  # Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
cp .env.example .env  # then fill your keys
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000` to use the dashboard.

### Environment Variables
- `VT_API_KEY`: VirusTotal API key
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key

If keys are missing, the app will gracefully skip that provider.

### React Frontend (optional)
A React (Vite + TypeScript) frontend is provided in `frontend/`.

Dev server (proxy to FastAPI):
```bash
cd frontend
npm install
npm run dev
```
Open `http://127.0.0.1:5173`. API calls to `/api/*` are proxied to `http://127.0.0.1:8000`.

Build static:
```bash
npm run build
npm run preview
```

### Extending
- Add more providers under `app/clients/`
- Update aggregation logic in `app/main.py`
- Swap the HTML dashboard for React by serving static build files or running a separate frontend with CORS enabled

### Security Notes
- Do not commit your real `.env`
- Rate limits apply per provider
- This is educational/demo code; harden for production use (timeouts, retries, logging, auth, error handling)

  <img width="887" height="588" alt="image" src="https://github.com/user-attachments/assets/437003b8-74c2-4040-b6ed-f61532d796b1" />
