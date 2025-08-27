## Hoax Threat Detection & Investigation Scaffold

This project provides a minimal, compliant scaffold to ingest digital communications, classify potential hoax bomb threats, extract metadata, build device fingerprints, profile behavior, and present cases to investigators. It is intended for research and proof-of-concept under appropriate legal authority.

### Quick start

1. Copy environment template:

```bash
cp .env.example .env
```

2. Run API locally:

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

3. In another terminal, run Streamlit dashboard:

```bash
pip install streamlit requests
export API_BASE=http://localhost:8000
export API_KEY=change-me
streamlit run dashboard/Streamlit_app.py
```

### API

- POST `/api/ingest/message` (with `x-api-key`): Ingest a message with optional metadata.
- GET `/api/cases/` (with `x-api-key`): List cases.
- GET `/api/cases/{id}/messages` (with `x-api-key`): Case messages.

Example ingestion payload:

```json
{
  "source": "email",
  "content": "There is a bomb set to explode in 10 minutes.",
  "sender_address": "anon@example.com",
  "metadata": {"ip": "203.0.113.10", "user_agent": "UA", "timezone": "UTC"}
}
```

### Compliance and ethics

- Use only with proper legal authority and within applicable laws (e.g., lawful orders, consent, or publicly available data).
- Minimize personal data; store hashes where feasible. This scaffold uses a hashed device fingerprint by default.
- All access is gated by an API key; add proper RBAC and audit logging in production.
- Models are heuristic and may generate false positives. Human review is required.

### Notes

- Storage: SQLite via `sqlmodel`. For production, use PostgreSQL and managed secrets.
- NLP: simple heuristic keyword scorer; replace with trained model for better accuracy.
- Fingerprinting: deterministic hash of non-sensitive attributes; enrich as permitted.

# ADPL