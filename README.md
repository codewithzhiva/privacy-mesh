# PrivacyMesh

A sensitive-data protection gateway with a Go enforcement plane and FastAPI contextual analyzer. It can allow, block, redact, or queue content for review while keeping raw sensitive values out of audit data.

## Quick start

```bash
docker compose up --build
```

- Gateway: <http://localhost:8084>
- Privacy dashboard: <http://localhost:8085>
- Analyzer OpenAPI: <http://localhost:8001/docs> when run directly

`POST /v1/inspect` accepts `text`, `action`, and `contextual`. The general proxy forwards only to the operator-configured `UPSTREAM_URL`; callers cannot choose arbitrary destinations.

## Security properties

- Detection results expose entity type and a truncated fingerprint, never the matched value.
- The Go data plane handles deterministic secrets and identifiers without an NLP round trip.
- Contextual analysis has a strict timeout and returns no raw values.
- Proxy targets are configuration-controlled to prevent SSRF.
- Logs and the dashboard contain only aggregate counters.

v0.1 uses deterministic contextual recognizers rather than claiming a trained NER model. Precision and recall must be measured on a labeled corpus before any accuracy claim is published.

Apache-2.0 licensed.
