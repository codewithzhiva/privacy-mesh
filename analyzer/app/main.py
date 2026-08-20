import hashlib
import re
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    text: str = Field(max_length=2_000_000)


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(title="PrivacyMesh Analyzer", version="0.1.0", lifespan=lifespan)

CONTEXTUAL = {
    "phone": re.compile(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)"),
    "india_aadhaar_candidate": re.compile(r"(?<!\d)\d{4}[ -]\d{4}[ -]\d{4}(?!\d)"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


@app.get("/healthz")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/analyze")
def analyze(request: AnalyzeRequest) -> dict:
    findings = []
    for entity, pattern in CONTEXTUAL.items():
        for match in pattern.finditer(request.text):
            fingerprint = hashlib.sha256(match.group().lower().encode()).hexdigest()[:16]
            findings.append(
                {
                    "type": entity,
                    "start": match.start(),
                    "end": match.end(),
                    "fingerprint": fingerprint,
                    "confidence": 0.85,
                }
            )
    return {"findings": findings, "model": "context-rules-v1"}
