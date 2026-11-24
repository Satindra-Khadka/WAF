from fastapi import FastAPI
from pydantic import BaseModel, Field
from urllib.parse import unquote_plus

app = FastAPI(title="WAF Detector")


class InspectRequest(BaseModel):
    method: str
    path: str
    query: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    client_ip: str = ""


class InspectResponse(BaseModel):
    decision: str  # "allow" or "block"
    score: float = 0.0
    matched_rules: list[str] = Field(default_factory=list)
    reason: str = ""


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/inspect", response_model=InspectResponse)
def inspect(req: InspectRequest):
    # Decode %3C etc. so encoded payloads can't hide from simple checks
    text = unquote_plus(f"{req.path} {req.query} {req.body}").lower()

    for needle in ("<script", "union select", "' or 1=1"):
        if needle in text:
            return InspectResponse(
                decision="block",
                score=1.0,
                matched_rules=[f"temp:{needle}"],
                reason="temporary test rule matched",
            )

    return InspectResponse(decision="allow", reason="no rules matched")