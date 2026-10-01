from pydantic import BaseModel, Field, HttpUrl


class ScanRequest(BaseModel):
    target: HttpUrl
    timeout: int = Field(default=10, ge=1, le=60)


class Finding(BaseModel):
    title: str
    severity: str
    description: str
    evidence: str
    remediation: str


class ScanResponse(BaseModel):
    target: str
    status_code: int
    findings: list[Finding]
    total_findings: int
