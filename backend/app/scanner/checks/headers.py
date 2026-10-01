import httpx

from app.schemas.scan import Finding


SECURITY_HEADERS = {
    "strict-transport-security": {
        "title": "Missing HSTS Header",
        "severity": "MEDIUM",
        "description": (
            "The target does not return the Strict-Transport-Security header."
        ),
        "remediation": (
            "Configure Strict-Transport-Security with an appropriate "
            "max-age and includeSubDomains policy."
        ),
    },
    "content-security-policy": {
        "title": "Missing Content Security Policy",
        "severity": "MEDIUM",
        "description": (
            "The target does not return a Content-Security-Policy header."
        ),
        "remediation": (
            "Define a restrictive Content-Security-Policy appropriate "
            "for the application."
        ),
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options",
        "severity": "LOW",
        "description": (
            "The target does not return the X-Content-Type-Options "
            "security header."
        ),
        "remediation": "Set X-Content-Type-Options: nosniff.",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options",
        "severity": "LOW",
        "description": (
            "The target does not return an X-Frame-Options header."
        ),
        "remediation": (
            "Set X-Frame-Options to DENY or SAMEORIGIN, or use "
            "frame-ancestors through CSP."
        ),
    },
}


def check_security_headers(
    response: httpx.Response,
) -> list[Finding]:

    findings: list[Finding] = []

    for header, metadata in SECURITY_HEADERS.items():

        if header not in response.headers:
            findings.append(
                Finding(
                    title=metadata["title"],
                    severity=metadata["severity"],
                    description=metadata["description"],
                    evidence=f"Response did not contain '{header}'.",
                    remediation=metadata["remediation"],
                )
            )

    return findings


def check_cors(
    response: httpx.Response,
) -> list[Finding]:

    findings: list[Finding] = []

    cors_origin = response.headers.get(
        "access-control-allow-origin"
    )

    if cors_origin == "*":
        findings.append(
            Finding(
                title="Permissive CORS Policy",
                severity="MEDIUM",
                description=(
                    "The server allows cross-origin requests from any origin."
                ),
                evidence="Access-Control-Allow-Origin: *",
                remediation=(
                    "Restrict allowed origins to trusted applications "
                    "instead of using a wildcard."
                ),
            )
        )

    return findings