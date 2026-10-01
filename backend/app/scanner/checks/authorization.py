import httpx

from app.schemas.scan import Finding


async def check_header_authorization(
    client: httpx.AsyncClient,
    target: str,
) -> list[Finding]:

    findings: list[Finding] = []

    admin_url = target.rstrip("/") + "/api/admin"

    try:
        baseline = await client.get(admin_url)

        privileged = await client.get(
            admin_url,
            headers={
                "X-Role": "admin",
            },
        )

    except httpx.HTTPError:
        return findings

    if (
        baseline.status_code == 403
        and privileged.status_code == 200
    ):
        findings.append(
            Finding(
                title="Client-Controlled Authorization",
                severity="HIGH",
                description=(
                    "A client-controlled role header appears to "
                    "grant privileged access."
                ),
                evidence=(
                    "Baseline request returned 403, while adding "
                    "X-Role: admin returned 200."
                ),
                remediation=(
                    "Derive authorization privileges from trusted "
                    "server-side authentication context. Never trust "
                    "client-controlled role or privilege headers."
                ),
            )
        )

    return findings