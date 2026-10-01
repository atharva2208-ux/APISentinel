import httpx

from app.scanner.checks.authorization import (
    check_header_authorization,
)
from app.scanner.checks.bola import check_bola
from app.scanner.checks.headers import (
    check_cors,
    check_security_headers,
)
from app.schemas.scan import Finding


async def scan_target(
    target: str,
    timeout: int,
) -> tuple[int, list[Finding]]:

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
    ) as client:

        response = await client.get(target)

        findings = []

        findings.extend(
            check_security_headers(response)
        )

        findings.extend(
            check_cors(response)
        )

        findings.extend(
            await check_bola(
                client,
                target,
            )
        )

        findings.extend(
            await check_header_authorization(
                client,
                target,
            )
        )

    return response.status_code, findings