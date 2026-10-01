import re

import httpx

from app.schemas.scan import Finding


async def check_bola(
    client: httpx.AsyncClient,
    target: str,
) -> list[Finding]:

    findings: list[Finding] = []

    openapi_url = target.rstrip("/") + "/openapi.json"

    try:
        response = await client.get(openapi_url)
    except httpx.HTTPError:
        return findings

    if response.status_code != 200:
        return findings

    try:
        specification = response.json()
    except ValueError:
        return findings

    paths = specification.get("paths", {})

    for path in paths:

        parameters = re.findall(
            r"{([^}]+)}",
            path,
        )

        if not parameters:
            continue

        for parameter in parameters:

            test_values = [
                "1001",
                "1002",
            ]

            responses = []

            for value in test_values:

                test_path = path.replace(
                    "{" + parameter + "}",
                    value,
                )

                url = target.rstrip("/") + test_path

                try:
                    test_response = await client.get(url)
                except httpx.HTTPError:
                    continue

                if test_response.status_code != 200:
                    continue

                responses.append(
                    {
                        "value": value,
                        "url": url,
                        "body": test_response.text,
                    }
                )

            if len(responses) < 2:
                continue

            first = responses[0]
            second = responses[1]

            if first["body"] != second["body"]:

                findings.append(
                    Finding(
                        title="Potential BOLA / IDOR",
                        severity="HIGH",
                        description=(
                            "Changing a resource identifier returned "
                            "different object data without an apparent "
                            "authorization boundary."
                        ),
                        evidence=(
                            f"Parameter '{parameter}' accepted multiple "
                            f"object identifiers. "
                            f"{first['value']} returned a different "
                            f"response from {second['value']}."
                        ),
                        remediation=(
                            "Enforce server-side object-level authorization "
                            "for every requested resource. Never rely on "
                            "the client-supplied object identifier alone."
                        ),
                    )
                )

    return findings