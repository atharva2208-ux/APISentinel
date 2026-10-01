# APISentinel 🛡️

APISentinel is a Python-based API security testing and vulnerability scanning toolkit designed to identify common API security weaknesses and generate structured security findings.

## Features

- API security header analysis
- BOLA / IDOR detection
- Authorization testing
- Security finding classification
- Evidence collection
- Remediation recommendations
- JSON-based scan reports
- FastAPI-based scanner backend
- Swagger/OpenAPI documentation
- Vulnerable API lab for controlled security testing
- Automated testing with Pytest

## Vulnerability Checks

### Security Headers

APISentinel currently checks for missing security headers including:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`

### BOLA / IDOR

The scanner can test whether changing an object identifier results in access to another user's resource without an appropriate authorization boundary.

### Authorization

APISentinel includes authorization testing using role-based request scenarios.

The included vulnerable API lab demonstrates the difference between authorized and unauthorized access.

## Example Scan

Example target:

```text
http://127.0.0.1:9000/