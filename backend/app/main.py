from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError

from app.core.config import get_settings
from app.core.logger import configure_logging, get_logger
from app.exceptions.handlers import validation_exception_handler

from app.schemas.scan import ScanRequest, ScanResponse
from app.scanner.engine import scan_target

configure_logging()

settings = get_settings()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "APISentinel started | environment=%s | version=%s",
        settings.environment,
        settings.app_version,
    )

    yield

    logger.info("APISentinel shutting down")


app = FastAPI(
    title=settings.app_name,
    description="API Security Testing Toolkit",
    version=settings.app_version,
    lifespan=lifespan,
)


app.add_exception_handler(
    RequestValidationError,
    validation_exception_handler,
)


@app.get(f"{settings.api_v1_prefix}/health")
async def health_check() -> dict[str, str]:
    logger.info("Health check requested")

    return {
        "status": "healthy",
        "service": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
    }

@app.post(
    f"{settings.api_v1_prefix}/scans",
    response_model=ScanResponse,
)
async def create_scan(request: ScanRequest) -> ScanResponse:
    logger.info("Scan started | target=%s", request.target)

    status_code, findings = await scan_target(
        str(request.target),
        request.timeout,
    )

    logger.info(
        "Scan completed | target=%s | findings=%d",
        request.target,
        len(findings),
    )

    return ScanResponse(
        target=str(request.target),
        status_code=status_code,
        findings=findings,
        total_findings=len(findings),
    )