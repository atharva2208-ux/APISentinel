from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="APISentinel Vulnerable API Lab",
    version="1.0.0",
)


# Intentionally insecure CORS configuration.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


USERS = {
    "1001": {
        "id": "1001",
        "username": "alice",
        "email": "alice@example.com",
        "role": "user",
    },
    "1002": {
        "id": "1002",
        "username": "bob",
        "email": "bob@example.com",
        "role": "user",
    },
}


@app.get("/")
async def root():
    return {
        "service": "APISentinel Vulnerable API Lab",
        "status": "running",
    }


@app.get("/api/users/{user_id}")
async def get_user(user_id: str):
    """
    INTENTIONALLY VULNERABLE:
    No authorization check is performed.
    """

    user = USERS.get(user_id)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    return user


@app.get("/api/profile")
async def get_profile(
    x_user_id: str | None = Header(default=None),
):
    """
    INTENTIONALLY VULNERABLE:
    Client-controlled identity header is trusted.
    """

    if not x_user_id:
        raise HTTPException(
            status_code=401,
            detail="Missing X-User-ID header",
        )

    user = USERS.get(x_user_id)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    return user

@app.get("/api/admin")
async def admin_panel(
    x_role: str | None = Header(
        default=None,
        alias="X-Role",
    ),
):
    """
    INTENTIONALLY VULNERABLE:
    Authorization is controlled by a client-supplied header.
    """

    if x_role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin privileges required",
        )

    return {
        "status": "success",
        "message": "Administrative panel accessed",
        "sensitive_data": "internal-admin-data",
    }