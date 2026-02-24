from __future__ import annotations

import hmac
from fastapi import Header, HTTPException, status


def extract_token(authorization: str | None, x_endpoint_token: str | None) -> str:
    if x_endpoint_token:
        return x_endpoint_token.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def verify_token(expected: str, provided: str) -> None:
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Adapter token not configured",
        )
    if not provided or not hmac.compare_digest(expected, provided):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )


def require_auth(
    expected_token: str,
    authorization: str | None = Header(default=None),
    x_endpoint_token: str | None = Header(default=None),
) -> None:
    token = extract_token(authorization, x_endpoint_token)
    verify_token(expected_token, token)
