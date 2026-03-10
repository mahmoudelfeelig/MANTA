from __future__ import annotations

import hmac
from fastapi import Cookie, Header, HTTPException, status


def extract_token(authorization: str | None, x_endpoint_token: str | None, dashboard_session: str | None = None) -> str:
    if x_endpoint_token:
        return x_endpoint_token.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    if dashboard_session:
        return dashboard_session.strip()
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
    dashboard_session: str | None = Cookie(default=None),
) -> None:
    token = extract_token(authorization, x_endpoint_token, dashboard_session)
    verify_token(expected_token, token)
