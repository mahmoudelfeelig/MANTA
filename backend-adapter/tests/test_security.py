from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.security import verify_any_token, verify_token


def test_device_token_does_not_satisfy_operator_token() -> None:
    with pytest.raises(HTTPException) as exc_info:
        verify_token("operator-token", "device-token")

    assert exc_info.value.status_code == 401


def test_safe_read_can_accept_device_or_operator_token() -> None:
    verify_any_token(("device-token", "operator-token"), "device-token")
    verify_any_token(("device-token", "operator-token"), "operator-token")
