from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


security = HTTPBearer(auto_error=False)


def _auth_mode() -> str:
    # supported: legacy | oidc | hybrid
    return os.getenv("SHADOW_AUTH_MODE", "hybrid").strip().lower()


def _legacy_token() -> str:
    return os.getenv("SHADOW_API_TOKEN", "shadow-secure-default-token-2026")


def _oidc_issuer() -> str:
    return os.getenv("OIDC_ISSUER", "").strip()


def _oidc_jwks_url() -> str:
    explicit = os.getenv("OIDC_JWKS_URL", "").strip()
    if explicit:
        return explicit
    issuer = _oidc_issuer().rstrip("/")
    if not issuer:
        return ""
    return f"{issuer}/protocol/openid-connect/certs"


def _oidc_public_key() -> str:
    return os.getenv("OIDC_PUBLIC_KEY", "").strip()


def _oidc_audience() -> str:
    return os.getenv("OIDC_AUDIENCE", "shadow-toolz").strip()


def _oidc_algorithms() -> list[str]:
    value = os.getenv("OIDC_ALGORITHMS", "RS256")
    return [item.strip() for item in value.split(",") if item.strip()]


def _oidc_scopes() -> str:
    return os.getenv("OIDC_SCOPES", "openid profile email").strip()


def _oidc_client_id() -> str:
    return os.getenv("OIDC_CLIENT_ID", "shadow-toolz-dashboard").strip()


def _oidc_redirect_uri() -> str:
    explicit = os.getenv("OIDC_REDIRECT_URI", "").strip()
    return explicit


def _oidc_authorize_url() -> str:
    explicit = os.getenv("OIDC_AUTHORIZE_URL", "").strip()
    if explicit:
        return explicit
    issuer = _oidc_issuer().rstrip("/")
    if not issuer:
        return ""
    return f"{issuer}/protocol/openid-connect/auth"


def _oidc_token_url() -> str:
    explicit = os.getenv("OIDC_TOKEN_URL", "").strip()
    if explicit:
        return explicit
    issuer = _oidc_issuer().rstrip("/")
    if not issuer:
        return ""
    return f"{issuer}/protocol/openid-connect/token"


def auth_config() -> dict[str, Any]:
    mode = _auth_mode()
    return {
        "auth_mode": mode,
        "oidc_enabled": bool(_oidc_jwks_url() or _oidc_public_key()),
        "client_id": _oidc_client_id(),
        "audience": _oidc_audience(),
        "scopes": _oidc_scopes(),
        "authorize_url": _oidc_authorize_url(),
        "token_url": _oidc_token_url(),
        "redirect_uri": _oidc_redirect_uri(),
    }


@lru_cache(maxsize=1)
def _jwks_client() -> jwt.PyJWKClient | None:
    jwks_url = _oidc_jwks_url()
    if not jwks_url:
        return None
    return jwt.PyJWKClient(jwks_url)


def _decode_oidc_token(token: str) -> dict[str, Any]:
    audience = _oidc_audience()
    algorithms = _oidc_algorithms()
    public_key = _oidc_public_key()
    issuer = _oidc_issuer()

    kwargs: dict[str, Any] = {
        "algorithms": algorithms,
        "audience": audience,
        "options": {"verify_signature": True, "verify_aud": bool(audience)},
    }
    if issuer:
        kwargs["issuer"] = issuer

    if public_key:
        payload = jwt.decode(token, public_key, **kwargs)
        return dict(payload)

    client = _jwks_client()
    if client is None:
        raise HTTPException(status_code=500, detail="OIDC not configured: missing JWKS or public key")
    signing_key = client.get_signing_key_from_jwt(token)
    payload = jwt.decode(token, signing_key.key, **kwargs)
    return dict(payload)


def _clearance_from_claims(claims: dict[str, Any]) -> int:
    raw = claims.get("security_clearance", claims.get("clearance", 0))
    try:
        return int(raw)
    except Exception:
        return 0


def verify_token(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, Any]:
    mode = _auth_mode()
    token = credentials.credentials if credentials else ""

    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    if mode in {"legacy", "hybrid"} and token == _legacy_token():
        return {
            "sub": "legacy-operator",
            "preferred_username": "legacy-operator",
            "security_clearance": 5,
            "auth_mode": "legacy",
        }

    if mode in {"oidc", "hybrid"}:
        try:
            payload = _decode_oidc_token(token)
            payload["auth_mode"] = "oidc"
            return payload
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid or expired security token")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid or expired security token")

    raise HTTPException(status_code=401, detail="Unauthorized")


def verify_websocket_token(token: str | None) -> dict[str, Any]:
    if not token:
        raise HTTPException(status_code=401, detail="Missing websocket token")

    mode = _auth_mode()
    if mode in {"legacy", "hybrid"} and token == _legacy_token():
        return {
            "sub": "legacy-operator",
            "preferred_username": "legacy-operator",
            "security_clearance": 5,
            "auth_mode": "legacy",
        }
    if mode in {"oidc", "hybrid"}:
        try:
            payload = _decode_oidc_token(token)
            payload["auth_mode"] = "oidc"
            return payload
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid websocket token")

    raise HTTPException(status_code=401, detail="Unauthorized")


def require_clearance(min_level: int):
    def _dependency(claims: dict[str, Any] = Depends(verify_token)) -> dict[str, Any]:
        if _clearance_from_claims(claims) < min_level:
            raise HTTPException(status_code=403, detail="Insufficient clearance level")
        return claims

    return _dependency
