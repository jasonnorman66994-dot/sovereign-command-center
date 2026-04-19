from __future__ import annotations

import os
import datetime
from functools import lru_cache
import json
from pathlib import Path
from typing import Any

import jwt
from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


security = HTTPBearer(auto_error=False)
_ABAC_DENY_TOTAL = 0
_ABAC_DENY_BY_ACTION: dict[str, int] = {}
_last_abac_reset: dict[str, str] = {}


def _auth_mode() -> str:
    # supported: legacy | oidc | hybrid
    return os.getenv("SHADOW_AUTH_MODE", "hybrid").strip().lower()


def _legacy_token() -> str:
    return os.getenv("SHADOW_API_TOKEN", "shadow-secure-default-token-2026")


def _api_key_registry_path() -> Path:
    return Path(os.getenv("SHADOW_API_KEY_FILE", "data/api_keys.json"))


def _abac_policy_path() -> Path:
    return Path(os.getenv("SHADOW_ABAC_POLICY_FILE", "data/abac_policy.json"))


@lru_cache(maxsize=1)
def _api_key_registry() -> dict[str, Any]:
    path = _api_key_registry_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


@lru_cache(maxsize=1)
def _abac_policy() -> dict[str, Any]:
    path = _abac_policy_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _verify_api_key(api_key: str) -> dict[str, Any] | None:
    if not api_key:
        return None
    registry = _api_key_registry()
    config = registry.get(api_key)
    if not isinstance(config, dict):
        return None
    if not bool(config.get("enabled", True)):
        return None

    return {
        "sub": config.get("subject", "api-key-user"),
        "preferred_username": config.get("username", "api-key-user"),
        "tenant": config.get("tenant_id", "global"),
        "role": config.get("role", "analyst"),
        "security_clearance": int(config.get("security_clearance", 2)),
        "auth_mode": "api_key",
    }


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
        raise HTTPException(
            status_code=500, detail="OIDC not configured: missing JWKS or public key"
        )
    signing_key = client.get_signing_key_from_jwt(token)
    payload = jwt.decode(token, signing_key.key, **kwargs)
    return dict(payload)


def _clearance_from_claims(claims: dict[str, Any]) -> int:
    raw = claims.get("security_clearance", claims.get("clearance", 0))
    try:
        return int(raw)
    except Exception:
        return 0


def verify_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> dict[str, Any]:
    mode = _auth_mode()
    token = credentials.credentials if credentials else ""

    key_claims = _verify_api_key(x_api_key or "")
    if key_claims is not None:
        return key_claims

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
            raise HTTPException(
                status_code=401, detail="Invalid or expired security token"
            )
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(
                status_code=401, detail="Invalid or expired security token"
            )

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


def _claims_roles(claims: dict[str, Any]) -> set[str]:
    roles: set[str] = set()
    single_role = claims.get("role")
    if isinstance(single_role, str) and single_role.strip():
        roles.add(single_role.strip().lower())

    multi_roles = claims.get("roles")
    if isinstance(multi_roles, list):
        for item in multi_roles:
            if isinstance(item, str) and item.strip():
                roles.add(item.strip().lower())

    return roles


def _abac_enforced() -> bool:
    return os.getenv("SHADOW_ABAC_ENFORCE", "true").strip().lower() == "true"


def _record_abac_deny(
    action: str,
    *,
    claims: dict[str, Any] | None = None,
    reason: str = "policy_denied",
) -> None:
    global _ABAC_DENY_TOTAL
    key = (action or "unknown").strip() or "unknown"
    _ABAC_DENY_TOTAL += 1
    _ABAC_DENY_BY_ACTION[key] = _ABAC_DENY_BY_ACTION.get(key, 0) + 1

    tenant_id = "global"
    if isinstance(claims, dict):
        tenant_id = (
            str(
                claims.get("tenant")
                or claims.get("tenant_id")
                or claims.get("business")
                or "global"
            ).strip()
            or "global"
        )

    try:
        from core.storage import track_abac_deny

        track_abac_deny(
            action=key,
            tenant_id=tenant_id,
            reason=reason,
            meta={"auth_mode": str((claims or {}).get("auth_mode", "unknown"))},
        )
    except Exception:
        # Deny persistence should never break auth enforcement.
        pass


def get_abac_metrics() -> dict[str, Any]:
    return {
        "deny_total": int(_ABAC_DENY_TOTAL),
        "deny_by_action": dict(_ABAC_DENY_BY_ACTION),
        "last_reset_by": _last_abac_reset.get("actor", ""),
        "last_reset_at": _last_abac_reset.get("at", ""),
    }


def reset_abac_metrics(actor: str = "unknown") -> dict[str, Any]:
    global _ABAC_DENY_TOTAL
    _ABAC_DENY_TOTAL = 0
    _ABAC_DENY_BY_ACTION.clear()
    _last_abac_reset["actor"] = actor
    _last_abac_reset["at"] = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return get_abac_metrics()


def enforce_abac(
    *,
    action: str,
    claims: dict[str, Any],
    tenant: str | None = None,
    resource: dict[str, Any] | None = None,
) -> None:
    _ = resource
    if not _abac_enforced():
        return

    policy = _abac_policy()
    rule = policy.get("actions", {}).get(action, {}) if isinstance(policy, dict) else {}
    if not isinstance(rule, dict) or not rule:
        return

    min_clearance = int(rule.get("min_clearance", 0) or 0)
    if _clearance_from_claims(claims) < min_clearance:
        _record_abac_deny(action, claims=claims, reason="insufficient_clearance")
        raise HTTPException(
            status_code=403, detail="ABAC denied: insufficient clearance"
        )

    allowed_roles = {
        str(item).strip().lower()
        for item in rule.get("allowed_roles", [])
        if str(item).strip()
    }
    if allowed_roles and not (_claims_roles(claims) & allowed_roles):
        _record_abac_deny(action, claims=claims, reason="role_not_allowed")
        raise HTTPException(status_code=403, detail="ABAC denied: role not allowed")

    scope = str(rule.get("tenant_scope", "self")).strip().lower()
    if not tenant or scope in {"any", "*"}:
        return

    requester_tenant = (
        str(
            claims.get("tenant")
            or claims.get("tenant_id")
            or claims.get("business")
            or "global"
        ).strip()
        or "global"
    )
    if requester_tenant.lower() == tenant.lower():
        return

    if scope == "self":
        _record_abac_deny(action, claims=claims, reason="tenant_scope_self")
        raise HTTPException(status_code=403, detail="ABAC denied: tenant scope")

    if scope == "self_or_admin":
        if "admin" in _claims_roles(claims) and _clearance_from_claims(claims) >= 4:
            return
        _record_abac_deny(action, claims=claims, reason="tenant_scope_self_or_admin")
        raise HTTPException(status_code=403, detail="ABAC denied: tenant scope")
