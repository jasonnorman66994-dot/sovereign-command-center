# Local Keycloak Operator Runbook

Use this when running strict `oidc` mode against a workstation Keycloak instance instead of Kubernetes.

## Prerequisites

- Keycloak binary under `%USERPROFILE%\tools\keycloak-dist\keycloak-26.6.0\bin`
- JDK 17 under `%USERPROFILE%\tools\jdk\jdk-17.0.18+8`
- Dashboard configured with `SHADOW_AUTH_MODE=oidc`
- Local redirect URI `http://localhost:8055/`

## Start Local Keycloak

```powershell
$env:JAVA_HOME = "$env:USERPROFILE\tools\jdk\jdk-17.0.18+8"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
& "$env:USERPROFILE\tools\keycloak-dist\keycloak-26.6.0\bin\kc.bat" start-dev --optimized
```

## Recover Admin Access

Only use this if the permanent `admin` account is unavailable.

```powershell
$env:JAVA_HOME = "$env:USERPROFILE\tools\jdk\jdk-17.0.18+8"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
$env:KC_BOOTSTRAP_ADMIN_PASSWORD = '<temporary-bootstrap-password>'
& "$env:USERPROFILE\tools\keycloak-dist\keycloak-26.6.0\bin\kc.bat" bootstrap-admin user --no-prompt --username temp-admin --password:env KC_BOOTSTRAP_ADMIN_PASSWORD
```

## Reseed Realm and Client

Reseed the local realm, dashboard client, audience mapper, and operator user.

```powershell
$secureAdmin = ConvertTo-SecureString '<current-admin-password>' -AsPlainText -Force
.\scripts\reseed-keycloak.ps1 -AdminUser admin -AdminPassword $secureAdmin
```

## Rotate Permanent Credentials

Rotate the permanent `admin` and `operator` passwords with shell-safe ASCII values.

```powershell
.\scripts\rotate-keycloak-passwords.ps1 \
  -CurrentAdminPassword '<current-admin-password>' \
  -NewAdminPassword '<new-admin-password>' \
  -NewOperatorPassword '<new-operator-password>'
```

## Validation Sequence

1. Confirm the dashboard reports strict OIDC config from `/auth/config`.
2. Verify direct token issuance for `operator` against `/realms/shadow-realm/protocol/openid-connect/token`.
3. Verify the authorization-code plus PKCE flow against `http://localhost:8055/`.
4. If a temporary `temp-admin` account was used for recovery, promote the permanent `admin` account first, validate `kcadm` login as `admin`, then remove `temp-admin`.

## Operational Notes

- Realm: `shadow-realm`
- Client ID: `shadow-toolz-dashboard`
- Audience: `shadow-toolz`
- Redirect URI: `http://localhost:8055/`
- Recommended pattern: after any admin cleanup or password rotation, validate both direct token issuance and the PKCE browser flow before treating the environment as healthy.
