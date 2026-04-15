Keycloak Helm deploy starter

1) Add chart repo
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

2) Install Keycloak
helm upgrade --install shadow-keycloak bitnami/keycloak -n shadow-iam --create-namespace -f k8s/keycloak/values.yaml

3) Create OIDC client in Keycloak realm
- Client ID: shadow-toolz-dashboard
- Public client: ON
- Standard flow: ON
- PKCE method: S256
- Valid redirect URI: http://127.0.0.1:8055/*

4) Set SHADOW-TOOLZ env vars
SHADOW_AUTH_MODE=oidc
OIDC_ISSUER=http://keycloak.shadow.local/realms/shadow
OIDC_AUDIENCE=shadow-toolz
OIDC_CLIENT_ID=shadow-toolz-dashboard
OIDC_REDIRECT_URI=http://127.0.0.1:8055/

5) Optional ABAC claim
Add protocol mapper in Keycloak for claim: security_clearance

6) Local workstation alternative
If you are running strict local OIDC against a workstation Keycloak instead of Kubernetes, use the repo runbook at LOCAL_KEYCLOAK_OPERATOR_RUNBOOK.md for startup, recovery, reseed, password rotation, and PKCE validation.
