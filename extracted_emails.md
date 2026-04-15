# Extracted Email Addresses from Workspace

- jasonnorman66994@gmail.com
- alerts@your-company.com
- soc@your-company.com
- it_admin@alpha.com
- sec_ops@alpha.com
- security@beta-corp.net
- operator@shadow.local

## Files and Contexts

### .env
- SHADOW_EMAIL_USER=jasonnorman66994@gmail.com
- SHADOW_ADMIN_EMAIL=jasonnorman66994@gmail.com
- OIDC_SCOPES=openid profile email

### .env.example
- SHADOW_EMAIL_USER=alerts@your-company.com
- SHADOW_ADMIN_EMAIL=soc@your-company.com
- OIDC_SCOPES=openid profile email

### cve-43887-check.sh
- EMAIL="jasonnorman66994@gmail.com"

### cve43887_healthcheck.ps1
- .\cve43887_healthcheck.ps1 -Quiet -AlertEmail "jasonnorman66994@gmail.com"
- [string]$AlertEmail = "jasonnorman66994@gmail.com"

### cve43887_dashboard_html.ps1
- [string]$AlertEmail = "jasonnorman66994@gmail.com"

### README.md
- "contacts": ["it_admin@alpha.com", "sec_ops@alpha.com"]
- "contacts": ["security@beta-corp.net"]
- ALERT_EMAIL=jasonnorman66994@gmail.com ./cve43887_healthcheck.sh --quiet
- 0 0 * * 0 ALERT_EMAIL=jasonnorman66994@gmail.com /usr/local/bin/cve43887_healthcheck.sh --quiet
- pwsh -ExecutionPolicy Bypass -File .\cve43887_healthcheck.ps1 -Quiet -AlertEmail "jasonnorman66994@gmail.com"

### sovereign_pulse_scheduler.py
- ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "jasonnorman66994@gmail.com")

### sovereign_db.py
- ("jasonnorman66994@gmail.com",)

### frontend/system_health.html
- <p class="active-target-email">jasonnorman66994@gmail.com</p>
- <input type="email" id="new-target-email" class="target-input" placeholder="user@example.com">
- const target = data.target || 'jasonnorman66994@gmail.com';

### data/targets.json
- "it_admin@alpha.com"
- "sec_ops@alpha.com"
- "security@beta-corp.net"
- "jasonnorman66994@gmail.com"

### scripts/reseed-keycloak.ps1
- email=operator@shadow.local

### sovereign-hud/package-lock.json
- i@izs.me (deprecated glob package)

---

This list includes all unique email addresses and their context found in your workspace. If you need this in another format or want to filter by file, let me know.