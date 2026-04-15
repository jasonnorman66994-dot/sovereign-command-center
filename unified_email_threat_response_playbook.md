## 📘 Unified Training Drill Workbook (All Scenarios Combined)

This workbook simulates a morning in the SOC where three different email‑related threats appear in sequence. Use it for analyst/agent training, tabletop exercises, or onboarding.

### 🧭 Overview

The drill covers:
- Log interpretation
- Threat classification
- Recommended actions
- Escalation logic
- Pattern recognition across scenarios

---

🥇 **Phase 1 — Spam Burst Detection**

**Input Log Snippet**

```
Apr 14 03:12:01 mailserver postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[203.0.113.10]: 554 5.7.1 <spam@example.com>: Relay access denied
Apr 14 03:12:02 mailserver postfix/smtpd[1234]: warning: unknown[203.0.113.10]: SASL LOGIN authentication failed
Apr 14 03:12:05 mailserver postfix/smtpd[1234]: disconnect from unknown[203.0.113.10]
```

**What to Detect:**
- High‑frequency inbound attempts
- Authentication failures
- Relay‑denied behavior typical of spam bots

**Expected Classification:**
Spam burst / bot‑driven relay probing

**Expected Actions:**
- Block IP
- Increase rate‑limit thresholds
- Verify no internal accounts were compromised
- Monitor for repeat attempts

---

🥈 **Phase 2 — Malware Attachment Attempt**

**Input Log Snippet**

```
Apr 14 03:45:10 mailserver amavis[5678]: (5678-01) Blocked INFECTED (Eicar-Test-Signature) from <attacker@example.com> to <user@example.com>
Apr 14 03:45:11 mailserver amavis[5678]: (5678-01) quarantined Eicar-Test-Signature
```

**What to Detect:**
- Malware signature match
- Quarantine event
- Known test signature (EICAR)

**Expected Classification:**
Malware attachment attempt

**Expected Actions:**
- Confirm quarantine
- Notify security team
- Check if similar messages bypassed filters
- Validate AV signatures are up to date

---

🥉 **Phase 3 — Unauthorized Access Attempt**

**Input Log Snippet**

```
Apr 14 04:15:20 mailserver imapd[8888]: LOGIN FAILED user=finance_team@example.com host=203.0.113.45
Apr 14 04:15:21 mailserver imapd[8888]: LOGIN FAILED user=finance_team@example.com host=198.51.100.23
Apr 14 04:15:22 mailserver imapd[8888]: LOGIN FAILED user=finance_team@example.com host=192.0.2.10
Apr 14 04:15:25 mailserver imapd[8888]: LOGIN SUCCESS user=finance_team@example.com host=203.0.113.45
Apr 14 04:15:26 mailserver imapd[8888]: SESSION START user=finance_team@example.com host=203.0.113.45
```

**What to Detect:**
- Multiple failed logins from rotating IPs
- Sudden success → likely credential compromise
- Session start from suspicious IP

**Expected Classification:**
Unauthorized access / credential compromise

**Expected Actions:**
- Disable account
- Terminate active session
- Force password reset
- Enforce MFA
- Block IPs
- Investigate credential theft vector

---

### 📦 Standalone Exercises (Modular Format)

**Exercise 1 — Spam Burst**
- Goal: Identify spam‑related anomalies
- Input: Spam log snippet
- Expected Output: Classification + recommended actions

**Exercise 2 — Malware Attachment**
- Goal: Detect malware signatures and quarantine events
- Input: EICAR detection logs
- Expected Output: Classification + containment steps

**Exercise 3 — Unauthorized Access**
- Goal: Identify credential compromise
- Input: Failed + successful login sequence
- Expected Output: Classification + account lockdown workflow

---
## 📜 Unauthorized Access Log Snippet

```
Apr 14 04:15:20 mailserver imapd[8888]: LOGIN FAILED user=finance_team@example.com host=203.0.113.45
Apr 14 04:15:21 mailserver imapd[8888]: LOGIN FAILED user=finance_team@example.com host=198.51.100.23
Apr 14 04:15:22 mailserver imapd[8888]: LOGIN FAILED user=finance_team@example.com host=192.0.2.10
Apr 14 04:15:25 mailserver imapd[8888]: LOGIN SUCCESS user=finance_team@example.com host=203.0.113.45
Apr 14 04:15:26 mailserver imapd[8888]: SESSION START user=finance_team@example.com host=203.0.113.45
```

---

### 🔎 Red Flags to Spot

- Multiple failed logins from different IPs in seconds → brute‑force or credential stuffing attack.
- Suspicious IP addresses (`203.0.113.45`, `198.51.100.23`, `192.0.2.10`) → not normal user behavior.
- Sudden success after failures → attacker finally guessed or used stolen credentials.
- Session start from unusual location → indicates unauthorized access.

---

### 🛠️ Do

1. **Detection:** Spot failed login spikes in logs.
2. **Investigation:** Confirm IPs are not from the employee’s usual location.
3. **Containment:** Disable the account and terminate active sessions.
4. **Root Cause:** Identify if credentials were stolen or brute‑forced.
5. **Remediation:** Reset password, enforce MFA, block suspicious IPs.
6. **Recovery:** Monitor for repeat attempts and update access policies.

---

## 📊 Visual Dashboard Templates & Script Enhancements

- Use the CSV output from `analyze_mail_log.py` to create:
	- **Line/Bar Charts:** Emails sent per sender per hour (Excel, Google Sheets, Grafana, Kibana)
	- **Pie Charts:** Top attachments or senders
	- **Heatmaps:** Activity by hour and sender
- For unauthorized access, plot failed logins per user/IP over time to spot brute-force attacks.
- Enhance the script to:
	- Parse IMAP/POP3/SMTP login failures and successes
	- Output a separate CSV for login attempts (user, IP, status, timestamp)
	- Alert on rapid failed logins or sudden success after failures

---
## 🧑‍💻 Advanced Scenarios

### A. Credential Stuffing Attack
- **Log:** Multiple failed logins from different IPs, then a sudden spike in outbound mail.
- **Response:** Lock account, investigate source IPs, enforce MFA.

### B. Internal Phishing
- **Log:** Compromised HR account sends phishing to all employees.
- **Response:** Quarantine, notify users, reset credentials, review internal comms.

### C. Outbound Spam via Scripted Bot
- **Log:** Outbound emails sent every few seconds, always with similar subject/attachment.
- **Response:** Disable account, scan for malware, block script signatures.

---

## 🐍 Ready-to-Run Log Analysis Script

For advanced analysis and visualization, use the included script:

- [analyze_mail_log.py](analyze_mail_log.py)

This script extracts spikes, suspicious attachments, and rapid sending from your mail logs, and outputs a CSV for visualization in Excel, Google Sheets, or dashboards.

---
## 📜 Malware Spam Log Snippet

```
Apr 14 04:10:45 mailserver postfix/smtpd[5555]: 987LMN: client=unknown[192.168.2.77]
Apr 14 04:10:46 mailserver postfix/cleanup[6666]: 987LMN: from=<hr_team@example.com>, size=4096, nrcpt=75
Apr 14 04:10:46 mailserver postfix/qmgr[7777]: 987LMN: from=<hr_team@example.com>, to=<victim1@gmail.com>, relay=none, status=sent, attachment=invoice.pdf
Apr 14 04:10:46 mailserver postfix/qmgr[7777]: 987LMN: from=<hr_team@example.com>, to=<victim2@yahoo.com>, relay=none, status=sent, attachment=invoice.pdf
Apr 14 04:10:47 mailserver postfix/qmgr[7777]: 987LMN: from=<hr_team@example.com>, to=<victim3@outlook.com>, relay=none, status=sent, attachment=invoice.pdf
```

---

### 🔎 Red Flags to Spot

- Unknown client IP: suspicious source (`192.168.2.77`).
- High recipient count: `nrcpt=75` → one email blasted to many people.
- Attachment field: `invoice.pdf` → common disguise for malware.
- Rapid sending: multiple emails in seconds → automated spam/malware campaign.

---

### 🛠️  What to Do

1. **Detection:** Notice the spike and suspicious attachments.
2. **Investigation:** Sandbox the `invoice.pdf` to see if it’s malware.
3. **Containment:** Quarantine all emails with that attachment, disable the compromised account.
4. **Root Cause:** Check if the account was hacked or malware is sending automatically.
5. **Remediation:** Patch systems, reset credentials, update antivirus signatures.
6. **Recovery:** Monitor endpoints and request delisting if blacklisted.

---

## 📊 Visualization & Automation

- Use log analysis scripts to extract spikes, sender accounts, and attachment names from mail logs.
- Visualize spikes and suspicious activity with tools like Kibana, Grafana, or even Excel charts.
- Example: Plot number of emails sent per account per hour to spot outbreaks.
- Automate detection with scripts that alert on high nrcpt, rapid sending, or suspicious attachments.

### Example Python Snippet for Log Analysis

```python
import re
from collections import Counter

logfile = 'maillog.txt'
sender_counter = Counter()
attachment_counter = Counter()

with open(logfile) as f:
	for line in f:
		m = re.search(r'from=<([^>]+)>', line)
		if m:
			sender_counter[m.group(1)] += 1
		a = re.search(r'attachment=([\w.]+)', line)
		if a:
			attachment_counter[a.group(1)] += 1

print('Top senders:', sender_counter.most_common(5))
print('Top attachments:', attachment_counter.most_common(5))
```

---
# Unified Email Threat Response Playbook

> **Last Updated:** April 14, 2026

## How to Use
1. Identify the type of email threat (spam, phishing, malware, unauthorized access).
2. Follow the relevant response workflow step-by-step.
3. Use the cross-linked resources in the 'See Also' table for deeper guidance or automation.
4. Integrate this playbook into your incident response documentation or training.

This playbook consolidates incident response workflows for multiple email-related threats: spam outbreaks, phishing attempts, malware distribution, and unauthorized access. It is designed for administrators to act quickly and consistently.

---

## 1. Spam Outbreak Response
- **Detection:** Monitor logs and SIEM alerts for outbound spikes.
- **Investigation:** Identify source accounts, review email samples, check SPF/DKIM/DMARC.
- **Containment:** Disable compromised accounts, throttle mail, quarantine suspicious emails.
- **Root Cause:** Check for open relay, scan devices for malware.
- **Remediation:** Reset credentials, enforce MFA, patch systems.
- **Recovery:** Request delisting, monitor traffic, document incident.

---

## 2. Phishing Attack Response
- **Detection:** User reports suspicious emails, gateway filters flag phishing attempts.
- **Investigation:** Analyze headers, links, and attachments; verify sender authenticity.
- **Containment:** Quarantine phishing emails, block malicious domains.
- **Root Cause:** Identify compromised accounts or spoofed domains.
- **Remediation:** Educate users, update filters, enforce stricter authentication.
- **Recovery:** Monitor for repeat attempts, share indicators of compromise (IOCs).

---

## 3. Malware Distribution Response
- **Detection:** Alerts from endpoint security or email gateway.
- **Investigation:** Extract and analyze attachments, sandbox suspicious files.
- **Containment:** Quarantine infected emails, block file types if necessary.
- **Root Cause:** Trace source of malware distribution, check compromised accounts.
- **Remediation:** Patch vulnerabilities, update antivirus signatures, reset credentials.
- **Recovery:** Monitor endpoints, conduct forensic analysis, strengthen attachment policies.

---

## 4. Unauthorized Access Response
- **Detection:** Alerts of unusual login attempts, failed authentication, or geographic anomalies.
- **Investigation:** Review login logs, check IP addresses, confirm user activity.
- **Containment:** Disable compromised accounts, revoke active sessions.
- **Root Cause:** Identify method of compromise (phishing, credential stuffing, weak passwords).
- **Remediation:** Reset credentials, enforce MFA, educate users.
- **Recovery:** Monitor for further attempts, update access policies, document incident.

---

## ✅ Key Takeaways
- Rapid detection and containment are critical across all threats.
- Authentication protocols (SPF, DKIM, DMARC, MFA) are essential safeguards.
- Continuous monitoring and user education reduce recurrence.
- Documentation ensures compliance and strengthens future response.

---

This unified playbook can be integrated into your organization’s incident response framework, providing a single reference for handling diverse email-related threats.

---

## 📚 Real-World Example: Spam Outbreak Mapped to Playbook

This scenario shows how the playbook works in practice:

1. **Detection:** 800 emails/hour from one account (spike in logs)
2. **Investigation:** Checked samples, found phishing links, SPF failed
3. **Containment:** Disabled the account and quarantined emails
4. **Root Cause:** Discovered the password was reused and stolen
5. **Remediation:** Enforced MFA, reset passwords, patched the server
6. **Recovery:** Requested delisting and monitored traffic

👉 That’s the full cycle in motion: Spot → Understand → Stop → Find why → Fix → Restore trust.

---

## 📝 Incident: Spamming Logs and Emails

### 1. Spamming Logs

- Every mail server keeps a log file — like a diary of all email activity.
- Each entry records details such as:
	- Who sent the email (account or IP address)
	- When it was sent (timestamp)
	- Where it was going (recipient address)
	- Whether it was accepted, rejected, or bounced

👉 Logs are the first place admins look when they suspect spam.

---

### 2. Spam Emails

- They often contain:
	- Phishing links (fake login pages, malicious downloads)
	- Spoofed sender addresses (pretending to be someone else)
	- Attachments with malware
- Spam emails usually come in large bursts — hundreds or thousands in minutes.

👉 By pulling samples from logs or quarantine, admins can see the content and confirm it’s spam.

---

### 3. How Admins Use Logs During an Outbreak

- **Detection:** Spot spikes in outbound traffic.
	- Example command: `tail -f /var/log/maillog` (streams live activity to catch unusual patterns)
- **Investigation:** Find which account is sending the most.
	- Example command: `grep "from=" /var/log/maillog | sort | uniq -c | sort -nr` (shows accounts ranked by number of emails sent)
- **Containment:** Once the account is identified, disable it immediately.

---

### 4. Why This Matters

- Logs tell the story of the outbreak: who, when, how many, and what type of emails.
- Spam emails themselves show the attack method: phishing, malware, or spoofing.
- Together, they guide admins through the response workflow: Spot → Understand → Stop → Fix → Restore trust.

---

## 📜 Example Mail Log Snippet

```
Apr 14 03:55:21 mailserver postfix/smtpd[1234]: 123ABCD: client=unknown[192.168.1.45]
Apr 14 03:55:22 mailserver postfix/cleanup[5678]: 123ABCD: from=<compromised_user@example.com>, size=2048, nrcpt=50
Apr 14 03:55:22 mailserver postfix/qmgr[9101]: 123ABCD: from=<compromised_user@example.com>, to=<victim1@gmail.com>, relay=none, status=sent
Apr 14 03:55:22 mailserver postfix/qmgr[9101]: 123ABCD: from=<compromised_user@example.com>, to=<victim2@yahoo.com>, relay=none, status=sent
Apr 14 03:55:23 mailserver postfix/qmgr[9101]: 123ABCD: from=<compromised_user@example.com>, to=<victim3@outlook.com>, relay=none, status=sent
```

---

### 🔎 How to Read This

- **Timestamp:** `Apr 14 03:55:21` → When the email was processed.
- **Process:** `postfix/smtpd` → The mail server software handling the email.
- **Client:** `unknown[192.168.1.45]` → The IP address of the sender.
- **From:** `<compromised_user@example.com>` → The account sending the spam.
- **Recipients:** `nrcpt=50` → This single email is being blasted to 50 recipients.
- **Status:** `status=sent` → The server successfully delivered it.

👉 In just a few seconds, one account sent dozens of emails to different domains — a clear sign of spam.

---

### 🛠️  Admins Do Next

1. **Detection:** Notice the spike in logs.
2. **Investigation:** Confirm the sender is compromised.
3. **Containment:** Disable `compromised_user@example.com`.
4. **Root Cause:** Check if the account was hacked or if malware is sending automatically.
5. **Remediation:** Reset password, enforce MFA, patch server.
6. **Recovery:** Request delisting if the domain gets blacklisted.

---

This is how spamming logs and emails work together: logs show the activity, emails show the content. Admins use both to respond quickly.

---

## 📜 Example Mail Log Snippet 2: High-Volume Spam from Compromised Account

```
Apr 14 04:05:10 mailserver postfix/smtpd[2222]: 789XYZ: client=unknown[172.16.0.99]
Apr 14 04:05:11 mailserver postfix/cleanup[3333]: 789XYZ: from=<sales_team@example.com>, size=1536, nrcpt=150
Apr 14 04:05:11 mailserver postfix/qmgr[4444]: 789XYZ: from=<sales_team@example.com>, to=<randomuser1@gmail.com>, relay=none, status=sent
Apr 14 04:05:11 mailserver postfix/qmgr[4444]: 789XYZ: from=<sales_team@example.com>, to=<randomuser2@yahoo.com>, relay=none, status=sent
Apr 14 04:05:12 mailserver postfix/qmgr[4444]: 789XYZ: from=<sales_team@example.com>, to=<randomuser3@outlook.com>, relay=none, status=sent
```

---

### 🔎 Red Flags to Spot

- Unknown client IP: `unknown[172.16.0.99]` → suspicious source.
- High recipient count: `nrcpt=150` → one email blasted to 150 people.
- Multiple domains targeted: Gmail, Yahoo, Outlook all hit in seconds.
- Rapid timestamps: Emails sent within one second → automated spam.

---

### 🛠️ What to Do

1. **Detection:** Notice the spike in logs.
2. **Investigation:** Confirm sender `<sales_team@example.com>` is compromised.
3. **Containment:** Disable that account immediately.
4. **Root Cause:** Check if password was stolen or server misconfigured.
5. **Remediation:** Reset credentials, enforce MFA, patch server.
6. **Recovery:** Request delisting if blacklisted.

---

---

## See Also
| 📄 Resource | Description |
|---|---|
| [✅ Email Spam Incident Response Checklist](email_spam_incident_response_checklist.md) | Step-by-step guide for spam outbreaks, with commands and key actions. |
| [🐧 Linux Incident Response Script](email_incident_response.sh) | Automated Bash script for Linux-based email incident response. |
| [🪟 Windows Incident Response Script](email_incident_response.ps1) | Automated PowerShell script for Windows/Exchange environments. |
| [📬 Extracted Email Addresses](extracted_emails.md) | All unique email addresses and their context, extracted from the workspace. |
| [📚 Documentation Index](EMAIL_SECURITY_DOCS_INDEX.md) | Central index for all email security documentation and automation. |
