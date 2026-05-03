# Wazuh Rule Reference

## Rule Severity Levels
Wazuh rules have severity levels from 0 to 15:
- **Level 0-3**: System notifications and low-priority events
- **Level 4-7**: Low to medium severity events requiring attention
- **Level 8-11**: High severity events indicating potential security issues
- **Level 12-13**: High severity events requiring immediate investigation
- **Level 14-15**: Critical events — active attacks or severe security breaches

## Common Rule IDs

### Authentication Rules
- **Rule 5501**: Login session opened — A user successfully logged in via PAM
- **Rule 5502**: Login session closed — User session ended normally
- **Rule 5503**: User login failed — An authentication attempt was rejected
- **Rule 5710**: SSH login attempt — Someone attempted to connect via SSH
- **Rule 5712**: SSH brute force attack (Level 10) — Multiple failed SSH login attempts detected from the same source, indicating an automated brute force attack
- **Rule 5720**: SSH login successful after multiple failures — May indicate a successful brute force attack
- **Rule 5763**: SSH insecure connection attempt — Attempt to use an insecure SSH configuration

### File Integrity Monitoring (FIM)
- **Rule 550**: File integrity checksum changed — A monitored file was modified
- **Rule 553**: File deleted from monitored directory — A watched file was removed
- **Rule 554**: File added to monitored directory — A new file appeared in a watched location
- **Rule 550-559**: FIM rules cover file additions, modifications, deletions, and permission changes

### Windows Security
- **Rule 18100-18199**: Windows Event Log — Authentication and logon events
- **Rule 80790**: Windows audit failure — An audited operation failed
- **Rule 80784**: Windows account locked out — Too many failed login attempts
- **Rule 80791**: Windows privilege escalation — User privileges were elevated

### Intrusion Detection
- **Rule 31100-31199**: Web attack rules — SQL injection, XSS, directory traversal attempts
- **Rule 31101**: SQL injection attempt detected
- **Rule 31103**: XSS (Cross-Site Scripting) attempt detected
- **Rule 31104**: Command injection attempt
- **Rule 31105**: PHP injection attempt

### Rootkit and Malware
- **Rule 510**: Host-based anomaly detection — Rootkit found through file signature
- **Rule 512**: Trojaned system file — A system binary appears to be compromised
- **Rule 515**: System audit — Process running from suspicious directory

### System Monitoring
- **Rule 502**: OS information change — The operating system details changed
- **Rule 509**: System error — A critical system error occurred
- **Rule 521**: System clock change — A modification to the system clock was detected

## Rule Groups
Rules are organized into groups for classification:
- `authentication_success` — Successful logins
- `authentication_failed` — Failed login attempts
- `bruteforce` — Brute force attack patterns
- `firewall` — Firewall allow/deny events
- `syscheck` — File integrity monitoring events
- `rootcheck` — Rootkit detection events
- `web` — Web application security events
- `syslog` — System log events
- `pci_dss` — PCI DSS compliance related
- `gdpr` — GDPR compliance related
- `hipaa` — HIPAA compliance related
