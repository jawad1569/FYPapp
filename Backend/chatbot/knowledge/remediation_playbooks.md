# Remediation Playbooks by Attack Type

## Brute Force Attack
**ML Class: Brute Force | Wazuh Rule Group: bruteforce**

### Indicators
- Multiple failed login attempts from a single source IP in a short timeframe
- Rule IDs: 5712 (SSH brute force), 80784 (Windows account lockout)
- Typically > 5 failed attempts within 1 minute

### Immediate Response
1. **Block the source IP** using Wazuh Active Response or firewall rules
2. **Check if any login was successful** after the failures (Rule 5720) — this indicates a compromised account
3. **Verify the target account** is not a service account or admin account

### Remediation Steps
1. Block the offending IP at the firewall level
2. If login was successful: immediately reset the compromised password, revoke active sessions
3. Enable account lockout policies (e.g., lock after 5 failed attempts)
4. Consider implementing fail2ban or Wazuh's built-in active response for automatic IP blocking
5. Enable multi-factor authentication (MFA)

### Wazuh Actions Available
- `universal_api_request(endpoint="/active-response", method="PUT", params={"agents_list": "<agent_id>"}, confirm_write=True)` — Execute active response script
- `get_login_failures(user="<username>", minutes_ago=60)` — Check recent login failures
- `get_bruteforce_hits(minutes_ago=60)` — Get all brute force detections

---

## DDoS / DoS Attack
**ML Class: DDoS, DoS**

### Indicators
- Unusually high volume of network traffic from multiple sources (DDoS) or single source (DoS)
- Significant increase in Events Per Second (EPS)
- Target services becoming unresponsive

### Immediate Response
1. Identify the target service/port
2. Enable rate limiting on the affected service
3. If single-source (DoS): block the source IP

### Remediation Steps
1. Implement rate limiting and traffic shaping
2. Configure Wazuh to alert on traffic anomalies
3. Set up upstream DDoS protection (e.g., cloud-based scrubbing)
4. Review firewall rules for unnecessary open ports
5. Consider implementing SYN cookies for TCP flood protection

### Wazuh Actions Available
- `get_firewall_events(action="deny", minutes_ago=30)` — Check blocked traffic
- `generate_summary_report(field="data.srcip", minutes_ago=30)` — Find top attacking IPs
- `get_high_data_transfer(min_bytes=1000000, minutes_ago=30)` — Detect high-volume transfers

---

## Backdoor
**ML Class: Backdoor**

### Indicators
- Outbound connections to known C2 (Command & Control) servers
- Unusual listening ports on endpoints
- Unexpected processes running on the system

### Immediate Response
1. **ISOLATE the affected endpoint** — disconnect from network immediately
2. **Preserve evidence** — do not reboot or clean yet
3. **Identify the backdoor process** — check running processes and open ports

### Remediation Steps
1. Isolate the compromised system from the network
2. Capture memory dump and disk image for forensics
3. Identify the initial infection vector (phishing email, vulnerable service, etc.)
4. Remove the backdoor and any persistence mechanisms
5. Rebuild the system from clean image if integrity is uncertain
6. Scan all systems on the same network segment for similar indicators
7. Block associated C2 IPs/domains at the firewall

### Wazuh Actions Available
- `universal_api_request(endpoint="/syscollector/<agent_id>/processes")` — List running processes
- `universal_api_request(endpoint="/syscollector/<agent_id>/ports")` — Check open ports
- `universal_api_request(endpoint="/syscheck/<agent_id>")` — Check file integrity changes

---

## Reconnaissance / Scanning
**ML Class: Reconnaissance, scanning**

### Indicators
- Port scanning activity from internal or external IPs
- Service enumeration attempts
- DNS reconnaissance queries

### Immediate Response
1. Identify the scanning source (internal vs external)
2. If external: block at firewall
3. If internal: investigate the source machine for compromise

### Remediation Steps
1. Block the scanning source IP
2. Review which ports/services were discovered
3. Disable unnecessary services on exposed systems
4. Implement network segmentation to limit scan reach
5. Set up honeypots to detect future scanning attempts

### Wazuh Actions Available
- `search_by_event_id(event_id="5710", minutes_ago=60)` — Check SSH connection attempts
- `get_firewall_events(action="deny", minutes_ago=60)` — See blocked scan probes
- `generate_summary_report(field="data.srcip", minutes_ago=60)` — Identify top scanners

---

## Ransomware
**ML Class: ransomware**

### Indicators
- Rapid file modification events across multiple directories
- File extensions changing to known ransomware patterns
- Ransom notes appearing in directories

### Immediate Response
1. **IMMEDIATELY ISOLATE** affected systems — disconnect network
2. **Do NOT pay the ransom**
3. **Preserve current state** for forensic analysis

### Remediation Steps
1. Isolate all affected systems
2. Identify patient zero and the ransomware variant
3. Check for available decryption tools (No More Ransom project)
4. Restore from clean backups after ensuring the infection vector is closed
5. Reset all credentials organization-wide
6. Implement application whitelisting

### Wazuh Actions Available
- `universal_api_request(endpoint="/syscheck/<agent_id>")` — Check mass file changes
- `get_offenses_in_timeframe(minutes_ago=30, min_severity=12)` — Get critical alerts
- `universal_api_request(endpoint="/agents/<agent_id>/restart", method="PUT", confirm_write=True)` — Restart agent after cleanup

---

## Exploits / Shellcode
**ML Class: Exploits, Shellcode**

### Indicators
- Buffer overflow patterns detected in network traffic
- Unusual payloads in HTTP requests
- Code execution attempts via known vulnerability exploits

### Immediate Response
1. Identify the targeted vulnerability (CVE if possible)
2. Check if the exploit was successful
3. Patch the vulnerable service immediately

### Remediation Steps
1. Apply security patches for the exploited vulnerability
2. If exploit was successful: treat as full compromise and investigate
3. Review and update WAF (Web Application Firewall) rules
4. Implement virtual patching if immediate patching is not possible
5. Conduct vulnerability scanning across all systems

### Wazuh Actions Available
- `universal_api_request(endpoint="/vulnerability/<agent_id>")` — Check known vulnerabilities
- `universal_api_request(endpoint="/syscollector/<agent_id>/packages")` — Check installed package versions
- `get_compliance_report(standard="pci_dss", minutes_ago=1440)` — Check compliance status

---

## Injection Attacks (SQL, XSS, Command)
**ML Class: injection, xss**

### Indicators
- SQL keywords in HTTP parameters (UNION, SELECT, DROP, etc.)
- Script tags or event handlers in user input
- Command separators (;, |, &&) in request parameters

### Immediate Response
1. Block the attacking IP
2. Check if the injection was successful (data exfiltration, defacement)
3. Review application logs for the specific request

### Remediation Steps
1. Implement parameterized queries / prepared statements
2. Enable input validation and output encoding
3. Deploy or update WAF rules
4. Review and patch the vulnerable application
5. Audit database for unauthorized changes

### Wazuh Actions Available
- `search_by_event_id(event_id="31101", minutes_ago=60)` — SQL injection attempts
- `search_by_event_id(event_id="31103", minutes_ago=60)` — XSS attempts
- `get_database_activity(minutes_ago=60)` — Check for unauthorized DB operations

---

## Man-in-the-Middle (MITM)
**ML Class: mitm**

### Indicators
- ARP spoofing detected on the network
- SSL/TLS certificate warnings
- DNS hijacking indicators

### Immediate Response
1. Identify affected network segment
2. Check for ARP spoofing or DNS poisoning
3. Warn users to avoid entering credentials

### Remediation Steps
1. Implement port security and dynamic ARP inspection on switches
2. Enforce HTTPS everywhere with HSTS
3. Deploy certificate pinning for critical applications
4. Implement DNS security (DNSSEC)
5. Use VPNs for sensitive communications

---

## Worms / Lateral Movement
**ML Class: Worms**

### Indicators
- Same exploit/malware appearing on multiple systems in rapid succession
- Unusual SMB/RPC traffic between endpoints
- Self-propagating patterns in network logs

### Immediate Response
1. Isolate the affected network segment
2. Identify patient zero
3. Block the propagation mechanism (close vulnerable ports/services)

### Remediation Steps
1. Segment the network to contain spread
2. Patch the vulnerability being exploited for propagation
3. Scan all systems in the segment for infection indicators
4. Implement network access control (NAC)
5. Disable unnecessary file sharing and remote services

### Wazuh Actions Available
- `universal_api_request(endpoint="/agents", params={"status": "active"})` — Check all active agents
- `generate_summary_report(field="agent.name", minutes_ago=60)` — See which agents have alerts
- `get_offenses_in_timeframe(minutes_ago=30, min_severity=10)` — Track spreading pattern
