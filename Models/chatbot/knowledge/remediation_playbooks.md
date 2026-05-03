# Wazuh Defense & Remediation Playbooks by Attack Type

Each playbook follows: Detect → Investigate → Contain → Eradicate → Harden.
All API calls use the MCP tools available in WazuhBot.

---

## Brute Force Attack Defense in Wazuh

**ML Class: Brute Force | MITRE: T1110 | Wazuh Rule Group: bruteforce**

### Detection Signals
- Rule 5712 (SSH brute force, Level 10) — fired when ≥8 failed logins in 60 s
- Rule 5720 — SSH login SUCCESS after failures — indicates possible compromise
- Rule 80784 — Windows account locked out (Level 8)
- Rule 18151 — Windows multiple failed login (EventID 4625)
- Alert fields: `data.srcip`, `data.dstuser`, `agent.name`

### Investigation Commands
```
get_bruteforce_hits(minutes_ago=60)          → shows all brute force alerts
get_login_failures(user="root", minutes_ago=60)  → check specific account
generate_summary_report(field="data.srcip")  → find top attacking IPs
search_by_event_id(event_id="5720")          → check for post-brute-force success
```

### Containment — Block the Attacker
```
# Block source IP via Wazuh Active Response (firewall-drop)
universal_api_request(
  endpoint="/active-response",
  method="PUT",
  params={"agents_list": "all"},
  body={"command": "!firewall-drop", "alert": {"data": {"srcip": "<ATTACKER_IP>"}}},
  confirm_write=True
)
```

### Eradication
1. If Rule 5720 triggered (successful login after brute force) — treat as compromise:
   - Force password reset for the affected user immediately
   - Revoke all active sessions for that user
   - Check `/var/log/auth.log` or Windows Security Event Log for what the attacker did post-login
2. Check for persistence mechanisms: new SSH authorized_keys, new cron jobs, new user accounts
3. Run rootcheck to find any rootkits installed:
```
universal_api_request(endpoint="/rootcheck", method="PUT", params={"agents_list": "<agent_id>"}, confirm_write=True)
```

### Wazuh Hardening to Prevent Recurrence
1. **Enable automatic active response for Rule 5712**:
   In `/var/ossec/etc/ossec.conf` add:
   ```xml
   <active-response>
     <command>firewall-drop</command>
     <location>local</location>
     <rules_id>5712</rules_id>
     <timeout>3600</timeout>
   </active-response>
   ```
2. **Increase detection sensitivity** — add custom rule to trigger at fewer attempts:
   ```xml
   <rule id="100100" level="10" frequency="3" timeframe="60">
     <if_matched_sid>5503</if_matched_sid>
     <same_source_ip/>
     <description>SSH brute force: 3 failures in 60s</description>
     <group>bruteforce,</group>
   </rule>
   ```
3. **SSH hardening on the monitored endpoint**:
   - Set `MaxAuthTries 3` in `/etc/ssh/sshd_config`
   - Disable password auth: `PasswordAuthentication no` (use keys only)
   - Change SSH port from 22 to a non-standard port
   - Add `AllowUsers` whitelist

---

## DDoS and DoS Attack Defense in Wazuh

**ML Class: DDoS, DoS | MITRE: T1498, T1499 | Wazuh Rule Group: firewall**

### Detection Signals
- Rapid spike in Events Per Second (EPS) in the Sentinel dashboard
- Wazuh firewall rules showing mass deny events from many IPs
- Rule 4151 (Firewall drop event) with high frequency from same source
- High traffic alerts from network devices sending syslog

### Investigation Commands
```
generate_summary_report(field="data.srcip", minutes_ago=15)   → top source IPs
get_offenses_in_timeframe(minutes_ago=15)                      → current high alerts
get_network_flows(minutes_ago=15)                               → traffic analysis
run_ai_analysis(flows=[...])                                    → classify traffic
```

### Containment
1. **Single-source DoS** — block the IP:
```
universal_api_request(
  endpoint="/active-response",
  method="PUT",
  params={"agents_list": "all"},
  body={"command": "!firewall-drop", "alert": {"data": {"srcip": "<SOURCE_IP>"}}},
  confirm_write=True
)
```
2. **Distributed DDoS** — block at upstream (firewall/ISP level, not individual agent)
3. Rate-limit at the firewall: `iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/min --limit-burst 100 -j ACCEPT`

### Wazuh Hardening
1. Configure Wazuh to monitor firewall logs for denial rate spikes
2. Add custom rule for DoS detection:
   ```xml
   <rule id="100200" level="12" frequency="500" timeframe="10">
     <if_matched_sid>4151</if_matched_sid>
     <description>Possible DoS: 500 firewall drops in 10 seconds</description>
     <group>dos,attack,</group>
   </rule>
   ```
3. Enable SYN cookies on Linux: `echo 1 > /proc/sys/net/ipv4/tcp_syncookies`
4. Configure Wazuh agent to monitor `/var/log/iptables.log` for traffic anomalies

---

## Backdoor and Command & Control (C2) Defense in Wazuh

**ML Class: Backdoor, Bot | MITRE: T1059, T1071, T1584**

### Detection Signals
- Wazuh FIM (syscheck) alerts — new files in `/tmp`, `/dev/shm`, unusual `/etc` changes
- Rule 510 — Rootkit found via file signature check
- Rule 512 — Trojaned system binary detected
- Rule 553/554 — unexpected file additions in system directories
- Outbound connections to unusual IPs on non-standard ports (anomaly from network logs)
- Beaconing patterns: regular small outbound connections at fixed intervals

### Investigation Commands
```
search_by_event_id(event_id="510", minutes_ago=1440)       → rootkit alerts
search_by_event_id(event_id="554", minutes_ago=360)        → new files added
universal_api_request(endpoint="/syscollector/<id>/processes")   → running processes
universal_api_request(endpoint="/syscollector/<id>/ports")       → open ports
universal_api_request(endpoint="/syscheck/<id>")                 → FIM scan results
```

### Containment — ISOLATE IMMEDIATELY
1. Isolate the agent (block network except Wazuh manager port 1514):
```
universal_api_request(
  endpoint="/active-response",
  method="PUT",
  params={"agents_list": "<agent_id>"},
  body={"command": "!route-null", "alert": {"data": {"srcip": "<C2_IP>"}}},
  confirm_write=True
)
```
2. Preserve evidence — take memory dump before touching the system
3. Block C2 IP at the firewall level

### Eradication
1. Identify persistence mechanisms:
   - Crontabs: `crontab -l` for all users
   - Startup scripts: `/etc/init.d/`, `/etc/rc.local`, systemd units
   - SSH authorized_keys for all users
   - SUID/GUID binaries: `find / -perm -4000 -type f`
2. Run full rootcheck after containment:
```
universal_api_request(endpoint="/rootcheck", method="PUT", params={"agents_list": "<agent_id>"}, confirm_write=True)
```
3. If integrity cannot be verified — rebuild from clean image

### Wazuh Hardening
1. **Enable FIM on sensitive directories** in `ossec.conf`:
   ```xml
   <syscheck>
     <directories realtime="yes" check_all="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>
     <directories realtime="yes" check_all="yes">/tmp,/var/tmp,/dev/shm</directories>
     <directories realtime="yes">/home</directories>
   </syscheck>
   ```
2. **Schedule full FIM scans every hour**:
   ```xml
   <syscheck>
     <frequency>3600</frequency>
     <scan_on_start>yes</scan_on_start>
   </syscheck>
   ```
3. **Enable rootcheck scanning**:
   ```xml
   <rootcheck>
     <frequency>3600</frequency>
     <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
     <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
   </rootcheck>
   ```
4. Block known C2 IP ranges using Wazuh CDB lists for automatic detection

---

## Ransomware Defense in Wazuh

**ML Class: ransomware | MITRE: T1486**

### Detection Signals
- Mass FIM alerts (Rule 550/553) — rapid file modifications across directories
- Rule 554 — unexpected files appearing (ransom notes: README.txt, DECRYPT.txt)
- High outbound data transfer before encryption begins (exfiltration phase)
- Wazuh ML anomaly: extremely high event rate from a single agent
- Known ransomware file extension patterns in FIM alerts

### Investigation Commands
```
search_by_event_id(event_id="550", minutes_ago=30)    → mass file modifications
search_by_event_id(event_id="554", minutes_ago=30)    → new files (ransom notes)
get_offenses_in_timeframe(minutes_ago=30)             → all recent critical alerts
universal_api_request(endpoint="/syscollector/<id>/processes")  → find encrypting process
```

### Containment — IMMEDIATE NETWORK ISOLATION
1. Immediately disconnect affected agent:
```
universal_api_request(
  endpoint="/active-response",
  method="PUT",
  params={"agents_list": "<agent_id>"},
  body={"command": "!firewall-drop", "alert": {"data": {"srcip": "0.0.0.0/0"}}},
  confirm_write=True
)
```
2. Do NOT reboot — keeps evidence in memory and may pause encryption
3. Identify the ransomware process and kill it:
```
universal_api_request(endpoint="/syscollector/<id>/processes")
```

### Eradication and Recovery
1. Identify the ransomware variant (file extension, ransom note format)
2. Check No More Ransom project (nomoreransom.org) for free decryptors
3. Restore from offline backups (verify backup integrity before restore)
4. Patch the initial access vulnerability before reconnecting
5. Reset all credentials that were accessible on the compromised machine

### Wazuh Hardening to Detect Ransomware Early
1. **FIM with real-time monitoring of backup directories**:
   ```xml
   <syscheck>
     <directories realtime="yes" report_changes="yes">/backup,/data,/home,/var/www</directories>
   </syscheck>
   ```
2. **Custom rule for mass file changes** (ransomware indicator):
   ```xml
   <rule id="100300" level="15" frequency="50" timeframe="30">
     <if_matched_sid>550</if_matched_sid>
     <same_field>agent.name</same_field>
     <description>Ransomware indicator: 50+ file modifications in 30 seconds</description>
     <group>ransomware,</group>
   </rule>
   ```
3. **Active response to isolate on ransomware rule**:
   ```xml
   <active-response>
     <command>firewall-drop</command>
     <location>local</location>
     <rules_id>100300</rules_id>
     <timeout>3600</timeout>
   </active-response>
   ```
4. Implement application whitelisting — only allow approved processes to write to sensitive directories

---

## Reconnaissance and Port Scanning Defense in Wazuh

**ML Class: Reconnaissance, scanning | MITRE: T1046, T1595**

### Detection Signals
- Rule 5710 — SSH connection attempts from unknown IP
- Wazuh firewall group rules showing sequential port access patterns
- SYN packets to many ports without established connections
- Rule 1002 — Unknown problem somewhere in the system (can indicate scanning noise)

### Investigation Commands
```
search_by_event_id(event_id="5710", minutes_ago=60)        → SSH scan attempts
generate_summary_report(field="data.srcip", minutes_ago=60)→ top scanning IPs
get_offenses_in_timeframe(minutes_ago=60)                   → correlated alerts
```

### Containment
```
# Block scanner IP
universal_api_request(
  endpoint="/active-response",
  method="PUT",
  params={"agents_list": "all"},
  body={"command": "!firewall-drop", "alert": {"data": {"srcip": "<SCANNER_IP>"}}},
  confirm_write=True
)
```

### Wazuh Hardening
1. **Custom rule to detect port scanning**:
   ```xml
   <rule id="100400" level="8" frequency="20" timeframe="30">
     <if_matched_sid>4151</if_matched_sid>
     <same_source_ip/>
     <description>Port scan: 20 denied connections in 30s from same source</description>
     <group>recon,portscan,</group>
   </rule>
   ```
2. **Enable firewall logging** and configure Wazuh to collect it:
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/log/iptables.log</location>
   </localfile>
   ```
3. **Deploy honeypot ports** — monitor connections to unused port numbers as high-confidence recon detection
4. **Network segmentation** — limit which systems can reach which ports using Wazuh SCA checks

---

## Exploit and Shellcode Defense in Wazuh

**ML Class: Exploits, Shellcode | MITRE: T1190, T1203**

### Detection Signals
- Web attack rules 31100-31199 triggering on HTTP requests
- Rule 31104 — command injection attempt
- Rule 31105 — PHP code injection
- Unusual process creation from web server processes (Apache spawning bash)
- FIM alerts on webserver directories (web shell dropped)
- Rule 510 — rootkit installed post-exploit

### Investigation Commands
```
search_by_event_id(event_id="31104", minutes_ago=120)      → command injection
search_by_event_id(event_id="554", minutes_ago=120)        → new files (web shells)
universal_api_request(endpoint="/syscollector/<id>/processes")  → unusual child processes
universal_api_request(endpoint="/vulnerability/<id>")           → known CVEs on agent
universal_api_request(endpoint="/syscollector/<id>/packages")   → package versions
```

### Containment
1. Block the attacking IP
2. If exploit was successful — take agent offline for forensics
3. Identify the exploited service and disable it temporarily:
```
universal_api_request(endpoint="/active-response", method="PUT", params={"agents_list": "<agent_id>"},
  body={"command": "!restart-service", "alert": {}}, confirm_write=True)
```

### Wazuh Hardening
1. **Enable vulnerability detection** in `ossec.conf`:
   ```xml
   <vulnerability-detection>
     <enabled>yes</enabled>
     <interval>1h</interval>
     <min_full_scan_interval>6h</min_full_scan_interval>
     <run_on_start>yes</run_on_start>
   </vulnerability-detection>
   ```
2. **Monitor web application directories with FIM**:
   ```xml
   <syscheck>
     <directories realtime="yes" check_all="yes">/var/www/html,/usr/share/nginx/html</directories>
   </syscheck>
   ```
3. **Custom rule for web shell creation** (FIM alert in webroot):
   ```xml
   <rule id="100500" level="15">
     <if_sid>554</if_sid>
     <field name="file">.php$|.asp$|.jsp$|.aspx$</field>
     <field name="path">/var/www|/usr/share/nginx</field>
     <description>Possible web shell: new PHP/ASP file in webroot</description>
     <group>webshell,exploit,</group>
   </rule>
   ```
4. Run SCA checks to identify unpatched vulnerabilities:
```
universal_api_request(endpoint="/sca/<agent_id>")
```

---

## SQL Injection and XSS Defense in Wazuh

**ML Class: injection, xss | MITRE: T1190, T1189**

### Detection Signals
- Rule 31101 — SQL injection attempt (union, select, drop in HTTP params)
- Rule 31103 — XSS attempt (script tags, event handlers in HTTP params)
- Rule 31100 — Web attack generic
- High frequency of 400/403 HTTP error codes from same source IP
- Wazuh WAF decoder logs showing malicious payloads

### Investigation Commands
```
search_by_event_id(event_id="31101", minutes_ago=120)  → SQL injection attempts
search_by_event_id(event_id="31103", minutes_ago=120)  → XSS attempts
generate_summary_report(field="data.srcip", minutes_ago=60)    → top attackers
```

### Containment
1. Block the attacking IP immediately
2. Check if injection was successful — look for unexpected database entries or data in responses
3. Verify application output for signs of compromise

### Wazuh Hardening
1. **Ensure web application log collection is enabled**:
   ```xml
   <localfile>
     <log_format>apache</log_format>
     <location>/var/log/apache2/access.log</location>
   </localfile>
   <localfile>
     <log_format>apache</log_format>
     <location>/var/log/apache2/error.log</location>
   </localfile>
   ```
2. **Custom rule for high-frequency web attacks**:
   ```xml
   <rule id="100600" level="10" frequency="10" timeframe="60">
     <if_matched_group>web</if_matched_group>
     <same_source_ip/>
     <description>Web attack: 10 attack attempts in 60s from same IP</description>
     <group>web,attack,</group>
   </rule>
   ```
3. **Active response on web attack rule**:
   ```xml
   <active-response>
     <command>firewall-drop</command>
     <location>local</location>
     <rules_group>web,attack</rules_group>
     <timeout>1800</timeout>
   </active-response>
   ```
4. Deploy ModSecurity WAF and forward logs to Wazuh for correlation

---

## Password Attack Defense in Wazuh

**ML Class: password | MITRE: T1110, T1003**

### Detection Signals
- Rule 5503 — login failed (repeated from same source)
- Rule 5712 — SSH brute force
- Rule 18151 — Windows multiple failed logons (EventID 4625)
- NTLM relay indicators in Wazuh network logs
- Kerberoasting: unusual Kerberos TGS requests in Windows event logs (EventID 4769)
- Windows credential dump: unusual access to LSASS process

### Investigation Commands
```
get_login_failures(user="administrator", minutes_ago=60)   → check admin account
get_bruteforce_hits(minutes_ago=60)                        → all brute force
search_by_event_id(event_id="18151", minutes_ago=60)      → Windows failures
```

### Containment
1. Lock targeted accounts temporarily
2. Block attacking IP
3. Force password reset for affected accounts:
```
# Disable Windows account via active response on the relevant agent
universal_api_request(
  endpoint="/active-response",
  method="PUT",
  params={"agents_list": "<windows_agent_id>"},
  body={"command": "!disable-account", "alert": {"data": {"dstuser": "<compromised_user>"}}},
  confirm_write=True
)
```

### Wazuh Hardening
1. **Windows Event Log collection for Kerberoasting detection** (EventID 4769):
   ```xml
   <localfile>
     <log_format>eventchannel</log_format>
     <location>Security</location>
     <query>Event/System[EventID=4769]</query>
   </localfile>
   ```
2. **Custom rule for LSASS access** (credential dumping detection):
   ```xml
   <rule id="100700" level="14">
     <if_sid>18102</if_sid>
     <field name="win.eventdata.targetProcessName">lsass.exe</field>
     <description>Possible credential dumping: LSASS process access</description>
     <group>credential_dumping,attack,</group>
   </rule>
   ```
3. Enable account lockout policy: lock after 5 failed attempts, 15-minute unlock
4. Deploy and enforce MFA for all accounts — especially admin and service accounts

---

## Data Theft and Exfiltration Defense in Wazuh

**ML Class: Theft | MITRE: T1041, T1048**

### Detection Signals
- Unusually large outbound transfers (high OUT_BYTES in ML analysis)
- Off-hours data transfers to external IPs
- DNS tunneling: abnormally long or high-frequency DNS queries
- FTP/HTTP uploads to external destinations
- Wazuh network anomaly alerts for unusual destination IPs
- High volume access to sensitive files in FIM

### Investigation Commands
```
get_network_flows(minutes_ago=60)                           → outbound traffic analysis
run_ai_analysis(flows=[...])                                → detect exfiltration pattern
generate_summary_report(field="data.srcip", minutes_ago=60)→ traffic source breakdown
search_by_event_id(event_id="550", minutes_ago=120)        → sensitive file access
```

### Containment
1. Block destination IP immediately
2. If DNS tunneling detected — block the suspicious domain at DNS level
3. Revoke credentials for the account performing the transfer

### Wazuh Hardening
1. **Monitor sensitive directories for read access** (FIM):
   ```xml
   <syscheck>
     <directories check_all="yes" report_changes="yes">/etc/passwd,/etc/shadow,/home,/var/lib/mysql</directories>
   </syscheck>
   ```
2. **Custom rule for mass file reads**:
   ```xml
   <rule id="100800" level="12" frequency="100" timeframe="60">
     <if_matched_sid>550</if_matched_sid>
     <same_field>agent.name</same_field>
     <description>Possible data exfiltration: 100+ sensitive file accesses in 60s</description>
     <group>exfiltration,</group>
   </rule>
   ```
3. Configure Wazuh to collect and analyze DNS logs for tunneling detection:
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/log/named.log</location>
   </localfile>
   ```

---

## Worms and Lateral Movement Defense in Wazuh

**ML Class: Worms | MITRE: T1210**

### Detection Signals
- Same alert pattern appearing across multiple agents in rapid succession
- SMB traffic from internal workstations to servers (unusual lateral scanning)
- Rule 5710 (SSH attempts) originating from internal IP addresses
- New user accounts created across multiple systems simultaneously
- FIM alerts for same file patterns appearing on multiple agents

### Investigation Commands
```
get_offenses_in_timeframe(minutes_ago=30)                     → track spreading alerts
generate_summary_report(field="agent.name", minutes_ago=30)   → which agents have alerts
universal_api_request(endpoint="/agents", params={"status": "active"})  → agent inventory
get_bruteforce_hits(minutes_ago=30)                           → lateral brute force
```

### Containment — Network Segmentation
1. Identify patient zero and isolate it
2. Block lateral movement ports (SMB 445, RDP 3389, SSH 22) between segments
3. Isolate the entire affected segment if spread is advanced

### Wazuh Hardening
1. **Enable Wazuh vulnerability detection** to identify which agents have the exploited vulnerability
2. **Custom rule for internal scanning** (internal IP performing reconnaissance):
   ```xml
   <rule id="100900" level="12" frequency="30" timeframe="60">
     <if_matched_sid>5710</if_matched_sid>
     <same_source_ip/>
     <field name="data.srcip">^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.</field>
     <description>Lateral movement: internal IP performing SSH scanning</description>
     <group>lateral_movement,worm,</group>
   </rule>
   ```
3. **Monitor SMB activity with Wazuh**:
   ```xml
   <localfile>
     <log_format>eventchannel</log_format>
     <location>Security</location>
     <query>Event/System[EventID=5140 or EventID=5145]</query>
   </localfile>
   ```
4. Implement network access control — every agent should only communicate with required hosts

---

## Man-in-the-Middle (MITM) Defense in Wazuh

**ML Class: mitm | MITRE: T1557**

### Detection Signals
- ARP spoofing detected by network monitoring agents
- SSL/TLS certificate alerts from monitored endpoints
- Unexpected ARP table changes in network logs
- DNS response anomalies (wrong IPs for known domains)

### Investigation Commands
```
get_offenses_in_timeframe(minutes_ago=60)                  → correlated MITM alerts
generate_summary_report(field="data.srcip", minutes_ago=60)→ anomalous sources
```

### Containment
1. Identify the compromised network segment
2. Remove the ARP spoofing device from the network
3. Flush ARP caches on affected systems: `arp -d` (Linux) or `arp -d *` (Windows)
4. Force re-authentication for all affected sessions

### Wazuh Hardening
1. **Collect ARP logs** via network device syslog forwarded to Wazuh
2. **Deploy Wazuh agents with network monitoring** to detect ARP anomalies:
   ```xml
   <wodle name="syscollector">
     <interval>10m</interval>
     <scan_on_start>yes</scan_on_start>
     <network>yes</network>
   </wodle>
   ```
3. Enforce HTTPS with HSTS everywhere — make SSL stripping ineffective
4. Implement 802.1X network access control on switches

---

## Fuzzing Attack Defense in Wazuh

**ML Class: Fuzzers | MITRE: T1190**

### Detection Signals
- High volume of HTTP 400/500 errors from a single source
- Malformed request payloads in web application logs
- Rule 31100 (web attack generic) with unusual request patterns
- Sudden spike in web error rate on Wazuh EPS monitoring

### Investigation Commands
```
search_by_event_id(event_id="31100", minutes_ago=60)       → web attack patterns
generate_summary_report(field="data.srcip", minutes_ago=60)→ top attacking IPs
```

### Containment
Block the fuzzing source IP:
```
universal_api_request(
  endpoint="/active-response", method="PUT",
  params={"agents_list": "all"},
  body={"command": "!firewall-drop", "alert": {"data": {"srcip": "<FUZZER_IP>"}}},
  confirm_write=True
)
```

### Wazuh Hardening
1. **Custom rule for HTTP error rate spikes**:
   ```xml
   <rule id="101000" level="10" frequency="50" timeframe="30">
     <if_matched_group>web</if_matched_group>
     <match>HTTP/1\.[01]" 4\d\d|HTTP/1\.[01]" 5\d\d</match>
     <same_source_ip/>
     <description>Possible fuzzing: 50+ HTTP error responses to same IP in 30s</description>
     <group>fuzzing,</group>
   </rule>
   ```
2. Implement request rate limiting at the web server (Nginx: `limit_req_zone`)
3. Deploy WAF rules to detect common fuzzing payloads

---

## Infiltration and APT Defense in Wazuh

**ML Class: Infilteration | MITRE: T1071**

### Detection Signals
- Low-and-slow communication patterns — Wazuh anomaly detection over long time window
- Data encoded inside legitimate protocols (DNS, HTTP) — tunneling indicators
- Unusual login times or locations in authentication logs
- Persistent connections to unusual external IPs
- Long dwell time with minimal activity then sudden data access

### Investigation Commands
```
get_offenses_in_timeframe(minutes_ago=1440)               → last 24h alerts
get_network_flows(minutes_ago=1440)                        → traffic over full day
run_ai_analysis(flows=[...])                               → classify long-term patterns
universal_api_request(endpoint="/syscollector/<id>/processes")  → persistent processes
```

### Wazuh Hardening
1. **Increase log retention** for long-dwell detection — configure Wazuh Indexer index lifecycle management
2. **Enable command monitoring** on agents to detect suspicious commands:
   ```xml
   <localfile>
     <log_format>command</log_format>
     <command>who</command>
     <frequency>300</frequency>
   </localfile>
   ```
3. **Baseline normal behavior** using Wazuh statistics module and alert on deviations
4. **Monitor DNS query volume** — DNS tunneling creates high query rates:
   ```xml
   <rule id="101100" level="10" frequency="100" timeframe="60">
     <if_matched_group>dns</if_matched_group>
     <same_source_ip/>
     <description>Possible DNS tunneling: 100+ DNS queries in 60s from same source</description>
     <group>dns_tunnel,exfiltration,</group>
   </rule>
   ```
5. Implement User and Entity Behavior Analytics (UEBA) — Wazuh can feed logs to external UEBA tools

---

## Privilege Escalation Defense in Wazuh

**MITRE: T1068, T1548**

### Detection Signals
- Rule 80791 — Windows privilege escalation event
- Sudo usage: Rule 5401/5402 — sudo command execution
- SUID/SGID binary execution from unexpected paths
- Rule 515 — process running from suspicious directory
- New entries in /etc/sudoers or SYSTEM-level changes

### Investigation Commands
```
search_by_event_id(event_id="80791", minutes_ago=60)     → Windows priv esc
search_by_event_id(event_id="5402", minutes_ago=60)      → sudo escalation
universal_api_request(endpoint="/syscollector/<id>/processes")  → check SUID processes
```

### Wazuh Hardening
1. **Monitor sudoers file changes**:
   ```xml
   <syscheck>
     <directories check_all="yes" realtime="yes">/etc/sudoers,/etc/sudoers.d</directories>
   </syscheck>
   ```
2. **Alert on new SUID binary creation**:
   ```xml
   <rule id="101200" level="14">
     <if_sid>554</if_sid>
     <field name="perm">^..s|^...s</field>
     <description>New SUID binary created — possible privilege escalation setup</description>
     <group>priv_esc,</group>
   </rule>
   ```
3. **Audit sudo usage** with Wazuh command monitoring:
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/log/sudo.log</location>
   </localfile>
   ```
