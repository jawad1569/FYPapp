# Wazuh Defense Hardening — Detection Tuning and Configuration

This guide covers how to configure Wazuh to detect threats more effectively, write custom rules, and harden your monitored environment through Wazuh's various modules.

---

## Custom Rule Writing in Wazuh

Custom rules go in `/var/ossec/etc/rules/local_rules.xml` on the manager.
Rules inherit from parent rule IDs using `<if_sid>`. Never modify built-in rules directly.

### Rule Structure
```xml
<rule id="100001" level="10" frequency="5" timeframe="120">
  <if_matched_sid>5503</if_matched_sid>   <!-- parent: login failed -->
  <same_source_ip/>                        <!-- group by same attacker IP -->
  <description>Multiple login failures from same source</description>
  <group>authentication_failed,bruteforce,</group>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

### Rule Condition Tags
- `<match>`: regex match on the log text
- `<regex>`: full regex on the decoded field
- `<field name="data.srcip">`: match a specific decoded field
- `<if_sid>`: child of a specific rule
- `<if_matched_sid>`: frequency-based child (N occurrences in timeframe)
- `<same_source_ip/>`: group events by source IP for frequency counting
- `<same_field>agent.name</same_field>`: group by any field
- `<frequency>`: number of matching events before triggering
- `<timeframe>`: window in seconds to count frequency

### Rule Level Guidelines
- Level 7-9: Medium — warrants review
- Level 10-11: High — prompt investigation needed
- Level 12-13: Critical — immediate action
- Level 14-15: Reserved for active attacks in progress

---

## SSH Attack Detection Hardening

### Detect SSH Login After Brute Force (Compromise Indicator)
```xml
<rule id="100001" level="15">
  <if_matched_sid>5712</if_matched_sid>
  <if_sid>5720</if_sid>
  <same_source_ip/>
  <description>Successful SSH login after brute force — possible compromise</description>
  <group>authentication_success,bruteforce,compromise,</group>
  <mitre><id>T1110</id></mitre>
</rule>
```

### Detect SSH Login from New Country / Unexpected IP Range
```xml
<rule id="100002" level="10">
  <if_sid>5715</if_sid>
  <not_same_source_ip/>
  <description>SSH login from new source IP</description>
  <group>authentication_success,anomaly,</group>
</rule>
```

### Wazuh Agent SSH Config Collection
Enable SSH auth log collection on Linux agents:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>    <!-- Debian/Ubuntu -->
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/secure</location>      <!-- RHEL/CentOS -->
</localfile>
```

---

## Web Application Attack Detection

### Collect Web Server Logs
```xml
<!-- Apache -->
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>

<!-- Nginx -->
<localfile>
  <log_format>nginx</log_format>
  <location>/var/log/nginx/access.log</location>
</localfile>
```

### Detect Web Shell Upload
```xml
<rule id="100010" level="15">
  <if_sid>554</if_sid>
  <field name="syscheck.path">/var/www|/usr/share/nginx|/srv/www</field>
  <field name="file">\.php$|\.asp$|\.aspx$|\.jsp$|\.phtml$|\.php5$</field>
  <description>Possible web shell uploaded to webroot</description>
  <group>webshell,exploit,attack,</group>
  <mitre><id>T1505.003</id></mitre>
</rule>
```

### Detect High HTTP Error Rate (Scanning/Fuzzing)
```xml
<rule id="100011" level="10" frequency="100" timeframe="60">
  <if_matched_group>web</if_matched_group>
  <match>HTTP/1\.[01]" [45]\d\d</match>
  <same_source_ip/>
  <description>High HTTP error rate from single IP — possible fuzzing or scanning</description>
  <group>web,fuzzing,attack,</group>
</rule>
```

### Detect Directory Traversal
```xml
<rule id="100012" level="12">
  <if_sid>31100</if_sid>
  <match>\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f</match>
  <description>Directory traversal attack detected</description>
  <group>web,attack,traversal,</group>
  <mitre><id>T1083</id></mitre>
</rule>
```

---

## File Integrity Monitoring (FIM) Best Practices

### Core System Files — Maximum Protection
```xml
<syscheck>
  <!-- Binaries — check all attributes in real-time -->
  <directories realtime="yes" check_all="yes">/bin,/sbin,/usr/bin,/usr/sbin</directories>

  <!-- Configuration files -->
  <directories realtime="yes" check_all="yes">/etc</directories>

  <!-- Suspicious temporary directories -->
  <directories realtime="yes" check_all="yes">/tmp,/var/tmp,/dev/shm</directories>

  <!-- Web application roots -->
  <directories realtime="yes" report_changes="yes">/var/www,/usr/share/nginx/html,/srv/www</directories>

  <!-- User home directories (for authorized_keys changes) -->
  <directories realtime="yes">/home,/root</directories>

  <!-- Cron directories (persistence mechanism) -->
  <directories realtime="yes">/etc/cron.d,/etc/cron.daily,/etc/cron.hourly</directories>

  <!-- Startup scripts (persistence) -->
  <directories realtime="yes">/etc/init.d,/etc/systemd/system,/lib/systemd/system</directories>

  <!-- Kernel modules -->
  <directories realtime="yes">/lib/modules</directories>

  <!-- Files to ignore -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore type="sregex">\.log$</ignore>
</syscheck>
```

### Windows FIM Configuration
```xml
<syscheck>
  <directories realtime="yes" check_all="yes">%WINDIR%\System32</directories>
  <directories realtime="yes">%WINDIR%\SysWOW64</directories>
  <directories realtime="yes">%PROGRAMFILES%</directories>
  <directories realtime="yes" check_all="yes">%WINDIR%\System32\drivers\etc</directories>

  <!-- Registry monitoring for persistence -->
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
  <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
</syscheck>
```

### Detect Registry Persistence (Windows)
```xml
<rule id="100020" level="12">
  <if_sid>750</if_sid>
  <field name="syscheck.path">Software\\Microsoft\\Windows\\CurrentVersion\\Run</field>
  <description>Registry run key modified — possible persistence mechanism</description>
  <group>persistence,registry,</group>
  <mitre><id>T1547.001</id></mitre>
</rule>
```

---

## Windows Event Log Monitoring

### Critical Windows Event IDs to Monitor
```xml
<localfile>
  <log_format>eventchannel</log_format>
  <location>Security</location>
  <query>
    Event/System[
      EventID=4624 or   <!-- Successful logon -->
      EventID=4625 or   <!-- Failed logon -->
      EventID=4648 or   <!-- Logon with explicit credentials -->
      EventID=4672 or   <!-- Special privileges assigned -->
      EventID=4698 or   <!-- Scheduled task created -->
      EventID=4702 or   <!-- Scheduled task modified -->
      EventID=4720 or   <!-- User account created -->
      EventID=4726 or   <!-- User account deleted -->
      EventID=4732 or   <!-- Member added to security group -->
      EventID=4768 or   <!-- Kerberos TGT requested -->
      EventID=4769 or   <!-- Kerberos service ticket requested (Kerberoasting) -->
      EventID=4776 or   <!-- NTLM auth attempt -->
      EventID=7045       <!-- New service installed -->
    ]
  </query>
</localfile>

<!-- PowerShell logging -->
<localfile>
  <log_format>eventchannel</log_format>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <query>Event/System[EventID=4103 or EventID=4104]</query>
</localfile>
```

### Detect Kerberoasting (EventID 4769)
```xml
<rule id="100030" level="12" frequency="10" timeframe="60">
  <if_group>windows</if_group>
  <field name="win.system.eventID">4769</field>
  <field name="win.eventdata.ticketEncryptionType">0x17|0x18</field>
  <same_field>win.eventdata.targetUserName</same_field>
  <description>Possible Kerberoasting: repeated TGS requests with RC4 encryption</description>
  <group>kerberoasting,credential_access,</group>
  <mitre><id>T1558.003</id></mitre>
</rule>
```

### Detect New Service Installation (Persistence)
```xml
<rule id="100031" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">7045</field>
  <description>New Windows service installed — possible persistence mechanism</description>
  <group>persistence,windows,</group>
  <mitre><id>T1543.003</id></mitre>
</rule>
```

### Detect PowerShell Encoded Commands (Obfuscation)
```xml
<rule id="100032" level="14">
  <if_group>windows,powershell</if_group>
  <match>-EncodedCommand|-enc |-e [A-Za-z0-9+/]{20,}</match>
  <description>PowerShell encoded command execution — possible obfuscation</description>
  <group>powershell,execution,obfuscation,</group>
  <mitre><id>T1059.001</id></mitre>
</rule>
```

---

## Vulnerability Detection Configuration

### Enable and Tune Vulnerability Scanning
```xml
<vulnerability-detection>
  <enabled>yes</enabled>
  <interval>1h</interval>
  <min_full_scan_interval>6h</min_full_scan_interval>
  <run_on_start>yes</run_on_start>
</vulnerability-detection>
```

### Query Vulnerable Agents via API
```python
# Get vulnerabilities for a specific agent
universal_api_request(endpoint="/vulnerability/<agent_id>")

# Get all critical vulnerabilities across all agents
universal_api_request(
  endpoint="/vulnerability",
  params={"severity": "Critical", "limit": 100}
)

# Get installed packages to verify patch status
universal_api_request(endpoint="/syscollector/<agent_id>/packages", params={"limit": 100})
```

### Alert on Critical CVE Detection
```xml
<rule id="100040" level="13">
  <if_sid>23501</if_sid>
  <field name="vulnerability.severity">Critical</field>
  <description>Critical CVE detected on agent $(agent.name)</description>
  <group>vulnerability,critical,</group>
</rule>
```

---

## Security Configuration Assessment (SCA)

Wazuh SCA checks system configurations against security benchmarks.

### Enable SCA
```xml
<sca>
  <enabled>yes</enabled>
  <interval>12h</interval>
  <scan_on_start>yes</scan_on_start>
  <policies>
    <policy>cis_rhel8_linux.yml</policy>        <!-- CIS Linux benchmark -->
    <policy>cis_win2019.yml</policy>             <!-- CIS Windows benchmark -->
    <policy>pci_dss.yml</policy>                 <!-- PCI DSS requirements -->
    <policy>sshd_config.yml</policy>             <!-- SSH hardening -->
  </policies>
</sca>
```

### Query SCA Results
```python
universal_api_request(endpoint="/sca/<agent_id>")
universal_api_request(endpoint="/sca/<agent_id>/checks", params={"result": "failed"})
```

---

## Centralized Agent Configuration via Groups

Wazuh allows centralized configuration for agent groups — useful for applying the same detection rules to all similar agents.

### Create Agent Group and Assign Agents
```python
# Create a group
universal_api_request(endpoint="/groups", method="POST", body={"group_id": "linux-servers"}, confirm_write=True)

# Assign agent to group
universal_api_request(endpoint="/agents/001/group/linux-servers", method="PUT", confirm_write=True)
```

### Group Configuration File (`/var/ossec/etc/shared/<group>/agent.conf`)
```xml
<agent_config>
  <!-- Applied only to agents in this group -->
  <syscheck>
    <directories realtime="yes">/etc,/bin,/usr/bin</directories>
    <frequency>3600</frequency>
  </syscheck>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
</agent_config>
```

---

## Network Traffic Analysis with Wazuh

### Collect Firewall and Network Logs
```xml
<!-- iptables -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/iptables.log</location>
</localfile>

<!-- pfSense / OPNsense via syslog -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.1.1/24</allowed-ips>
</remote>

<!-- Suricata IDS integration -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

### Detect Lateral Movement via Internal SSH
```xml
<rule id="100050" level="12" frequency="5" timeframe="60">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip/>
  <field name="data.srcip">^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[01])\.</field>
  <description>Internal host scanning SSH ports — possible lateral movement</description>
  <group>lateral_movement,bruteforce,</group>
  <mitre><id>T1021.004</id></mitre>
</rule>
```

### Detect Tor Exit Node Usage (C2 indicator)
Use Wazuh CDB (constant database) lists to match known Tor exit node IPs:
```xml
<rule id="100051" level="14">
  <if_group>firewall</if_group>
  <list field="data.srcip" lookup="address_match_key">etc/lists/tor_exit_nodes</list>
  <description>Connection from known Tor exit node</description>
  <group>tor,c2,</group>
</rule>
```

---

## Log Collection Best Practices

### Priority Log Sources to Collect
1. **Authentication logs**: `/var/log/auth.log`, `/var/log/secure`, Windows Security Event Log
2. **Web server logs**: Apache/Nginx access and error logs
3. **Database logs**: MySQL general/slow query log, PostgreSQL pg_log
4. **Firewall logs**: iptables, pf, Windows Firewall
5. **DNS logs**: BIND named.log, dnsmasq, Windows DNS debug log
6. **Sudo logs**: `/var/log/sudo.log`
7. **Audit daemon**: `/var/log/audit/audit.log` (Linux auditd)

### Linux auditd Integration (Privileged Command Monitoring)
```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

Audit rules to add in `/etc/audit/rules.d/wazuh.rules`:
```
# Privileged command monitoring
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
# File deletion monitoring
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -k file_deletion
# Network configuration changes
-w /etc/hosts -p wa -k hosts_modification
-w /etc/resolv.conf -p wa -k resolv_modification
```

---

## Wazuh Decoder Customization

Decoders parse raw log lines into structured fields that rules can match on.
Custom decoders go in `/var/ossec/etc/decoders/local_decoder.xml`.

### Example: Parse Custom Application Log
If your app logs: `2024-01-15 10:23:45 ALERT user=john action=login_fail ip=192.168.1.45`

```xml
<decoder name="custom-app">
  <prematch>ALERT user=</prematch>
  <regex>ALERT user=(\w+) action=(\w+) ip=(\d+\.\d+\.\d+\.\d+)</regex>
  <order>data.user,data.action,data.srcip</order>
</decoder>
```

Then write rules matching `data.action` and `data.srcip` just like built-in rules.

---

## Threat Intelligence Integration

### CDB Lists for Known Malicious IPs
Create `/var/ossec/etc/lists/malicious_ips`:
```
192.168.100.5:malware_c2
10.0.0.99:known_scanner
```

### Rule Using CDB List
```xml
<rule id="100060" level="15">
  <if_group>firewall,syslog</if_group>
  <list field="data.srcip" lookup="address_match_key">etc/lists/malicious_ips</list>
  <description>Connection from known malicious IP</description>
  <group>threat_intel,attack,</group>
</rule>
```

Update CDB list via API:
```python
universal_api_request(
  endpoint="/lists/files/malicious_ips",
  method="PUT",
  body={"content": "203.0.113.45:botnet_c2\n198.51.100.12:scanner"},
  confirm_write=True
)
```

---

## Wazuh Compliance Monitoring

### Map Alerts to Compliance Frameworks
Add compliance mapping to custom rules:
```xml
<rule id="100070" level="10">
  <if_sid>5503</if_sid>
  <description>Authentication failure</description>
  <group>authentication_failed,</group>
  <pci_dss>10.2.4,10.2.5</pci_dss>      <!-- PCI DSS access control logging -->
  <gdpr>IV_35.7.d</gdpr>                  <!-- GDPR security monitoring -->
  <hipaa>164.312.b</hipaa>                <!-- HIPAA audit controls -->
  <nist_800_53>AC.7,AU.14</nist_800_53>  <!-- NIST access control -->
</rule>
```

### Query Compliance Status via API
```python
# Get all failing PCI DSS SCA checks
universal_api_request(endpoint="/sca/<agent_id>/checks", params={"result": "failed", "compliance": "pci_dss"})

# Generate compliance summary
generate_summary_report(field="rule.pci_dss", minutes_ago=1440)
```

---

## Wazuh Alert Tuning — Reducing False Positives

### Suppress Noisy Alerts
Use `<if_sid>` with `<different_srcip>` or whitelist expected behavior:
```xml
<rule id="100080" level="0">
  <if_sid>5712</if_sid>
  <field name="data.srcip">10.0.0.5</field>   <!-- monitoring tool, not a threat -->
  <description>Ignore brute force alert from authorized scanner</description>
</rule>
```

### Increase Level for Critical Assets
```xml
<rule id="100081" level="15">
  <if_sid>5503</if_sid>
  <field name="agent.name">domain-controller-01</field>
  <description>Login failure on domain controller — elevated priority</description>
  <group>authentication_failed,critical_asset,</group>
</rule>
```
