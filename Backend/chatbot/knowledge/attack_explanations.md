# Attack Type Explanations & MITRE ATT&CK Mapping

This document provides explanations for each attack class detected by the WazuhBot ML model,
mapped to MITRE ATT&CK techniques where applicable.

## Normal Traffic (Class: Normal)
Benign network traffic with no malicious indicators. This is the baseline behavior.
No action required.

## Brute Force (Class: Brute Force)
**MITRE ATT&CK: T1110 — Brute Force**

An attacker systematically attempts all possible passwords or passphrases to gain unauthorized access.
Variants include: password spraying (T1110.003), credential stuffing (T1110.004).

**Network indicators**: High volume of connection attempts to authentication services (SSH port 22, RDP port 3389, HTTP login endpoints) from a single source IP with rapid succession.

**Risk**: High — if successful, attacker gains initial access to the system.

## DDoS (Class: DDoS)
**MITRE ATT&CK: T1498 — Network Denial of Service**

Distributed Denial of Service — multiple compromised systems flood the target with traffic to make it unavailable. Unlike DoS, the traffic comes from many sources (a botnet).

**Network indicators**: Extremely high packet rate from many different source IPs, SYN floods, UDP floods, HTTP floods targeting web services.

**Risk**: High — causes service outage, may be used as a diversion for other attacks.

## DoS (Class: DoS)
**MITRE ATT&CK: T1499 — Endpoint Denial of Service**

Denial of Service from a single source. Can exploit protocol weaknesses (SYN flood, Slowloris) or application vulnerabilities.

**Network indicators**: High traffic volume from a single IP, abnormal packet patterns, resource exhaustion on the target.

**Risk**: Medium-High — single source is easier to block but can still cause outages.

## Reconnaissance / Scanning (Class: Reconnaissance, scanning)
**MITRE ATT&CK: T1046 — Network Service Scanning, T1595 — Active Scanning**

Attacker probes the network to discover hosts, open ports, running services, and potential vulnerabilities. This is typically the first phase of an attack.

**Network indicators**: Sequential port access patterns, SYN scans (half-open connections), service version probes, multiple connection attempts to different ports on the same host.

**Risk**: Medium — not directly harmful but indicates an attacker is preparing for an attack. Should trigger increased monitoring.

## Backdoor (Class: Backdoor)
**MITRE ATT&CK: T1059 — Command and Scripting Interpreter, T1071 — Application Layer Protocol**

Malware that creates a persistent hidden access point for an attacker. Often communicates with a Command & Control (C2) server for instructions.

**Network indicators**: Persistent outbound connections to unusual external IPs, encrypted traffic on non-standard ports, beaconing patterns (regular check-ins at fixed intervals).

**Risk**: Critical — indicates an already compromised system with active attacker access.

## Bot (Class: Bot)
**MITRE ATT&CK: T1584 — Compromise Infrastructure**

The system has been enrolled in a botnet — a network of compromised computers controlled by an attacker. Used for DDoS attacks, spam, cryptocurrency mining, or further attacks.

**Network indicators**: C2 communication patterns, IRC/HTTP-based control traffic, participation in coordinated attacks.

**Risk**: Critical — the system is actively controlled by an attacker.

## Exploits (Class: Exploits)
**MITRE ATT&CK: T1190 — Exploit Public-Facing Application, T1203 — Exploitation for Client Execution**

Exploitation of known software vulnerabilities to execute unauthorized code. Can target: web applications, operating system services, client applications.

**Network indicators**: Payloads matching known CVE exploit patterns, buffer overflow attempts, format string attacks, deserialization attacks.

**Risk**: Critical — successful exploitation leads to code execution on the target.

## Shellcode (Class: Shellcode)
**MITRE ATT&CK: T1059 — Command and Scripting Interpreter**

Machine code used as the payload in an exploit. Typically provides the attacker with a command shell on the target system. Often delivered through buffer overflow vulnerabilities.

**Network indicators**: NOP sleds (0x90 byte sequences), encoded shellcode patterns in network payloads, reverse shell connection attempts.

**Risk**: Critical — indicates active code execution attempt.

## Injection (Class: injection)
**MITRE ATT&CK: T1190 — Exploit Public-Facing Application**

Injection attacks insert malicious data into application inputs that gets interpreted as code or commands. Types include: SQL injection, LDAP injection, OS command injection.

**Network indicators**: SQL keywords in HTTP parameters (UNION SELECT, DROP TABLE), command separators (;, |, &&) in inputs, encoded payloads.

**Risk**: High — can lead to data breach, data destruction, or system compromise.

## XSS — Cross-Site Scripting (Class: xss)
**MITRE ATT&CK: T1189 — Drive-by Compromise**

Attacker injects malicious scripts into web pages viewed by other users. Types: Reflected XSS, Stored XSS, DOM-based XSS.

**Network indicators**: Script tags (<script>), event handlers (onerror, onload) in HTTP parameters or response bodies, encoded JavaScript payloads.

**Risk**: Medium-High — can steal user sessions, credentials, or redirect users to malicious sites.

## Man-in-the-Middle (Class: mitm)
**MITRE ATT&CK: T1557 — Adversary-in-the-Middle**

Attacker positions themselves between two communicating parties to intercept, read, or modify traffic. Techniques include ARP spoofing, DNS spoofing, SSL stripping.

**Network indicators**: ARP anomalies, certificate errors, DNS response manipulation, unexpected network routing changes.

**Risk**: High — attacker can steal credentials, sensitive data, and modify communications.

## Ransomware (Class: ransomware)
**MITRE ATT&CK: T1486 — Data Encrypted for Impact**

Malware that encrypts victim's files and demands payment for decryption. Modern ransomware also exfiltrates data before encryption (double extortion).

**Network indicators**: Rapid file system changes, outbound data exfiltration before encryption, communication with known ransomware C2 infrastructure, Tor network traffic.

**Risk**: Critical — causes immediate operational impact, potential data loss, and financial damage.

## Password Attacks (Class: password)
**MITRE ATT&CK: T1110 — Brute Force, T1003 — OS Credential Dumping**

Attacks specifically targeting password/credential systems. Includes: dictionary attacks, hash cracking, password spraying, credential dumping from memory (Mimikatz).

**Network indicators**: Authentication traffic patterns similar to brute force but may also include NTLM hash relay, Kerberos ticket manipulation, or LDAP credential extraction.

**Risk**: High — compromised credentials provide initial access or lateral movement capability.

## Theft / Data Exfiltration (Class: Theft)
**MITRE ATT&CK: T1041 — Exfiltration Over C2 Channel, T1048 — Exfiltration Over Alternative Protocol**

Unauthorized extraction of sensitive data from the network. May use: encrypted channels, DNS tunneling, steganography, or cloud services.

**Network indicators**: Large outbound data transfers, unusual DNS query volumes, encrypted traffic to new external destinations, off-hours data transfers.

**Risk**: Critical — indicates a data breach in progress or completed.

## Fuzzers (Class: Fuzzers)
**MITRE ATT&CK: T1190 — Exploit Public-Facing Application**

Automated testing technique that sends random, malformed, or unexpected data to find vulnerabilities. While used legitimately in security testing, unauthorized fuzzing indicates attack preparation.

**Network indicators**: High volume of requests with random or malformed payloads, HTTP requests with unusual parameter values, protocol-level anomalies.

**Risk**: Medium — indicates vulnerability discovery phase; often precedes exploitation.

## Worms (Class: Worms)
**MITRE ATT&CK: T1210 — Exploitation of Remote Services**

Self-propagating malware that spreads across networks without user interaction. Exploits vulnerabilities in network services to move between systems.

**Network indicators**: Same exploit traffic appearing across multiple hosts, lateral movement patterns, SMB/RPC scanning from internal hosts.

**Risk**: Critical — self-propagating nature means rapid spread; requires immediate containment.

## Generic Attacks (Class: Generic)
Attacks that don't fit neatly into other categories or use combinations of techniques. May include: protocol-level attacks, novel attack techniques, or blended threats.

**Risk**: Variable — investigate individual alerts to determine specific threat nature.

## Analysis Traffic (Class: Analysis)
Network traffic patterns associated with security analysis tools, vulnerability scanners, or penetration testing activities. May be legitimate (authorized testing) or malicious (unauthorized scanning).

**Risk**: Low if authorized, Medium-High if unauthorized.

## Infiltration (Class: Infilteration)
**MITRE ATT&CK: T1071 — Application Layer Protocol**

Stealthy intrusion into a network using techniques like social engineering, phishing, or exploiting trusted relationships. Unlike brute force, infiltration attempts to blend in with normal traffic.

**Network indicators**: Slow and low communication patterns, data hidden in legitimate protocols, long dwell times.

**Risk**: High — difficult to detect due to stealth; may indicate advanced persistent threat (APT).
