# Wazuh Architecture & Components

## Overview
Wazuh is an open-source security platform providing unified XDR (Extended Detection and Response) and SIEM (Security Information and Event Management) capabilities. It monitors endpoints, cloud workloads, and containers for threats, vulnerabilities, and compliance.

## Core Components

### Wazuh Manager (Port 55000 — API, Port 1514/1515 — Agent Communication)
The central component that:
- Receives and processes events from agents
- Runs the analysis engine (rules and decoders)
- Generates alerts when rules match
- Manages active responses (automated actions)
- Exposes the Wazuh API for management operations

Key API categories:
- `/agents` — Agent lifecycle management (add, remove, restart, upgrade)
- `/manager` — Manager configuration, logs, and status
- `/rules` and `/decoders` — Rule and decoder management
- `/syscheck` — File Integrity Monitoring (FIM)
- `/rootcheck` — Rootkit detection
- `/syscollector` — System inventory (hardware, software, processes, ports)
- `/active-response` — Execute response scripts on agents
- `/mitre` — MITRE ATT&CK mapping

### Wazuh Indexer (Port 9200 — OpenSearch-based)
The data storage and search engine that:
- Indexes all alerts and events in `wazuh-alerts-*` indices
- Provides full-text search and aggregation capabilities
- Stores historical data for compliance and forensic analysis

Common query patterns:
- Search by rule level (severity): `rule.level >= 12` for critical alerts
- Search by rule group: `rule.groups: "bruteforce"`
- Search by source IP: `data.srcip: "192.168.1.45"`
- Search by agent: `agent.name: "server-01"`
- Time-based filtering: `@timestamp >= "now-1h"`

### Wazuh Agents
Lightweight software installed on monitored endpoints that:
- Collect system logs, file changes, process lists, network connections
- Forward data to the Wazuh Manager
- Execute active response commands when triggered
- Support Windows, Linux, macOS, and other operating systems

Agent statuses:
- `active` — Connected and reporting
- `disconnected` — Lost connection to the manager
- `pending` — Registered but never connected
- `never_connected` — Registered but has never been seen

### Wazuh Dashboard (Port 443 — Web UI)
Web-based interface built on OpenSearch Dashboards that provides:
- Visual overview of security events
- Alert investigation and drilldown
- Compliance dashboards
- Agent management UI

## Key Features

### File Integrity Monitoring (FIM / Syscheck)
- Monitors specified files and directories for changes
- Detects: creation, modification, deletion, permission changes
- Computes checksums (MD5, SHA1, SHA256) for comparison
- Useful for: detecting unauthorized changes, compliance (PCI DSS 11.5)

### Vulnerability Detection
- Checks installed packages against CVE databases
- Supports: Windows, Linux, macOS
- Identifies: package name, version, CVE ID, severity (CVSS)

### Security Configuration Assessment (SCA)
- Validates system configurations against security benchmarks
- Supports: CIS benchmarks, PCI DSS, HIPAA, GDPR
- Checks: password policies, service configurations, file permissions

### Active Response
- Automated actions triggered by specific alerts
- Can: block IPs via firewall, disable users, restart services, run custom scripts
- Requires caution: can cause service disruption if misconfigured

### Log Collection & Analysis
- Collects logs from: syslog, Windows Event Log, application logs, cloud services
- Decoders parse raw logs into structured fields
- Rules match patterns to generate alerts with severity levels

## Alert Data Structure
A typical Wazuh alert contains:
- `@timestamp` — When the event occurred
- `rule.id` — The rule that triggered
- `rule.description` — Human-readable description
- `rule.level` — Severity (0-15)
- `rule.groups` — Categories (authentication_failed, bruteforce, etc.)
- `agent.id` / `agent.name` — Source endpoint
- `data.srcip` — Source IP address (if applicable)
- `data.dstuser` — Target user (if applicable)
- `full_log` — The raw log message
- `rule.mitre.id` — MITRE ATT&CK technique ID
- `rule.pci_dss` — PCI DSS requirement mapping
- `rule.gdpr` — GDPR article mapping
