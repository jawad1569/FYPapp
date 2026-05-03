# Wazuh Active Response — Configuration and Usage Guide

Active Response is Wazuh's built-in automated threat mitigation system. It executes scripts on agents or the manager when specific alert conditions are met.

## How Active Response Works

1. An alert fires (a rule matches an event)
2. Wazuh Manager evaluates active response rules
3. If a matching rule is found, the manager sends a command to the target agent(s)
4. The agent runs the response script with the alert context (attacker IP, username, etc.)
5. The script takes action (blocks IP, disables account, etc.)
6. After the timeout, the reverse action is applied (unblock IP, re-enable account)

## Active Response Locations

- `local` — run on the agent that generated the alert
- `server` — run on the Wazuh manager itself
- `defined-agent` — run on a specific agent (by ID)
- `all` — run on every connected agent

## Built-in Active Response Scripts

### firewall-drop (Linux/macOS)
Blocks an IP address using iptables (Linux) or ipfw (macOS).
- **Use for**: Brute force, port scanning, DDoS, web attacks
- Adds `iptables -A INPUT -s <IP> -j DROP` and `iptables -A OUTPUT -d <IP> -j DROP`
- Supports timeout (auto-unblock after N seconds)
- Script path: `/var/ossec/active-response/bin/firewall-drop`

### host-deny (Linux)
Adds the attacker IP to `/etc/hosts.deny`.
- **Use for**: SSH brute force, generic authentication attacks
- Script path: `/var/ossec/active-response/bin/host-deny`

### disable-account (Linux/Windows)
Disables a user account to prevent further login after a compromise.
- **Use for**: Post-brute-force success, credential compromise
- Linux: runs `passwd -l <username>`
- Windows: runs `net user <username> /active:no`
- Script path: `/var/ossec/active-response/bin/disable-account`

### route-null (Linux)
Routes an IP address to the null interface, effectively blackholing traffic.
- **Use for**: C2 communication blocking, DDoS source blocking
- Adds `ip route add blackhole <IP>`
- Script path: `/var/ossec/active-response/bin/route-null`

### restart-wazuh
Restarts the Wazuh agent service on the affected endpoint.
- **Use for**: After configuration changes, after malware removal
- Script path: `/var/ossec/active-response/bin/restart-wazuh`

### win_route-null (Windows)
Windows equivalent of route-null using `route add <IP> mask 255.255.255.255 0.0.0.0`.
- **Use for**: Windows agents needing C2 blocking

## Configuration in ossec.conf

### Basic Active Response Configuration
Active responses are configured in `/var/ossec/etc/ossec.conf` on the Wazuh Manager.

```xml
<!-- Define the command -->
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Define when to trigger it -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>        <!-- run on agent that fired alert -->
  <rules_id>5712</rules_id>         <!-- SSH brute force rule -->
  <timeout>3600</timeout>           <!-- block for 1 hour -->
</active-response>
```

### Trigger by Rule Group
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_group>bruteforce</rules_group>  <!-- any rule in bruteforce group -->
  <timeout>1800</timeout>
</active-response>
```

### Trigger by Severity Level
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <level>10</level>    <!-- trigger on any rule level 10 or above -->
  <timeout>7200</timeout>
</active-response>
```

### Protect Specific IPs from Being Blocked (Whitelist)
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5712</rules_id>
  <timeout>3600</timeout>
  <white_list>192.168.1.0/24</white_list>   <!-- never block this subnet -->
  <white_list>10.0.0.1</white_list>          <!-- never block this IP -->
</active-response>
```

## Triggering Active Response via Wazuh API

You can manually trigger active responses through the WazuhBot MCP:

### Block an IP on All Agents
```python
universal_api_request(
  endpoint="/active-response",
  method="PUT",
  params={"agents_list": "all"},
  body={
    "command": "!firewall-drop",
    "alert": {
      "data": {"srcip": "192.168.1.45"},
      "rule": {"level": 10}
    }
  },
  confirm_write=True
)
```

### Block an IP on a Specific Agent
```python
universal_api_request(
  endpoint="/active-response",
  method="PUT",
  params={"agents_list": "001"},  # agent ID
  body={
    "command": "!firewall-drop",
    "alert": {"data": {"srcip": "10.0.0.23"}}
  },
  confirm_write=True
)
```

### Disable a Compromised Account
```python
universal_api_request(
  endpoint="/active-response",
  method="PUT",
  params={"agents_list": "002"},
  body={
    "command": "!disable-account",
    "alert": {"data": {"dstuser": "john.doe"}}
  },
  confirm_write=True
)
```

### Route C2 IP to Null (Blackhole)
```python
universal_api_request(
  endpoint="/active-response",
  method="PUT",
  params={"agents_list": "003"},
  body={
    "command": "!route-null",
    "alert": {"data": {"srcip": "172.16.0.8"}}
  },
  confirm_write=True
)
```

## Complete Active Response Configurations by Attack Type

### SSH Brute Force Response
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5712</rules_id>
  <timeout>3600</timeout>
</active-response>
```

### RDP Brute Force Response (Windows)
```xml
<active-response>
  <command>win_route-null</command>
  <location>local</location>
  <rules_id>80784</rules_id>
  <timeout>3600</timeout>
</active-response>
```

### Web Attack Response
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_group>web,attack</rules_group>
  <level>8</level>
  <timeout>1800</timeout>
</active-response>
```

### Account Disable After Compromise
```xml
<active-response>
  <command>disable-account</command>
  <location>local</location>
  <rules_id>5720</rules_id>    <!-- successful login after brute force -->
  <timeout>0</timeout>         <!-- 0 = permanent until manually re-enabled -->
</active-response>
```

### Port Scan Blocking
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100400</rules_id>  <!-- custom port scan rule -->
  <timeout>7200</timeout>
</active-response>
```

## Custom Active Response Scripts

You can create custom scripts for specialized responses.

### Script Location
Place scripts in: `/var/ossec/active-response/bin/` on each agent (or distribute via centralized config)

### Script Template (Linux bash)
```bash
#!/bin/bash
# Custom active response script
# Arguments passed by Wazuh: action add/delete, user, ip, alert_id, rule_id

LOCAL=`dirname $0`
ACTION=$1    # add or delete
USER=$2      # alert user
IP=$3        # source IP from alert

if [ "$ACTION" = "add" ]; then
    # Block the IP
    iptables -A INPUT -s "$IP" -j DROP
    logger "Custom AR: Blocked IP $IP"
elif [ "$ACTION" = "delete" ]; then
    # Unblock the IP
    iptables -D INPUT -s "$IP" -j DROP
    logger "Custom AR: Unblocked IP $IP"
fi
```

### Register Custom Script in ossec.conf
```xml
<command>
  <name>custom-block</name>
  <executable>custom-block.sh</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

## Checking Active Response Logs

Active response execution is logged on the agent at:
- **Linux**: `/var/ossec/logs/active-responses.log`
- **Windows**: `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`

Query via API:
```python
universal_api_request(endpoint="/manager/logs", params={"type": "active-response"})
```

## Stateful vs Stateless Responses

- **Stateful** (timeout > 0): Action is reversed after the timeout period (e.g., IP is unblocked after 1 hour). Uses `add`/`delete` commands.
- **Stateless** (timeout = 0): Action is permanent and must be manually reversed. Use for account disabling, permanent bans.

## Important Cautions

1. **NEVER block your own IP or management network** — use `<white_list>` for admin subnets
2. **Test active responses in a lab** before enabling in production — a misconfiguration can lock admins out
3. **Set reasonable timeouts** — short timeouts (< 30 min) may allow re-attack; very long timeouts accumulate stale blocks
4. **Monitor active-response.log** regularly to ensure responses are firing as expected
5. **Coordinate with firewall team** — Wazuh active response operates independently of perimeter firewall changes
