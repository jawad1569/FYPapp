from mcp.server.fastmcp import FastMCP
import os
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
import base64

# ==========================================
# WAZUH SUPERCHARGED MCP SERVER
# Credentials and IP are injected via environment variables by mcp_bridge.py
# so each user's bridge subprocess uses their own Wazuh instance.
# ==========================================

# --- Configuration (read from env vars set by mcp_bridge.py) ---
_WAZUH_IP         = os.environ.get("WAZUH_IP",         "127.0.0.1")
_WAZUH_INDEXER_IP = os.environ.get("WAZUH_INDEXER_IP", _WAZUH_IP)  # separate IP for indexer if needed

# Manager API credentials (port 55000)
_WAZUH_API_USER = os.environ.get("WAZUH_API_USER", os.environ.get("WAZUH_USER", "wazuh-wui"))
_WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", os.environ.get("WAZUH_PASS", ""))

# Indexer credentials (port 9200)
_WAZUH_IDX_USER = os.environ.get("WAZUH_IDX_USER", os.environ.get("WAZUH_USER", "admin"))
_WAZUH_IDX_PASS = os.environ.get("WAZUH_IDX_PASS", os.environ.get("WAZUH_PASS", ""))

WAZUH_INDEXER_URL  = f"https://{_WAZUH_INDEXER_IP}:9200"
WAZUH_MANAGER_URL  = f"https://{_WAZUH_IP}:55000"
WAZUH_API_USER     = _WAZUH_API_USER
WAZUH_API_PASS     = _WAZUH_API_PASS
WAZUH_INDEXER_USER = _WAZUH_IDX_USER
WAZUH_INDEXER_PASS = _WAZUH_IDX_PASS

# --- Safety Settings (Prevent "Gotchas") ---
DEFAULT_LIMIT = 10           # Prevents JSON blast / context overflow
MAX_LIMIT = 100              # Hard cap even if user requests more
READ_ONLY_MODE = False       # Set True to block all write operations
DANGEROUS_METHODS = ["DELETE", "PUT", "POST"]  # Methods that modify data

# --- Create MCP Server ---
mcp = FastMCP("Wazuh Unified")

# --- Helper: Insecure SSL ---
def get_ssl_context():
    """Ignores self-signed certificate errors common in local Wazuh installs"""
    return ssl._create_unverified_context()


# ==========================================
# MCP RESOURCE: API CHEAT SHEET
# Prevents LLM from hallucinating endpoints
# ==========================================

@mcp.resource("wazuh://api-schema")
def get_api_schema() -> str:
    """
    A cheat sheet of the MOST IMPORTANT Wazuh API endpoints.
    READ THIS RESOURCE BEFORE calling universal_api_request to avoid 404 errors.
    Based on official Wazuh API v4.14.1 documentation.
    """
    return """
# Wazuh Manager API Quick Reference (v4.14.1)
# ALWAYS verify endpoints exist before calling!

## ===== API INFO =====
- GET /                             -> Basic API info (version, hostname)

## ===== AGENTS (Read) =====
- GET /agents                       -> List all agents
    Params: status (active|pending|never_connected|disconnected), limit, offset, sort, q
- GET /agents?status=active         -> Only active agents
- GET /agents/summary/status        -> Connection & config sync status counts
- GET /agents/summary/os            -> OS summary of agents
- GET /agents/summary               -> Full summary (status, OS, groups)
- GET /agents/outdated              -> List agents needing upgrade
- GET /agents/no_group              -> Agents without assigned group
- GET /agents/upgrade_result        -> Get upgrade task results
- GET /agents/{agent_id}/key        -> Get agent's registration key
- GET /agents/{agent_id}/config/{component}/{configuration}
    Components: agent, agentless, analysis, auth, com, csyslog, integrator, 
                logcollector, mail, monitor, request, syscheck, wazuh-db, wmodules
    Configurations: client, buffer, labels, internal, syscheck, rootcheck, localfile, etc.

## ===== AGENTS (Write - CAUTION) =====
- POST /agents                      -> Add new agent (body: {name, ip})
- PUT /agents/restart               -> Restart agents (params: agents_list)
- PUT /agents/{agent_id}/restart    -> Restart specific agent
- PUT /agents/reconnect             -> Force reconnect agents
- PUT /agents/group                 -> Assign agents to group
- PUT /agents/upgrade               -> Upgrade agents
- DELETE /agents                    -> Delete agents (REQUIRES: agents_list, status)
- DELETE /agents/{agent_id}/group   -> Remove agent from groups
- DELETE /agents/{agent_id}/group/{group_id} -> Remove from specific group

## ===== ACTIVE RESPONSE (Write - CAUTION) =====
- PUT /active-response              -> Run command on agents
    Params: agents_list (required)
    Body: { "command": "!script_name", "arguments": [], "alert": {} }

## ===== SYSCHECK / File Integrity =====
- GET /syscheck/{agent_id}          -> FIM findings for agent
    Params: file, type (file|registry_key|registry_value), hash, md5, sha1, sha256
- GET /syscheck/{agent_id}/last_scan -> Last scan start/end times
- PUT /syscheck                     -> Run FIM scan (params: agents_list)
- DELETE /syscheck/{agent_id}       -> Clear FIM results

## ===== ROOTCHECK =====
- GET /rootcheck/{agent_id}         -> Rootcheck findings
- GET /rootcheck/{agent_id}/last_scan -> Last rootcheck scan time
- PUT /rootcheck                    -> Run rootcheck scan
- DELETE /rootcheck/{agent_id}      -> Clear rootcheck results

## ===== SCA (Security Configuration Assessment) =====
- GET /sca/{agent_id}               -> SCA policies for agent
- GET /sca/{agent_id}/checks/{policy_id} -> Policy check results

## ===== SYSCOLLECTOR (System Inventory) =====
- GET /syscollector/{agent_id}/hardware   -> CPU, RAM info
- GET /syscollector/{agent_id}/os         -> OS details
- GET /syscollector/{agent_id}/packages   -> Installed packages
- GET /syscollector/{agent_id}/processes  -> Running processes
- GET /syscollector/{agent_id}/ports      -> Open ports
- GET /syscollector/{agent_id}/netaddr    -> Network addresses
- GET /syscollector/{agent_id}/netiface   -> Network interfaces
- GET /syscollector/{agent_id}/netproto   -> Network protocols
- GET /syscollector/{agent_id}/hotfixes   -> Windows hotfixes
- GET /syscollector/{agent_id}/users      -> System users
- GET /syscollector/{agent_id}/groups     -> System groups
- GET /syscollector/{agent_id}/services   -> Services
- GET /syscollector/{agent_id}/browser_extensions -> Browser extensions

## ===== GROUPS =====
- GET /groups                       -> List all groups
- GET /groups/{group_id}/agents     -> Agents in group
- GET /groups/{group_id}/configuration -> Group config (agent.conf)
- GET /groups/{group_id}/files      -> Files in group directory
- POST /groups                      -> Create group (body: {group_id})
- PUT /groups/{group_id}/configuration -> Update group config
- DELETE /groups                    -> Delete groups (params: groups_list)

## ===== MANAGER =====
- GET /manager/info                 -> Version, compilation date, path
- GET /manager/status               -> Running daemons status
- GET /manager/configuration        -> Current ossec.conf
- GET /manager/configuration/validation -> Validate config
- GET /manager/logs                 -> Manager logs (params: level, limit)
- GET /manager/logs/summary         -> Log summary by daemon
- GET /manager/stats                -> Manager statistics
- GET /manager/stats/hourly         -> Hourly stats
- GET /manager/stats/weekly         -> Weekly stats
- GET /manager/daemons/stats        -> Daemon-specific stats
- GET /manager/api/config           -> API configuration
- PUT /manager/restart              -> Restart manager

## ===== RULES & DECODERS =====
- GET /rules                        -> List rules (params: rule_ids, group, level, file)
- GET /rules/groups                 -> Rule group names
- GET /rules/files                  -> Rule files
- GET /decoders                     -> List decoders
- GET /decoders/files               -> Decoder files
- GET /decoders/parents             -> Parent decoders

## ===== MITRE ATT&CK =====
- GET /mitre/tactics                -> MITRE tactics
- GET /mitre/techniques             -> MITRE techniques  
- GET /mitre/mitigations            -> MITRE mitigations
- GET /mitre/groups                 -> MITRE threat groups
- GET /mitre/software               -> MITRE software/malware

## ===== CDB LISTS =====
- GET /lists                        -> CDB lists info
- GET /lists/files                  -> List files

## ===== CLUSTER =====
- GET /cluster/status               -> Cluster enabled/running
- GET /cluster/nodes                -> List cluster nodes
- GET /cluster/healthcheck          -> Cluster health

## ===== OVERVIEW =====
- GET /overview/agents              -> Full agents overview dashboard

## ===== EXPERIMENTAL (Multi-agent queries) =====
- GET /experimental/syscollector/hardware  -> All agents hardware
- GET /experimental/syscollector/packages  -> All agents packages
- GET /experimental/syscollector/processes -> All agents processes
- GET /experimental/syscollector/ports     -> All agents ports
- GET /experimental/syscollector/os        -> All agents OS info
- DELETE /experimental/syscheck            -> Clear FIM for multiple agents

## ===== COMMON PARAMETERS =====
- limit: Max results (default 10 in this MCP, API default 500, max 100000)
- offset: Pagination start (default 0)
- sort: +field (asc) or -field (desc)
- search: Text search
- select: Fields to return
- q: Query filter (e.g., q=status=active)
- pretty: Human-readable format (default false)
- wait_for_complete: Disable timeout (default false)

## ===== DANGEROUS OPERATIONS (Require confirm_write=True) =====
- DELETE /agents                    -> Delete agents (REQUIRES agents_list AND status)
- DELETE /groups                    -> Delete groups  
- PUT /active-response              -> Execute commands on agents
- PUT /agents/restart               -> Restart agents
- PUT /manager/restart              -> Restart manager
- DELETE /syscheck/{agent_id}       -> Clear FIM database
- DELETE /rootcheck/{agent_id}      -> Clear rootcheck database
"""


@mcp.resource("wazuh://help")
def get_help() -> str:
    """
    Quick help for using this MCP server.
    """
    return """
# Wazuh MCP Server - Quick Help (v4.14.1 Compatible)

## Two Types of Tools:

### 1. universal_api_request - Call ANY Wazuh Manager API endpoint
   - ALWAYS check wazuh://api-schema first to verify the endpoint exists!
   - Example: universal_api_request(endpoint="/agents", params={"status": "active"})
   - Example: universal_api_request(endpoint="/agents/001/config/syscheck/syscheck")
   
   Parameters:
   - endpoint (required): API path like "/agents" or "/syscheck/001"
   - method: GET (default), PUT, POST, DELETE
   - params: Query parameters as dict, e.g., {"limit": 10, "status": "active"}
   - confirm_write: Must be True for PUT/POST/DELETE operations

### 2. Specific Log Query Tools - Pre-built queries for common tasks:
   - get_offenses_in_timeframe(minutes_ago, min_severity) - High severity alerts
   - get_login_failures(user, minutes_ago) - Auth failures  
   - get_bruteforce_hits(minutes_ago) - Brute force detections
   - search_by_event_id(event_id, minutes_ago) - Search by rule ID
   - generate_summary_report(field, minutes_ago) - Top 10 aggregation
   - raw_log_query(query_body) - Custom OpenSearch DSL query

## Safety Features Built-In:
- Default limit of 10 results prevents context window overflow
- Max limit capped at 100 even if explicitly requested higher
- Write operations (DELETE, PUT, POST) require confirm_write=True
- Set READ_ONLY_MODE=True in config to block ALL write operations
- 404 errors include helpful hints about checking the API schema
- Fresh auth token generated per request (no expiry issues)

## Common Workflow Examples:

### List active agents:
universal_api_request(endpoint="/agents", params={"status": "active"})

### Get agent details:
universal_api_request(endpoint="/agents/001")

### Check FIM findings:
universal_api_request(endpoint="/syscheck/001", params={"limit": 20})

### Get manager status:
universal_api_request(endpoint="/manager/status")

### Restart an agent (WRITE - needs confirmation):
universal_api_request(
    endpoint="/agents/restart", 
    method="PUT", 
    params={"agents_list": "001"},
    confirm_write=True
)

### Run active response command (WRITE - needs confirmation):
universal_api_request(
    endpoint="/active-response",
    method="PUT",
    params={"agents_list": "001"},
    body={"command": "!firewall-drop", "arguments": ["-", "null", "192.168.1.10"], "alert": {}},
    confirm_write=True
)

## Tips:
1. Always start by checking wazuh://api-schema for valid endpoints
2. Use params={"limit": N} to control result size
3. Agent IDs are strings with leading zeros: "001", "002", etc.
4. Use q parameter for filtering: params={"q": "status=active"}
5. Sort with +/- prefix: params={"sort": "-name"} for descending
"""


# ==========================================
# PART 1: THE "UNIVERSAL" TOOL (Manager API)
# This implements the "Sideways" architecture.
# ==========================================

def get_api_token():
    """
    Gets a temporary JWT token for the Manager API.
    UPDATED: Uses POST and 127.0.0.1 to fix connection errors.
    """
    auth_str = f"{WAZUH_API_USER}:{WAZUH_API_PASS}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    
    url = f"{WAZUH_MANAGER_URL}/security/user/authenticate"
    
    # Wazuh API strictly requires Content-Type for POST requests
    headers = {
        'Authorization': f'Basic {b64_auth}',
        'Content-Type': 'application/json'
    }
    
    # Method must be POST, and data must be an empty byte string
    req = urllib.request.Request(
        url, 
        headers=headers, 
        data=b'', 
        method="POST"
    )
    
    with urllib.request.urlopen(req, context=get_ssl_context(), timeout=30) as response:
        data = json.loads(response.read().decode())
        return data['data']['token']

@mcp.tool()
def universal_api_request(endpoint: str, method: str = "GET", params: dict = None, body: dict = None, confirm_write: bool = False) -> dict:
    """
    MASTER TOOL: Executes ANY Wazuh Manager API request.
    IMPORTANT: Check wazuh://api-schema resource first to verify endpoints!

    Args:
        endpoint (str): The API path (e.g., '/agents', '/syscheck/001/last_scan').
        method (str): GET, PUT, POST, DELETE. (PUT/POST/DELETE require confirm_write=True)
        params (dict): URL parameters (e.g., {'status': 'active', 'limit': 5}).
        body (dict): JSON request body for PUT/POST requests (e.g., active response payload).
        confirm_write (bool): Must be True to execute PUT/POST/DELETE operations.
    """
    
    # === SAFETY CHECK 1: Block writes in read-only mode ===
    method = method.upper()
    if READ_ONLY_MODE and method in DANGEROUS_METHODS:
        return {
            "error": "Write operation blocked",
            "details": f"Server is in READ_ONLY_MODE. {method} requests are disabled.",
            "hint": "Contact admin to enable write operations or set READ_ONLY_MODE=False"
        }
    
    # === SAFETY CHECK 2: Require explicit confirmation for dangerous methods ===
    if method in DANGEROUS_METHODS and not confirm_write:
        return {
            "error": "Write confirmation required",
            "details": f"{method} is a dangerous operation that can modify or delete data.",
            "hint": "Set confirm_write=True to proceed. Double-check the endpoint and params!",
            "blocked_request": {"endpoint": endpoint, "method": method, "params": params}
        }
    
    # === SAFETY CHECK 3: Enforce default limit to prevent JSON blast (GET only) ===
    if params is None:
        params = {}
    if method == "GET":
        if 'limit' not in params:
            params['limit'] = DEFAULT_LIMIT
        else:
            try:
                requested_limit = int(params['limit'])
                params['limit'] = min(requested_limit, MAX_LIMIT)
            except (ValueError, TypeError):
                params['limit'] = DEFAULT_LIMIT
    
    try:
        token = get_api_token()
    except Exception as e:
        return {"error": "Failed to get auth token", "details": str(e)}
    
    # Construct URL
    full_url = f"{WAZUH_MANAGER_URL}{endpoint}"
    if params:
        # Filter out None values
        clean_params = {k: v for k, v in params.items() if v is not None}
        if clean_params:
            query_string = urllib.parse.urlencode(clean_params)
            full_url += f"?{query_string}"
        
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    encoded_body = json.dumps(body).encode() if body else None
    req = urllib.request.Request(full_url, data=encoded_body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=30) as response:
            result = json.loads(response.read().decode())
            # Add metadata about safety limits applied
            if isinstance(result, dict):
                result['_safety_info'] = {
                    'limit_applied': params.get('limit'),
                    'method': method,
                    'write_confirmed': confirm_write if method in DANGEROUS_METHODS else 'N/A'
                }
            return result
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        # Provide helpful hint for 404 errors (hallucinated endpoints)
        if e.code == 404:
            return {
                "error": f"API Error {e.code} - Endpoint not found",
                "details": error_body,
                "hint": "This endpoint may not exist in your Wazuh version. Check wazuh://api-schema for valid endpoints!"
            }
        return {"error": f"API Error {e.code}", "details": error_body}
    except Exception as e:
        return {"error": str(e)}


# ==========================================
# PART 2: THE "SPECIFIC" TOOLS (Indexer/Logs)
# These act as shortcuts for complex database queries (Port 9200)
# ==========================================

def make_indexer_request(payload):
    """
    Sends a payload to the Wazuh Indexer (OpenSearch).
    """
    url = f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search"
    
    auth_str = f"{WAZUH_INDEXER_USER}:{WAZUH_INDEXER_PASS}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {b64_auth}'
    }

    encoded_body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=encoded_body, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=30) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            # Return aggregations if present, otherwise return hits
            if "aggregations" in data:
                return data["aggregations"]
            
            hits = data.get('hits', {}).get('hits', [])
            return [hit['_source'] for hit in hits]

    except urllib.error.HTTPError as e:
        return {"error": f"HTTP Error {e.code}", "details": e.read().decode()}
    except Exception as e:
        return {"error": str(e)}

# FastMCP handles the JSON parsing automatically if you type hint as dict
@mcp.tool()
def raw_log_query(query_body: dict) -> list:
    """
    UNIVERSAL LOG TOOL: Execute a raw OpenSearch/Elasticsearch JSON query against wazuh-alerts-*.
    Use this if the specific tools below don't cover your needs.
    Args:
        query_body (dict): The ES query DSL as a dictionary.
    """
    return make_indexer_request(query_body)

# --- Specific Shortcuts (QRadar Parity) ---

@mcp.tool()
def get_offenses_in_timeframe(minutes_ago: int, min_severity: int = 12) -> list:
    """Gets high-severity alerts (Offenses) within a timeframe."""
    payload = {
        "size": 20,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"rule.level": {"gte": min_severity}}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}}
                ]
            }
        },
        "_source": ["@timestamp", "rule.level", "rule.description", "agent.name", "data.srcip"]
    }
    return make_indexer_request(payload)

@mcp.tool()
def search_by_event_id(event_id: str, minutes_ago: int = 60) -> list:
    """Searches for a specific Wazuh Rule ID (Event ID)."""
    payload = {
        "size": 20,
        "query": {
            "bool": {
                "must": [
                    {"match": {"rule.id": event_id}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}}
                ]
            }
        },
        "_source": ["@timestamp", "rule.description", "full_log"]
    }
    return make_indexer_request(payload)

@mcp.tool()
def get_login_failures(user: str = None, minutes_ago: int = 60) -> list:
    """Fetches authentication failure events."""
    must_conditions = [
        {"match": {"rule.groups": "authentication_failed"}},
        {"range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}}
    ]
    if user:
        must_conditions.append({
            "multi_match": {
                "query": user,
                "fields": ["data.dstuser", "data.win.eventdata.targetUserName"]
            }
        })

    payload = {
        "size": 20,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"must": must_conditions}},
        "_source": ["@timestamp", "data.dstuser", "data.srcip", "rule.description"]
    }
    return make_indexer_request(payload)

@mcp.tool()
def get_bruteforce_hits(minutes_ago: int = 60) -> list:
    """Fetches detected brute force attacks."""
    payload = {
        "size": 20,
        "sort": [{"@timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [
                    {"match": {"rule.groups": "bruteforce"}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}}
                ]
            }
        },
        "_source": ["@timestamp", "data.srcip", "data.dstuser", "rule.description", "full_log"]
    }
    return make_indexer_request(payload)

@mcp.tool()
def generate_summary_report(field: str, minutes_ago: int = 60) -> dict:
    """Generates a statistical summary (Top X) for any field."""
    payload = {
        "size": 0,
        "query": {
            "range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}
        },
        "aggs": {
            "summary_report": {
                "terms": {
                    "field": field,
                    "size": 10
                }
            }
        }
    }
    return make_indexer_request(payload)

# ==========================================
# Group 6: AI Threat Analysis
# ==========================================

ML_SERVICE_URL = os.environ.get("ML_SERVICE_URL", "http://localhost:5001")


def _flows_from_offense_pattern(offense_type: str) -> list:
    """Generate representative network flows for a given offense type."""
    patterns = {
        "bruteforce": [
            {"IN_BYTES": 480,  "OUT_BYTES": 240, "IN_PKTS": 12, "OUT_PKTS": 12,
             "PROTOCOL": 6, "L4_DST_PORT": 22,   "L4_SRC_PORT": 54321, "DURATION": 2,  "TCP_FLAGS": 2},
            {"IN_BYTES": 560,  "OUT_BYTES": 280, "IN_PKTS": 14, "OUT_PKTS": 14,
             "PROTOCOL": 6, "L4_DST_PORT": 22,   "L4_SRC_PORT": 54322, "DURATION": 1,  "TCP_FLAGS": 2},
        ],
        "portscan": [
            {"IN_BYTES": 60,   "OUT_BYTES": 40,  "IN_PKTS": 1,  "OUT_PKTS": 1,
             "PROTOCOL": 6, "L4_DST_PORT": 443,  "L4_SRC_PORT": 55000, "DURATION": 0,  "TCP_FLAGS": 4},
            {"IN_BYTES": 60,   "OUT_BYTES": 40,  "IN_PKTS": 1,  "OUT_PKTS": 1,
             "PROTOCOL": 6, "L4_DST_PORT": 8080, "L4_SRC_PORT": 55001, "DURATION": 0,  "TCP_FLAGS": 4},
            {"IN_BYTES": 60,   "OUT_BYTES": 40,  "IN_PKTS": 1,  "OUT_PKTS": 1,
             "PROTOCOL": 6, "L4_DST_PORT": 3389, "L4_SRC_PORT": 55002, "DURATION": 0,  "TCP_FLAGS": 4},
        ],
        "c2": [
            {"IN_BYTES": 1200, "OUT_BYTES": 800, "IN_PKTS": 8,  "OUT_PKTS": 6,
             "PROTOCOL": 6, "L4_DST_PORT": 4444, "L4_SRC_PORT": 49152, "DURATION": 60, "TCP_FLAGS": 24},
            {"IN_BYTES": 1180, "OUT_BYTES": 790, "IN_PKTS": 8,  "OUT_PKTS": 6,
             "PROTOCOL": 6, "L4_DST_PORT": 4444, "L4_SRC_PORT": 49153, "DURATION": 60, "TCP_FLAGS": 24},
        ],
        "normal": [
            {"IN_BYTES": 52000,"OUT_BYTES": 3200, "IN_PKTS": 45, "OUT_PKTS": 30,
             "PROTOCOL": 6, "L4_DST_PORT": 443,  "L4_SRC_PORT": 50000, "DURATION": 5,  "TCP_FLAGS": 24},
        ],
    }
    return patterns.get(offense_type, patterns["normal"])


@mcp.tool()
def get_network_flows(minutes_ago: int = 60) -> list:
    """
    Queries the Wazuh Indexer for network-related alert data and converts it
    to ML flow format (IN_BYTES, OUT_BYTES, PROTOCOL, L4_DST_PORT, etc.).
    Call this before run_ai_analysis() to get real traffic data from Wazuh.

    Args:
        minutes_ago (int): Look-back window in minutes.

    Returns:
        List of flow dicts ready to be passed to run_ai_analysis().
    """
    payload = {
        "size": 50,
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}}],
                "should": [
                    {"exists": {"field": "data.srcip"}},
                    {"exists": {"field": "data.src_bytes"}},
                    {"match":  {"rule.groups": "network"}},
                    {"match":  {"rule.groups": "firewall"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "_source": [
            "data.srcip", "data.dstip", "data.src_bytes", "data.dst_bytes",
            "data.proto",  "data.dstport", "data.srcport", "data.duration",
            "rule.groups", "rule.description",
        ],
    }
    alerts = make_indexer_request(payload)

    flows = []
    for alert in alerts:
        if not isinstance(alert, dict) or "error" in alert:
            continue
        data = alert.get("data", {})
        flows.append({
            "IN_BYTES":    int(data.get("src_bytes", 500) or 500),
            "OUT_BYTES":   int(data.get("dst_bytes", 200) or 200),
            "IN_PKTS":     max(1, int(data.get("src_bytes", 500) or 500) // 100),
            "OUT_PKTS":    max(1, int(data.get("dst_bytes", 200) or 200) // 100),
            "PROTOCOL":    6,
            "L4_DST_PORT": int(data.get("dstport", 0) or 0),
            "L4_SRC_PORT": int(data.get("srcport", 0) or 0),
            "DURATION":    max(1, int(data.get("duration", 1) or 1)),
            "TCP_FLAGS":   0,
        })

    # If Wazuh has no raw NetFlow data, build flows from high-severity alert patterns
    if not flows:
        offense_alerts = make_indexer_request({
            "size": 20,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level":    {"gte": 10}}},
                        {"range": {"@timestamp":    {"gte": f"now-{minutes_ago}m"}}},
                    ]
                }
            },
            "_source": ["rule.groups"],
        })
        for offense in offense_alerts:
            if not isinstance(offense, dict) or "error" in offense:
                continue
            groups = " ".join(offense.get("rule", {}).get("groups", []))
            if   "bruteforce" in groups or "authentication_failed" in groups:
                flows.extend(_flows_from_offense_pattern("bruteforce"))
            elif "scan" in groups or "recon" in groups:
                flows.extend(_flows_from_offense_pattern("portscan"))
            elif "malware" in groups or "trojan" in groups:
                flows.extend(_flows_from_offense_pattern("c2"))
            else:
                flows.extend(_flows_from_offense_pattern("normal"))

    return flows[:50]  # cap to prevent ML service overload


@mcp.tool()
def run_ai_analysis(flows: list = None) -> dict:
    """
    Runs AI-powered threat classification on network flows using the local ML service.
    Returns threat predictions with confidence scores and attack type breakdown.

    WORKFLOW:
      1. Call get_network_flows() to get real Wazuh traffic data.
      2. Pass those flows here to get AI classification.
      3. Use the results to inform your threat assessment and recommendations.

    If flows is empty or None, automatically fetches flows from Wazuh first.

    Args:
        flows (list): Network flow dicts with fields IN_BYTES, OUT_BYTES, IN_PKTS,
                      OUT_PKTS, PROTOCOL, L4_DST_PORT, L4_SRC_PORT, DURATION, TCP_FLAGS.

    Returns:
        dict: { count, threat_count, normal_count, class_summary, results[] }
              Each result has: prediction, confidence, is_threat.
    """
    if not flows:
        flows = get_network_flows()

    if not flows:
        return {"error": "No network flow data available from Wazuh to analyze."}

    try:
        body = json.dumps({"logs": flows}).encode("utf-8")
        req  = urllib.request.Request(
            f"{ML_SERVICE_URL}/batch-predict",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        return {
            "error": f"ML service unreachable: {e.reason}",
            "hint":  "Ensure the ML inference service is running on port 5001",
        }
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    mcp.run()