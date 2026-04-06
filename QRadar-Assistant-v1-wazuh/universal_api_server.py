from mcp.server.fastmcp import FastMCP
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
import base64

# ==========================================
# WAZUH SUPERCHARGED MCP SERVER
# Combines "Universal" API access with "Specific" Log Analysis
# ==========================================

# --- Configuration ---
# Port 9200 = The Indexer (Database/Logs) - Localhost usually works here
WAZUH_INDEXER_URL = "https://127.0.0.1:9200" 
# Port 55000 = The Manager API - 127.0.0.1 is required for Docker/WSL stability
WAZUH_MANAGER_URL = "https://127.0.0.1:55000"

# Credentials - Manager API uses different credentials than Indexer
WAZUH_API_USER = "wazuh-wui"
WAZUH_API_PASS = "MyS3cr37P450r.*-"  # For Manager API (port 55000)
WAZUH_INDEXER_USER = "admin"
WAZUH_INDEXER_PASS = "SecretPassword"  # For Indexer (port 9200)

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
# Note: This requires a request body, which universal_api_request doesn't support yet.
# For body-based requests, consider extending the tool or using specific MCP tools.

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
def universal_api_request(endpoint: str, method: str = "GET", params: dict = None, confirm_write: bool = False) -> dict:
    """
    MASTER TOOL: Executes ANY Wazuh Manager API request.
    IMPORTANT: Check wazuh://api-schema resource first to verify endpoints!
    
    Args:
        endpoint (str): The API path (e.g., '/agents', '/syscheck/001/last_scan').
        method (str): GET, PUT, DELETE. (PUT/DELETE require confirm_write=True)
        params (dict): URL parameters (e.g., {'status': 'active', 'limit': 5}).
        confirm_write (bool): Must be True to execute PUT/DELETE operations.
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
    
    # === SAFETY CHECK 3: Enforce default limit to prevent JSON blast ===
    if params is None:
        params = {}
    if 'limit' not in params:
        params['limit'] = DEFAULT_LIMIT  # Prevent context window overflow
    else:
        # Cap the limit even if explicitly set
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
    
    req = urllib.request.Request(full_url, headers=headers, method=method)

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

# Add this to the very bottom
if __name__ == "__main__":
    mcp.run()