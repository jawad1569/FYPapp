from mcp.server.fastmcp import FastMCP
import os
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
import base64

# ==== Wazuh Indexer MCP - QRadar Feature Parity ====

# --- Configuration (injected via env vars by mcp_bridge.py) ---
_WAZUH_IP = os.environ.get("WAZUH_IP", "127.0.0.1")
WAZUH_INDEXER_URL = f"https://{_WAZUH_IP}:9200"
WAZUH_USER = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "")

# --- Create MCP Server ---
mcp = FastMCP("Wazuh QRadar Parity")

# --- Helper: Insecure SSL ---
def get_ssl_context():
    return ssl._create_unverified_context()

# --- Helper: Generic Indexer Request ---
def make_indexer_request(payload):
    """
    Sends a payload to the OpenSearch/Wazuh Indexer.
    Handles both standard 'hits' (logs) and 'aggregations' (summaries).
    """
    url = f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search"
    
    auth_str = f"{WAZUH_USER}:{WAZUH_PASS}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {b64_auth}'
    }

    encoded_body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=encoded_body, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, context=get_ssl_context()) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            # Scenario A: Aggregation Report (Summaries)
            if "aggregations" in data:
                return data["aggregations"]
            
            # Scenario B: Standard Log Search
            hits = data.get('hits', {}).get('hits', [])
            return [hit['_source'] for hit in hits]

    except urllib.error.HTTPError as e:
        return {"error": f"HTTP Error {e.code}", "details": e.read().decode()}
    except Exception as e:
        return {"error": str(e)}


# ==========================================
# Group 1: Offenses & General Security
# ==========================================

@mcp.tool()
def get_offenses_in_timeframe(minutes_ago: int, min_severity: int = 12) -> list:
    """
    Replicates 'QRadar Offenses'. Gets high-severity alerts within a timeframe.
    
    Args:
        minutes_ago (int): Look back X minutes (e.g., 60).
        min_severity (int): 12 = High, 14 = Critical.
    """
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
    """
    Searches for a specific Wazuh Rule ID (Event ID).
    
    Args:
        event_id (str): The Rule ID (e.g., '5710').
        minutes_ago (int): Timeframe in minutes.
    """
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


# ==========================================
# Group 2: Authentication & Bruteforce
# ==========================================

@mcp.tool()
def get_login_failures(user: str = None, minutes_ago: int = 60) -> list:
    """
    Fetches authentication failure events.
    """
    must_conditions = [
        {"match": {"rule.groups": "authentication_failed"}},
        {"range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}}
    ]
    
    # If a specific user is requested, add that filter
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
    """
    Fetches detected brute force attacks (Rule Group 'bruteforce' or specific IDs).
    """
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


# ==========================================
# Group 3: Network & Firewall
# ==========================================

@mcp.tool()
def get_firewall_events(action: str, minutes_ago: int = 60) -> list:
    """
    Fetches firewall 'allow' or 'deny' events in a timeframe.
    
    Args:
        action (str): Either 'allow' or 'deny'.
        minutes_ago (int): Timeframe.
    """
    # Note: 'action' field availability depends on your firewall integration.
    # We search broadly for the keyword if the field doesn't strictly exist.
    payload = {
        "size": 20,
        "query": {
            "bool": {
                "must": [
                    {"match": {"rule.groups": "firewall"}},
                    {"query_string": {"query": f"*{action}*"}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}}
                ]
            }
        },
        "_source": ["@timestamp", "data.srcip", "data.dstip", "data.dstport", "rule.description", "full_log"]
    }
    return make_indexer_request(payload)

@mcp.tool()
def get_high_data_transfer(min_bytes: int, minutes_ago: int = 60) -> list:
    """
    Searches for network events where bytes transferred exceeds a limit.
    Warning: Requires logs (like Suricata/Fortinet) to have a 'src_bytes' field parsed.
    """
    payload = {
        "size": 20,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}},
                    {"range": {"data.src_bytes": {"gte": min_bytes}}}
                ]
            }
        },
        "_source": ["@timestamp", "data.srcip", "data.src_bytes", "rule.description"]
    }
    return make_indexer_request(payload)


# ==========================================
# Group 4: Database & Compliance (RTA)
# ==========================================

@mcp.tool()
def get_database_activity(db_name: str = None, table_name: str = None, minutes_ago: int = 60) -> list:
    """
    Tracks user activities, table modifications, or queries on a database.
    
    Args:
        db_name (str): The identifier (e.g., 'RTA', 'Oracle').
        table_name (str): Filter by table name if available in logs.
    """
    must_conditions = [
        {"range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}}
    ]
    
    # Generic search for DB keywords + Specific DB Name
    query_string = "(UPDATE OR INSERT OR DELETE OR SELECT OR DROP OR ALTER)"
    if db_name:
        query_string += f" AND *{db_name}*"
    if table_name:
        query_string += f" AND *{table_name}*"

    must_conditions.append({
        "query_string": {
            "query": query_string,
            "analyze_wildcard": True
        }
    })

    payload = {
        "size": 20,
        "query": {"bool": {"must": must_conditions}},
        "_source": ["@timestamp", "rule.description", "full_log", "data.db.query"]
    }
    return make_indexer_request(payload)

@mcp.tool()
def get_compliance_report(standard: str, minutes_ago: int = 1440) -> dict:
    """
    Returns a summary report of compliance violations (PCI-DSS, GDPR, etc).
    
    Args:
        standard (str): e.g., 'pci_dss', 'gdpr', 'hipaa'.
        minutes_ago (int): Default 1 day (1440 mins).
    """
    # This uses Aggregations to create a "Report"
    payload = {
        "size": 0, # We want the report, not the logs
        "query": {
            "bool": {
                "must": [
                    {"match": {f"rule.{standard}": "*"}},
                    {"range": {"@timestamp": {"gte": f"now-{minutes_ago}m"}}}
                ]
            }
        },
        "aggs": {
            "top_violations": {
                "terms": {"field": "rule.description", "size": 5}
            },
            "affected_agents": {
                "terms": {"field": "agent.name", "size": 5}
            }
        }
    }
    return make_indexer_request(payload)


# ==========================================
# Group 5: Summaries & Reporting
# ==========================================

@mcp.tool()
def generate_summary_report(field: str, minutes_ago: int = 60) -> dict:
    """
    Generates a statistical summary (Top X) for any field.
    Replicates QRadar 'Group By' reports.
    
    Args:
        field (str): The field to group by (e.g., 'data.srcip', 'rule.description', 'agent.name').
        minutes_ago (int): Timeframe.
    """
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

# Add this to the very bottom of wazuh_server.py
if __name__ == "__main__":
    mcp.run()