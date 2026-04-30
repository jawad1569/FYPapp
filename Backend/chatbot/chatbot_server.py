"""
chatbot_server.py — WazuhBot Chat Orchestrator
Coordinates LLM (Ollama), RAG (ChromaDB), and MCP (Wazuh tools)
to provide an intelligent security assistant.

Usage:
    python chatbot_server.py
"""

import os
import sys
import json
import asyncio
import time
import traceback
from threading import Thread

from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS

import ollama
import chromadb
from chromadb.utils import embedding_functions

# ── Config ──
PORT          = int(os.environ.get("CHATBOT_PORT", 5002))
OLLAMA_MODEL  = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")
CHROMA_DIR    = os.path.join(os.path.dirname(__file__), "vectorstore")
COLLECTION    = "wazuh_knowledge"
ML_SERVICE    = os.environ.get("ML_SERVICE_URL", "http://localhost:5001")

# Max conversation history turns to send to LLM (to fit context window)
MAX_HISTORY_TURNS = 20

# ── System prompt ──
SYSTEM_PROMPT = """You are WazuhBot, an expert AI security assistant integrated with a live Wazuh SIEM/XDR deployment.

You have access to real-time Wazuh tools. When a user asks for logs, alerts, agents, or security data YOU MUST CALL THE TOOLS — do not describe what you would do, do not write pseudocode, just call them immediately.

## Available tools — call them immediately, never describe them in text
- get_offenses_in_timeframe(minutes_ago) — recent high-severity alerts
- get_bruteforce_hits(minutes_ago) — brute force detections
- get_login_failures(user, minutes_ago) — authentication failures for a user
- search_by_event_id(event_id) — alerts matching a specific Wazuh rule ID
- generate_summary_report(field) — aggregate statistics (top sources, rule groups, etc.)
- get_network_flows(minutes_ago) — raw network traffic flows from Wazuh
- run_ai_analysis(flows) — ML threat classification on flows
- raw_log_query(query) — freeform Elasticsearch/OpenSearch query for anything else
- universal_api_request(endpoint, method, params, body) — direct Wazuh Manager API call (agents, rules, etc.)

## Rules
- When user asks for logs / alerts / recent activity → call get_offenses_in_timeframe immediately
- When user asks about brute force / failed logins → call get_bruteforce_hits or get_login_failures
- When user asks about agents → call universal_api_request with endpoint="/agents"
- When user asks about a specific rule / event ID → call search_by_event_id
- When user wants a summary / stats → call generate_summary_report
- For threat questions: fetch alerts first, then call get_network_flows + run_ai_analysis
- NEVER write Python code blocks — call the tool directly
- NEVER say "I would call X" or "I'll use X" — just call it
- If a tool returns empty results, say so clearly: "No data found"

## Write actions (require YES confirmation)
Only call universal_api_request with method PUT/POST/DELETE after the user explicitly says YES, proceed, or go ahead.
For write actions: first describe what will happen and ask for confirmation.

Common remediations:
- SSH brute force → block source IP via active-response firewall-drop (MITRE T1110)
- Port scan → block scanning IP, disable unused ports (MITRE T1046)
- Malware / C2 → block C2 IP, isolate agent, run FIM + rootcheck (MITRE T1071)
- Auth failures → lock account, review PAM config (MITRE T1078)

## For conceptual / config questions
Answer from your security knowledge directly without calling tools."""

# ── Flask app ──
app = Flask(__name__)
CORS(app)

# ── Persistent event loop for MCP bridges ──
# A single event loop running in a daemon thread so asyncio subprocess pipes
# and Locks stay alive across multiple Flask request threads.
_mcp_loop = asyncio.new_event_loop()
_mcp_thread = Thread(target=_mcp_loop.run_forever, daemon=True)
_mcp_thread.start()

# ── RAG setup ──
rag_collection = None

def init_rag():
    """Initialize the RAG vector store connection."""
    global rag_collection
    try:
        if not os.path.exists(CHROMA_DIR):
            print("[WARN] Vector store not found. Run build_vectorstore.py first.")
            print(f"       Expected at: {os.path.abspath(CHROMA_DIR)}")
            return

        client = chromadb.PersistentClient(path=CHROMA_DIR)
        embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        rag_collection = client.get_collection(
            name=COLLECTION,
            embedding_function=embed_fn,
        )
        count = rag_collection.count()
        print(f"[OK] RAG loaded -- {count} chunks in vector store")
    except Exception as e:
        print(f"[WARN] RAG init failed: {e}")
        rag_collection = None


def retrieve_context(query: str, n_results: int = 5) -> str:
    """Retrieve relevant knowledge chunks for the query."""
    if not rag_collection:
        return ""

    try:
        results = rag_collection.query(
            query_texts=[query],
            n_results=n_results,
        )

        if not results["documents"] or not results["documents"][0]:
            return ""

        chunks = []
        for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
            source = meta.get("source", "unknown")
            heading = meta.get("heading", "")
            chunks.append(f"[Source: {source} | {heading}]\n{doc}")

        return "\n\n---\n\n".join(chunks)

    except Exception as e:
        print(f"[WARN] RAG retrieval error: {e}")
        return ""


# ── MCP Bridge (per-user, credential-based) ──

async def get_mcp_for_request(wazuh_ip: str, wazuh_indexer_ip: str,
                              idx_user: str, idx_pass: str,
                              api_user: str = "", api_pass: str = ""):
    """
    Return (bridge, tools_for_llm) for the given credentials.
    idx_* = Indexer (port 9200), api_* = Manager API (port 55000).
    Returns (None, None) if credentials are absent or connection fails.
    """
    if not idx_user or not idx_pass:
        return None, None
    try:
        from mcp_bridge import get_bridge
        bridge = await get_bridge(wazuh_ip, wazuh_indexer_ip, idx_user, idx_pass, api_user, api_pass)
        tools  = await bridge.list_tools()
        return bridge, bridge.get_tools_for_llm(tools)
    except Exception as e:
        print(f"[WARN] MCP unavailable ({idx_user}@{wazuh_ip}): {e}")
        return None, None


async def execute_tool_call(bridge, name: str, arguments: dict) -> str:
    """Execute a tool call via the provided MCP bridge."""
    if not bridge:
        return json.dumps({"error": "MCP bridge not connected. Cannot execute Wazuh tools."})
    try:
        result        = await bridge.call_tool(name, arguments)
        content_parts = result.get("content", [])
        text_parts    = [
            p["text"] if isinstance(p, dict) and p.get("type") == "text" else str(p)
            for p in content_parts
        ]
        return "\n".join(text_parts) if text_parts else json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Tool execution failed: {str(e)}"})


def run_async(coro):
    """
    Submit a coroutine to the single persistent MCP event loop running in a
    background thread.  This avoids the 'Future attached to a different loop'
    error that occurs when asyncio.run() (each Flask thread) creates throwaway
    event loops while the cached MCPBridge pipes are tied to the original loop.
    """
    future = asyncio.run_coroutine_threadsafe(coro, _mcp_loop)
    return future.result(timeout=90)


# ── Chat endpoint ──

@app.route("/health", methods=["GET"])
def health():
    """Health check — reports status of all sub-services."""
    # Check Ollama
    ollama_ok = False
    try:
        models = ollama.list()
        model_names = [m.model for m in models.models] if hasattr(models, 'models') else []
        ollama_ok = True
    except Exception as e:
        model_names = []

    return jsonify({
        "status":    "ok" if ollama_ok else "degraded",
        "ollama":    {"connected": ollama_ok, "model": OLLAMA_MODEL, "available_models": model_names},
        "rag":       {"loaded": rag_collection is not None, "collection": COLLECTION},
        "mcp":       {"note": "per-user credential bridges — connect on first chat"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


@app.route("/chat", methods=["POST"])
def chat():
    body = request.get_json(silent=True)
    if not body or "message" not in body:
        return jsonify({"error": "Request body must contain 'message'"}), 400

    user_message    = body["message"]
    history         = body.get("history", [])
    context         = body.get("context", {})
    wazuh_ip         = body.get("wazuh_ip",         "127.0.0.1")
    wazuh_indexer_ip = body.get("wazuh_indexer_ip", wazuh_ip)   # separate IP for indexer
    wazuh_idx_user   = body.get("wazuh_idx_user",   body.get("wazuh_user", ""))
    wazuh_idx_pass   = body.get("wazuh_idx_pass",   body.get("wazuh_password", ""))
    wazuh_api_user   = body.get("wazuh_api_user",   "")
    wazuh_api_pass   = body.get("wazuh_api_pass",   "")

    try:
        result = process_chat(user_message, history, context,
                              wazuh_ip, wazuh_indexer_ip,
                              wazuh_idx_user, wazuh_idx_pass,
                              wazuh_api_user, wazuh_api_pass)
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "response":   f"I encountered an error: {str(e)}. Please try again.",
            "error":      str(e),
            "tool_calls": [],
            "sources":    [],
        }), 500


def process_chat(user_message: str, history: list, context: dict,
                 wazuh_ip: str = "127.0.0.1",
                 wazuh_indexer_ip: str = "",
                 idx_user: str = "", idx_pass: str = "",
                 api_user: str = "", api_pass: str = "") -> dict:
    """
    Process a chat message through the RAG + LLM + MCP pipeline.
    idx_* = Indexer credentials (port 9200), api_* = Manager API credentials (port 55000).
    """
    tool_calls_made = []
    rag_sources     = []

    effective_indexer_ip = wazuh_indexer_ip or wazuh_ip
    # 1. Get per-user MCP bridge
    bridge, mcp_tools = run_async(get_mcp_for_request(wazuh_ip, effective_indexer_ip, idx_user, idx_pass, api_user, api_pass))
    if mcp_tools:
        print(f"[MCP] {len(mcp_tools)} tools available: {[t['function']['name'] for t in mcp_tools]}")
    else:
        print(f"[MCP] No tools — bridge={bridge is not None}, idx_user={repr(idx_user)}, wazuh_ip={wazuh_ip}")

    # 2. Retrieve relevant knowledge via RAG
    rag_context = retrieve_context(user_message)
    if rag_context:
        rag_sources = list(set(
            meta.split("|")[0].replace("[Source:", "").strip()
            for meta in rag_context.split("---")
            if "[Source:" in meta
        ))

    # 3. Build messages for the LLM
    messages = _build_messages(user_message, history, rag_context, context)

    # 4. Agentic tool-call loop
    max_tool_rounds = 5
    final_response  = ""

    for round_num in range(max_tool_rounds + 1):
        call_kwargs = {"model": OLLAMA_MODEL, "messages": messages}
        if mcp_tools and round_num < max_tool_rounds:
            call_kwargs["tools"] = mcp_tools

        try:
            response = ollama.chat(**call_kwargs)
        except Exception as e:
            error_msg = str(e)
            if "model" in error_msg.lower() and "not found" in error_msg.lower():
                return {
                    "response":   f"⚠️ The LLM model `{OLLAMA_MODEL}` is not installed. Please run:\n```\nollama pull {OLLAMA_MODEL}\n```\nThen restart the chatbot service.",
                    "tool_calls": [],
                    "sources":    rag_sources,
                    "error":      error_msg,
                }
            raise

        msg = response.message

        if msg.tool_calls:
            messages.append({
                "role":    "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {"function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in msg.tool_calls
                ],
            })

            for tc in msg.tool_calls:
                tool_name = tc.function.name
                tool_args = tc.function.arguments
                if isinstance(tool_args, str):
                    try:
                        tool_args = json.loads(tool_args)
                    except json.JSONDecodeError:
                        tool_args = {}

                print(f"  [TOOL] {tool_name}({json.dumps(tool_args)})")
                tool_result = run_async(execute_tool_call(bridge, tool_name, tool_args))

                tool_calls_made.append({
                    "tool":           tool_name,
                    "arguments":      tool_args,
                    "result_preview": tool_result[:500] if len(tool_result) > 500 else tool_result,
                })
                messages.append({"role": "tool", "content": tool_result})

            continue
        else:
            final_response = msg.content or ""
            break

    return {
        "response":   final_response,
        "tool_calls": tool_calls_made,
        "sources":    rag_sources,
    }


def _build_messages(user_message: str, history: list, rag_context: str, context: dict) -> list:
    """Build the messages array for the LLM call."""
    messages = []

    # System prompt
    system_content = SYSTEM_PROMPT

    # Add RAG context if available
    if rag_context:
        system_content += f"\n\n--- RELEVANT KNOWLEDGE ---\n{rag_context}\n--- END KNOWLEDGE ---"

    # Add ML prediction context if provided
    if context.get("ml_prediction"):
        pred = context["ml_prediction"]
        system_content += f"\n\n--- CURRENT ML PREDICTION ---\n"
        system_content += f"The ML model has classified network traffic as:\n"
        system_content += f"Prediction: {pred.get('prediction', 'Unknown')}\n"
        system_content += f"Confidence: {pred.get('confidence', 'N/A')}\n"
        system_content += f"Is Threat: {pred.get('is_threat', 'N/A')}\n"
        if pred.get("probabilities"):
            top_probs = sorted(
                pred["probabilities"].items(),
                key=lambda x: x[1], reverse=True
            )[:5]
            system_content += f"Top predictions: {json.dumps(dict(top_probs))}\n"
        system_content += "--- END ML PREDICTION ---"

    # Add sentinel/alert context if provided
    if context.get("sentinel_data"):
        system_content += f"\n\n--- CURRENT ALERT DATA ---\n"
        system_content += json.dumps(context["sentinel_data"], indent=2)
        system_content += "\n--- END ALERT DATA ---"

    messages.append({"role": "system", "content": system_content})

    # Add conversation history (limited to prevent context overflow)
    trimmed_history = history[-MAX_HISTORY_TURNS * 2:]  # keep last N turns (user + assistant pairs)
    for msg in trimmed_history:
        messages.append({
            "role": msg["role"],
            "content": msg["content"],
        })

    # Add the current user message
    messages.append({"role": "user", "content": user_message})

    return messages


# ── Startup ──

def startup():
    """Initialize all services on startup."""
    print(f"\n{'='*50}")
    print(f"  WazuhBot Chat Orchestrator")
    print(f"{'='*50}\n")

    # Init RAG
    init_rag()

    print("[OK] MCP bridges connect on first chat request (per-user credentials)")

    # Check Ollama
    try:
        models = ollama.list()
        model_names = [m.model for m in models.models] if hasattr(models, 'models') else []
        if any(OLLAMA_MODEL in m for m in model_names):
            print(f"[OK] Ollama model ready: {OLLAMA_MODEL}")
        else:
            print(f"[WARN] Model '{OLLAMA_MODEL}' not found in Ollama.")
            print(f"       Available: {model_names}")
            print(f"       Run: ollama pull {OLLAMA_MODEL}")
    except Exception as e:
        print(f"[ERROR] Ollama not reachable: {e}")
        print(f"        Install from: https://ollama.com/download")

    print(f"\n>>> Chat service starting on http://localhost:{PORT}\n")


if __name__ == "__main__":
    startup()
    app.run(host="0.0.0.0", port=PORT, debug=False)
