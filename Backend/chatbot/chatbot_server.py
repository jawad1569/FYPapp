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
SYSTEM_PROMPT = """You are WazuhBot, an expert AI security assistant for the Wazuh SIEM/XDR platform.

Your capabilities:
1. **Explain security data** — Analyze alerts, ML predictions, and log patterns. Provide clear reasoning about what threats mean, their severity, and their potential impact.
2. **Recommend actions** — Based on detected threats, suggest specific remediation steps following security best practices.
3. **Execute actions** — When the user explicitly confirms, use the available Wazuh tools to perform operations like querying alerts, restarting agents, running scans, or executing active responses.

Guidelines:
- Always explain WHY something is a threat before suggesting actions
- When presenting data from tools, summarize the key findings clearly
- For dangerous operations (DELETE, PUT, active-response), ALWAYS ask for user confirmation first
- Present remediation steps in a prioritized, actionable order
- Reference specific Wazuh rule IDs and MITRE ATT&CK techniques when relevant
- If you're unsure about something, say so rather than guessing
- Keep responses concise but thorough — bullet points for action items

When you need live data from Wazuh, use the available tools. When the user asks about a concept or best practice, use your knowledge directly.

IMPORTANT: When calling tools that modify data (PUT, DELETE, POST methods), you MUST get explicit user confirmation first. Never auto-execute write operations."""

# ── Flask app ──
app = Flask(__name__)
CORS(app)

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


# ── MCP Bridge (lazy-loaded) ──
mcp_bridge = None
mcp_tools_ollama = None
mcp_connected = False

async def init_mcp():
    """Initialize the MCP bridge connection."""
    global mcp_bridge, mcp_tools_ollama, mcp_connected
    try:
        from mcp_bridge import get_bridge
        mcp_bridge = await get_bridge()
        tools = await mcp_bridge.list_tools()
        mcp_tools_ollama = mcp_bridge.get_tools_for_llm(tools)
        mcp_connected = True
        print(f"[OK] MCP connected -- {len(tools)} tools available")
    except Exception as e:
        print(f"[WARN] MCP connection failed: {e}")
        print("       Chatbot will work without live Wazuh tool access")
        mcp_bridge = None
        mcp_tools_ollama = None
        mcp_connected = False


async def execute_tool_call(name: str, arguments: dict) -> str:
    """Execute a tool call via MCP and return the result as a string."""
    if not mcp_bridge:
        return json.dumps({"error": "MCP bridge not connected. Cannot execute Wazuh tools."})

    try:
        result = await mcp_bridge.call_tool(name, arguments)

        # Extract text content from MCP result
        content_parts = result.get("content", [])
        text_parts = []
        for part in content_parts:
            if isinstance(part, dict) and part.get("type") == "text":
                text_parts.append(part["text"])
            elif isinstance(part, str):
                text_parts.append(part)

        if text_parts:
            return "\n".join(text_parts)

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": f"Tool execution failed: {str(e)}"})


def run_async(coro):
    """Run an async coroutine from sync context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # We're inside an existing event loop, create a new thread
            result = [None]
            exception = [None]
            def run():
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                try:
                    result[0] = new_loop.run_until_complete(coro)
                except Exception as e:
                    exception[0] = e
                finally:
                    new_loop.close()
            t = Thread(target=run)
            t.start()
            t.join(timeout=60)
            if exception[0]:
                raise exception[0]
            return result[0]
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


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
        "status":        "ok" if ollama_ok else "degraded",
        "ollama":        {"connected": ollama_ok, "model": OLLAMA_MODEL, "available_models": model_names},
        "rag":           {"loaded": rag_collection is not None, "collection": COLLECTION},
        "mcp":           {"connected": mcp_connected},
        "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


@app.route("/chat", methods=["POST"])
def chat():
    """
    Main chat endpoint.

    Body JSON:
    {
        "message": "user message text",
        "history": [
            {"role": "user", "content": "..."},
            {"role": "assistant", "content": "..."}
        ],
        "context": {
            "ml_prediction": { ... },  // optional: current ML prediction to reason about
            "sentinel_data": { ... }   // optional: current sentinel/alert data
        }
    }

    Returns:
    {
        "response": "assistant message",
        "tool_calls": [ ... ],   // tools that were called
        "sources": [ ... ]       // RAG sources used
    }
    """
    body = request.get_json(silent=True)
    if not body or "message" not in body:
        return jsonify({"error": "Request body must contain 'message'"}), 400

    user_message = body["message"]
    history = body.get("history", [])
    context = body.get("context", {})

    try:
        result = process_chat(user_message, history, context)
        return jsonify(result)
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "response": f"I encountered an error: {str(e)}. Please try again.",
            "error": str(e),
            "tool_calls": [],
            "sources": [],
        }), 500


def process_chat(user_message: str, history: list, context: dict) -> dict:
    """
    Process a chat message through the RAG + LLM + MCP pipeline.
    Supports multi-turn tool calling (agentic loop).
    """
    tool_calls_made = []
    rag_sources = []

    # 1. Retrieve relevant knowledge via RAG
    rag_context = retrieve_context(user_message)
    if rag_context:
        rag_sources = list(set(
            meta.split("|")[0].replace("[Source:", "").strip()
            for meta in rag_context.split("---")
            if "[Source:" in meta
        ))

    # 2. Build the messages array for the LLM
    messages = _build_messages(user_message, history, rag_context, context)

    # 3. Call LLM (with tool definitions if MCP is available)
    max_tool_rounds = 5  # prevent infinite tool-call loops
    final_response = ""

    for round_num in range(max_tool_rounds + 1):
        # Call Ollama
        call_kwargs = {
            "model": OLLAMA_MODEL,
            "messages": messages,
        }
        if mcp_tools_ollama and round_num < max_tool_rounds:
            call_kwargs["tools"] = mcp_tools_ollama

        try:
            response = ollama.chat(**call_kwargs)
        except Exception as e:
            error_msg = str(e)
            if "model" in error_msg.lower() and "not found" in error_msg.lower():
                return {
                    "response": f"⚠️ The LLM model `{OLLAMA_MODEL}` is not installed. Please run:\n```\nollama pull {OLLAMA_MODEL}\n```\nThen restart the chatbot service.",
                    "tool_calls": [],
                    "sources": rag_sources,
                    "error": error_msg,
                }
            raise

        msg = response.message

        # Check if the LLM wants to call tools
        if msg.tool_calls:
            # Add assistant message with tool calls to history
            messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        }
                    }
                    for tc in msg.tool_calls
                ],
            })

            # Execute each tool call
            for tc in msg.tool_calls:
                tool_name = tc.function.name
                tool_args = tc.function.arguments

                # Convert arguments if they're a string
                if isinstance(tool_args, str):
                    try:
                        tool_args = json.loads(tool_args)
                    except json.JSONDecodeError:
                        tool_args = {}

                print(f"  [TOOL] {tool_name}({json.dumps(tool_args)})")

                # Execute via MCP bridge
                tool_result = run_async(execute_tool_call(tool_name, tool_args))

                tool_calls_made.append({
                    "tool": tool_name,
                    "arguments": tool_args,
                    "result_preview": tool_result[:500] if len(tool_result) > 500 else tool_result,
                })

                # Add tool result to messages
                messages.append({
                    "role": "tool",
                    "content": tool_result,
                })

            # Continue the loop — LLM will process tool results
            continue

        else:
            # No tool calls — we have the final response
            final_response = msg.content or ""
            break

    return {
        "response": final_response,
        "tool_calls": tool_calls_made,
        "sources": rag_sources,
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

    # Init MCP (async)
    try:
        run_async(init_mcp())
    except Exception as e:
        print(f"[WARN] MCP init skipped: {e}")

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
