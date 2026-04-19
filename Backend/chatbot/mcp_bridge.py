"""
mcp_bridge.py — MCP Client Bridge for Wazuh Tool Execution
Connects to the Wazuh MCP server (universal_api_server.py) via stdio
and exposes tool definitions + execution for the LLM orchestrator.
"""

import os
import sys
import json
import asyncio
import subprocess
from contextlib import asynccontextmanager

# ── Config ──
MCP_SERVER_SCRIPT = os.environ.get(
    "MCP_SERVER_SCRIPT",
    os.path.join(os.path.dirname(__file__), "..", "..", "QRadar-Assistant-v1-wazuh", "universal_api_server.py")
)
# Python executable — use the same venv or system python that has `mcp` installed
MCP_PYTHON = os.environ.get("MCP_PYTHON", sys.executable)


class MCPBridge:
    """
    Manages a connection to the Wazuh MCP server.
    Spawns the MCP server as a subprocess (stdio transport)
    and provides methods to list tools and call them.
    """

    def __init__(self):
        self._process = None
        self._reader = None
        self._writer = None
        self._request_id = 0
        self._tools_cache = None
        self._lock = asyncio.Lock()

    async def connect(self):
        """Spawn the MCP server subprocess and initialize the connection."""
        abs_script = os.path.abspath(MCP_SERVER_SCRIPT)
        if not os.path.exists(abs_script):
            raise FileNotFoundError(f"MCP server script not found: {abs_script}")

        self._process = await asyncio.create_subprocess_exec(
            MCP_PYTHON, abs_script,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._reader = self._process.stdout
        self._writer = self._process.stdin

        # Send initialize request (JSON-RPC over stdio)
        init_result = await self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "wazuhbot-chatbot", "version": "1.0.0"}
        })

        # Send initialized notification
        await self._send_notification("notifications/initialized", {})

        return init_result

    async def disconnect(self):
        """Cleanly shut down the MCP server subprocess."""
        if self._process and self._process.returncode is None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()

    async def list_tools(self) -> list[dict]:
        """Get the list of available tools from the MCP server."""
        if self._tools_cache:
            return self._tools_cache

        result = await self._send_request("tools/list", {})
        tools = result.get("tools", [])
        self._tools_cache = tools
        return tools

    async def call_tool(self, name: str, arguments: dict) -> dict:
        """Call a tool on the MCP server and return the result."""
        result = await self._send_request("tools/call", {
            "name": name,
            "arguments": arguments,
        })
        return result

    def get_tools_for_llm(self, tools: list[dict]) -> list[dict]:
        """
        Convert MCP tool definitions to the Ollama function-calling format.
        Returns a list suitable for the `tools` parameter of ollama.chat().
        """
        ollama_tools = []
        for tool in tools:
            func_def = {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("inputSchema", {
                        "type": "object",
                        "properties": {},
                    }),
                },
            }
            ollama_tools.append(func_def)
        return ollama_tools

    # ── Internal JSON-RPC helpers ──

    async def _send_request(self, method: str, params: dict) -> dict:
        """Send a JSON-RPC request and wait for the response."""
        async with self._lock:
            self._request_id += 1
            msg = {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": method,
                "params": params,
            }
            await self._write_message(msg)
            return await self._read_response(self._request_id)

    async def _send_notification(self, method: str, params: dict):
        """Send a JSON-RPC notification (no response expected)."""
        msg = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        await self._write_message(msg)

    async def _write_message(self, msg: dict):
        """Write a JSON-RPC message with Content-Length header."""
        body = json.dumps(msg)
        header = f"Content-Length: {len(body)}\r\n\r\n"
        self._writer.write(header.encode() + body.encode())
        await self._writer.drain()

    async def _read_response(self, request_id: int, timeout: float = 30.0) -> dict:
        """Read a JSON-RPC response for the given request ID."""
        try:
            while True:
                # Read Content-Length header
                header_line = await asyncio.wait_for(
                    self._reader.readline(), timeout=timeout
                )
                if not header_line:
                    raise ConnectionError("MCP server closed connection")

                header_str = header_line.decode().strip()
                if header_str.startswith("Content-Length:"):
                    content_length = int(header_str.split(":")[1].strip())

                    # Read empty line after header
                    await self._reader.readline()

                    # Read body
                    body = await asyncio.wait_for(
                        self._reader.readexactly(content_length), timeout=timeout
                    )
                    response = json.loads(body.decode())

                    # Check if this response matches our request
                    if response.get("id") == request_id:
                        if "error" in response:
                            raise Exception(
                                f"MCP error: {response['error'].get('message', 'Unknown')}"
                            )
                        return response.get("result", {})
                    # Otherwise, keep reading (might be a notification)

        except asyncio.TimeoutError:
            raise TimeoutError(f"MCP server did not respond within {timeout}s")


# ── Singleton management ──

_bridge_instance: MCPBridge | None = None


async def get_bridge() -> MCPBridge:
    """Get or create the global MCP bridge instance."""
    global _bridge_instance
    if _bridge_instance is None:
        _bridge_instance = MCPBridge()
        try:
            await _bridge_instance.connect()
            print("[OK] MCP Bridge connected to Wazuh server")
        except Exception as e:
            print(f"[WARN] MCP Bridge connection failed: {e}")
            print("       Chatbot will work without live Wazuh data")
            _bridge_instance = None
            raise
    return _bridge_instance


async def shutdown_bridge():
    """Shut down the global MCP bridge."""
    global _bridge_instance
    if _bridge_instance:
        await _bridge_instance.disconnect()
        _bridge_instance = None
