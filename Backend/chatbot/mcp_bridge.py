"""
mcp_bridge.py — MCP Client Bridge for Wazuh Tool Execution
Spawns the Wazuh MCP server as a subprocess (stdio JSON-RPC) with per-user
credentials injected via environment variables. Bridges are cached by
credential hash so the same user always reuses the same subprocess.
"""

import os
import sys
import json
import hashlib
import asyncio

MCP_SERVER_SCRIPT = os.environ.get(
    "MCP_SERVER_SCRIPT",
    os.path.join(os.path.dirname(__file__), "..", "..", "QRadar-Assistant-v1-wazuh", "universal_api_server.py")
)
MCP_PYTHON = os.environ.get("MCP_PYTHON", sys.executable)


class MCPBridge:
    """
    Manages one MCP server subprocess for a specific set of Wazuh credentials.
    """

    def __init__(self, wazuh_ip: str, wazuh_user: str, wazuh_pass: str):
        self._wazuh_ip   = wazuh_ip
        self._wazuh_user = wazuh_user
        self._wazuh_pass = wazuh_pass
        self._process    = None
        self._reader     = None
        self._writer     = None
        self._request_id = 0
        self._tools_cache = None
        self._lock       = asyncio.Lock()

    async def connect(self):
        abs_script = os.path.abspath(MCP_SERVER_SCRIPT)
        if not os.path.exists(abs_script):
            raise FileNotFoundError(f"MCP server script not found: {abs_script}")

        # Pass credentials and service URLs to the subprocess via environment variables
        env = os.environ.copy()
        env["WAZUH_IP"]       = self._wazuh_ip
        env["WAZUH_USER"]     = self._wazuh_user
        env["WAZUH_PASS"]     = self._wazuh_pass
        env["ML_SERVICE_URL"] = os.environ.get("ML_SERVICE_URL", "http://localhost:5001")

        self._process = await asyncio.create_subprocess_exec(
            MCP_PYTHON, abs_script,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        self._reader = self._process.stdout
        self._writer = self._process.stdin

        await self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "wazuhbot-chatbot", "version": "1.0.0"},
        })
        await self._send_notification("notifications/initialized", {})

    def is_alive(self) -> bool:
        return self._process is not None and self._process.returncode is None

    async def disconnect(self):
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

    async def list_tools(self) -> list:
        if self._tools_cache:
            return self._tools_cache
        result = await self._send_request("tools/list", {})
        self._tools_cache = result.get("tools", [])
        return self._tools_cache

    async def call_tool(self, name: str, arguments: dict) -> dict:
        return await self._send_request("tools/call", {"name": name, "arguments": arguments})

    def get_tools_for_llm(self, tools: list) -> list:
        return [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("inputSchema", {"type": "object", "properties": {}}),
                },
            }
            for tool in tools
        ]

    # ── Internal JSON-RPC helpers ──

    async def _send_request(self, method: str, params: dict) -> dict:
        async with self._lock:
            self._request_id += 1
            msg = {"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params}
            await self._write_message(msg)
            return await self._read_response(self._request_id)

    async def _send_notification(self, method: str, params: dict):
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        await self._write_message(msg)

    async def _write_message(self, msg: dict):
        body   = json.dumps(msg)
        header = f"Content-Length: {len(body)}\r\n\r\n"
        self._writer.write(header.encode() + body.encode())
        await self._writer.drain()

    async def _read_response(self, request_id: int, timeout: float = 30.0) -> dict:
        try:
            while True:
                header_line = await asyncio.wait_for(self._reader.readline(), timeout=timeout)
                if not header_line:
                    raise ConnectionError("MCP server closed connection")

                header_str = header_line.decode().strip()
                if header_str.startswith("Content-Length:"):
                    content_length = int(header_str.split(":")[1].strip())
                    await self._reader.readline()  # blank line
                    body     = await asyncio.wait_for(self._reader.readexactly(content_length), timeout=timeout)
                    response = json.loads(body.decode())

                    if response.get("id") == request_id:
                        if "error" in response:
                            raise Exception(f"MCP error: {response['error'].get('message', 'Unknown')}")
                        return response.get("result", {})
        except asyncio.TimeoutError:
            raise TimeoutError(f"MCP server did not respond within {timeout}s")


# ── Bridge cache: keyed by MD5 of (ip, user, pass) ──

_bridges: dict = {}


def _cache_key(wazuh_ip: str, wazuh_user: str, wazuh_pass: str) -> str:
    return hashlib.md5(f"{wazuh_ip}:{wazuh_user}:{wazuh_pass}".encode()).hexdigest()


async def get_bridge(wazuh_ip: str, wazuh_user: str, wazuh_pass: str) -> MCPBridge:
    """
    Return a live MCPBridge for these credentials, creating one if needed.
    If the cached subprocess has died, it is replaced automatically.
    """
    key = _cache_key(wazuh_ip, wazuh_user, wazuh_pass)

    if key in _bridges and _bridges[key].is_alive():
        return _bridges[key]

    # Remove stale entry if any
    if key in _bridges:
        await _bridges[key].disconnect()
        del _bridges[key]

    bridge = MCPBridge(wazuh_ip=wazuh_ip, wazuh_user=wazuh_user, wazuh_pass=wazuh_pass)
    await bridge.connect()
    _bridges[key] = bridge
    print(f"[MCP] New bridge connected for {wazuh_user}@{wazuh_ip}")
    return bridge


async def shutdown_all():
    for bridge in list(_bridges.values()):
        await bridge.disconnect()
    _bridges.clear()
