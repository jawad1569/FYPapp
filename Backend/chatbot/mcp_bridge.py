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
    Carries separate credentials for the Indexer (port 9200) and Manager API (port 55000).
    """

    def __init__(self, wazuh_ip: str, indexer_ip: str = "",
                 idx_user: str = "", idx_pass: str = "",
                 api_user: str = "", api_pass: str = ""):
        self._wazuh_ip    = wazuh_ip
        self._indexer_ip  = indexer_ip or wazuh_ip
        self._idx_user    = idx_user
        self._idx_pass    = idx_pass
        self._api_user    = api_user
        self._api_pass    = api_pass
        self._process     = None
        self._reader      = None
        self._writer      = None
        self._request_id  = 0
        self._tools_cache = None
        self._lock        = asyncio.Lock()

    async def connect(self):
        abs_script = os.path.abspath(MCP_SERVER_SCRIPT)
        if not os.path.exists(abs_script):
            raise FileNotFoundError(f"MCP server script not found: {abs_script}")

        env = os.environ.copy()
        env["WAZUH_IP"]         = self._wazuh_ip
        env["WAZUH_INDEXER_IP"] = self._indexer_ip
        # Indexer (port 9200)
        env["WAZUH_IDX_USER"] = self._idx_user
        env["WAZUH_IDX_PASS"] = self._idx_pass
        # Manager API (port 55000)
        env["WAZUH_API_USER"] = self._api_user
        env["WAZUH_API_PASS"] = self._api_pass
        # Legacy fallback — some tools may still read WAZUH_USER/WAZUH_PASS
        env["WAZUH_USER"]     = self._idx_user
        env["WAZUH_PASS"]     = self._idx_pass
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


def _cache_key(wazuh_ip: str, idx_user: str, idx_pass: str, api_user: str, api_pass: str) -> str:
    return hashlib.md5(f"{wazuh_ip}:{idx_user}:{idx_pass}:{api_user}:{api_pass}".encode()).hexdigest()


async def get_bridge(wazuh_ip: str, wazuh_indexer_ip: str = "",
                     idx_user: str = "", idx_pass: str = "",
                     api_user: str = "", api_pass: str = "") -> MCPBridge:
    """
    Return a live MCPBridge for these credentials, creating one if needed.
    idx_*  = Wazuh Indexer (port 9200) credentials  — e.g. admin
    api_*  = Wazuh Manager API (port 55000) creds   — e.g. wazuh-wui
    Falls back to idx creds for the API if api_user is not provided.
    """
    effective_indexer_ip = wazuh_indexer_ip or wazuh_ip
    effective_api_user   = api_user or idx_user
    effective_api_pass   = api_pass or idx_pass

    key = _cache_key(wazuh_ip, idx_user, idx_pass, effective_api_user, effective_api_pass)

    if key in _bridges and _bridges[key].is_alive():
        return _bridges[key]

    if key in _bridges:
        await _bridges[key].disconnect()
        del _bridges[key]

    bridge = MCPBridge(
        wazuh_ip=wazuh_ip, indexer_ip=effective_indexer_ip,
        idx_user=idx_user, idx_pass=idx_pass,
        api_user=effective_api_user, api_pass=effective_api_pass,
    )
    await bridge.connect()
    _bridges[key] = bridge
    print(f"[MCP] New bridge: indexer={idx_user}@{effective_indexer_ip}:9200  api={effective_api_user}@{wazuh_ip}:55000")
    return bridge


async def shutdown_all():
    for bridge in list(_bridges.values()):
        await bridge.disconnect()
    _bridges.clear()
