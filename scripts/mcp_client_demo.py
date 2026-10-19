"""Talk to Sentinel's MCP server the way an MCP host does: start it, handshake, discover, call a tool.

Usage:  .venv/bin/python scripts/mcp_client_demo.py
This is the host/client side of MCP: no LLM involved. A host like Claude Desktop does exactly these steps,
then lets its model decide which of the discovered tools to call.
"""
import asyncio
import json
import sys
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

SENTINEL_DIR = Path(__file__).resolve().parent.parent
SERVER = StdioServerParameters(command=sys.executable, args=["-m", "mcp_server.server"], cwd=str(SENTINEL_DIR))


async def main() -> dict:
    async with stdio_client(SERVER) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()  # 1. handshake: both sides declare what they support
        print(f"1. connected to {init.server_info.name!r} (protocol {init.protocol_version})")

        tools = (await session.list_tools()).tools  # 2. discovery: names, descriptions, input schemas
        print(f"2. {len(tools)} tools: " + ", ".join(
            f"{t.name}{' (read-only)' if t.annotations and t.annotations.read_only_hint else ''}" for t in tools))
        resources = (await session.list_resources()).resources
        prompts = (await session.list_prompts()).prompts
        print(f"   resources: {[str(r.uri) for r in resources]} · prompts: {[p.name for p in prompts]}")

        result = await session.call_tool("get_auth_events", {  # 3. a tool call, exactly what a model would request
            "start": "2026-09-30T01:45:00Z", "end": "2026-09-30T03:00:00Z", "source_ip": "203.0.113.45"})
        payload = result.structured_content or json.loads(result.content[0].text)
        print(f"3. get_auth_events → by_outcome={payload['by_outcome']}, first={payload['events'][0]['ref']}")

        bad = await session.call_tool("get_auth_events", {"start": "yesterday", "end": "today"})
        print(f"   with bad arguments → is_error={bad.is_error}: {bad.content[0].text[:90]}…")

        dataset = await session.read_resource("sentinel://dataset")  # 4. a resource the host can attach
        print(f"4. resource sentinel://dataset → {dataset.contents[0].text.splitlines()[1]}")
        return {"tools": [t.name for t in tools], "by_outcome": payload["by_outcome"], "bad_is_error": bad.is_error}


if __name__ == "__main__":
    asyncio.run(main())
