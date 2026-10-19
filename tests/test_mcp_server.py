"""Sentinel's MCP server, exercised through a real MCP client over stdio (a subprocess, like a host would)."""
import asyncio

from scripts.mcp_client_demo import main


def test_mcp_server_discovery_and_calls():
    result = asyncio.run(main())
    assert "propose_action" in result["tools"] and "get_auth_events" in result["tools"]
    assert "submit_report" not in result["tools"]  # internal to Sentinel's own agent
    assert not any("execute" in t for t in result["tools"])  # execution is never exposed
    assert result["by_outcome"] == {"failure": 6, "success": 1}
    assert result["bad_is_error"] is True
