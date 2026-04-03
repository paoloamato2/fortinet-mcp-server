import pytest
from server import mcp

def test_mcp_instance_name():
    """Basic test to ensure the MCP server instance can be imported."""
    assert mcp.name == "FortiOS MCP Server"
