Help on function run in module mcp.server.fastmcp.server:

rruunn(self, transport: "Literal['stdio', 'sse', 'streamable-http']" = 'stdio', mount_path: 'str | None' = None) -> 'None'
    Run the FastMCP server. Note this is a synchronous function.

    Args:
        transport: Transport protocol to use ("stdio", "sse", or "streamable-http")
        mount_path: Optional mount path for SSE transport
