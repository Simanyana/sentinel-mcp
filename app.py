from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

mcp = MCPServer("hello")


@mcp.tool()
def say_hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"


# Lambda Web Adapter forwards requests with the Lambda URL's own Host header,
# so the local-only DNS rebinding check must be off. Stateless JSON mode suits Lambda.
app = mcp.streamable_http_app(
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)
