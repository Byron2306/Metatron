"""
Compatibility shim for the canonical Seraph MCP authority.

Canonical implementation:
    backend.services.mcp_server

This module must not contain independent MCP authority, policy,
capability, governance, or execution logic.
"""

from backend.services.mcp_server import (
    MCPMessage,
    MCPMessageType,
    MCPServer,
    MCPToolCategory,
    MCPToolExecution,
    MCPToolSchema,
    mcp_server,
)

__all__ = [
    "MCPMessage",
    "MCPMessageType",
    "MCPServer",
    "MCPToolCategory",
    "MCPToolExecution",
    "MCPToolSchema",
    "mcp_server",
]


def __getattr__(name):
    raise AttributeError(
        f"mcp_server compatibility shim has no attribute {name!r}; "
        "use backend.services.mcp_server"
    )
