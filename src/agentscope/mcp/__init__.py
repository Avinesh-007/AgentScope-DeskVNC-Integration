# -*- coding: utf-8 -*-
"""The MCP module in AgentScope, that provides fine-grained control over
the MCP servers."""

from ._config import StdioMCPConfig, HttpMCPConfig
from ._mcp_client import MCPClient
from ._deskvnc import create_deskvnc_mcp_client

__all__ = [
    "MCPClient",
    "StdioMCPConfig",
    "HttpMCPConfig",
    "create_deskvnc_mcp_client",
]
