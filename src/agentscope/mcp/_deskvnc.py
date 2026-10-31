# -*- coding: utf-8 -*-
"""DeskVNC MCP client factory for AgentScope."""

from __future__ import annotations

import os
import shutil
from typing import Sequence

from ._config import HttpMCPConfig, StdioMCPConfig
from ._mcp_client import MCPClient


# pylint: disable=too-many-positional-arguments
def create_deskvnc_mcp_client(
    command: str | None = None,
    args: Sequence[str] | None = None,
    http_url: str | None = None,
    auth_token: str | None = None,
    name: str = "deskvnc",
    is_stateful: bool = True,
) -> MCPClient:
    """Create a configured AgentScope MCPClient connected to DeskVNC.

    Args:
        command: Path to the dvv executable (defaults to PATH discovery).
        args: Command arguments for stdio MCP (defaults to ['mcp',
            '--stdio']).
        http_url: Optional loopback HTTP URL if connecting over HTTP
            SSE transport.
        auth_token: Optional bearer token for HTTP transport.
        name: Unique client identifier in AgentScope (default 'deskvnc').
        is_stateful: Whether the client connection is persistent (default
            True).

    Returns:
        MCPClient: Configured MCP client ready for connect() and
            list_tools().
    """
    if http_url:
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        config = HttpMCPConfig(url=http_url, headers=headers)
        return MCPClient(
            name=name,
            is_stateful=is_stateful,
            mcp_config=config,
        )

    resolved_cmd = (
        command
        or os.getenv("DESKVNC_DVV_PATH")
        or shutil.which("dvv")
        or "dvv"
    )
    cmd_args = list(args) if args is not None else ["mcp", "--stdio"]

    config = StdioMCPConfig(command=resolved_cmd, args=cmd_args)
    return MCPClient(
        name=name,
        is_stateful=is_stateful,
        mcp_config=config,
    )
