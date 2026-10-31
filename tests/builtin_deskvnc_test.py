# -*- coding: utf-8 -*-
"""DeskVNC tool and MCP client factory unit tests."""

import json
import os
import unittest
from unittest.async_case import IsolatedAsyncioTestCase

from agentscope.mcp import MCPClient, create_deskvnc_mcp_client
from agentscope.message import DataBlock, TextBlock, ToolResultState
from agentscope.permission import PermissionBehavior, PermissionContext
from agentscope.tool import DeskVNCTool, unscale_coordinates


class DeskVNCInterfaceTest(IsolatedAsyncioTestCase):
    """Test public tool interfaces, schemas, and permission rules."""

    async def test_tool_attributes_and_schemas(self) -> None:
        tool = DeskVNCTool()
        self.assertEqual(tool.name, "DeskVNCTool")
        self.assertFalse(tool.is_concurrency_safe)
        self.assertFalse(tool.is_read_only)
        self.assertIn("action", tool.input_schema["properties"])
        self.assertIn("limb_id", tool.input_schema["properties"])
        self.assertIn("generation", tool.input_schema["properties"])
        self.assertIn("reason", tool.input_schema["properties"])
        self.assertIn("scale", tool.input_schema["properties"])

    async def test_permission_boundaries(self) -> None:
        tool = DeskVNCTool()
        ctx = PermissionContext()

        # Read actions should be auto-allowed
        for act in ("list_hosts", "list_sessions", "observe"):
            dec = await tool.check_permissions({"action": act}, ctx)
            self.assertEqual(dec.behavior, PermissionBehavior.ALLOW)

        # Mutating actions should require user approval (ASK)
        for act in ("click", "type", "key", "connect", "disconnect", "reconnect"):
            dec = await tool.check_permissions({"action": act}, ctx)
            self.assertEqual(dec.behavior, PermissionBehavior.ASK)


class DeskVNCCoordinateScalingTest(unittest.TestCase):
    """Test coordinate scaling and unscaling mathematics."""

    def test_unscale_coordinates(self) -> None:
        # At scale 0.5, image coordinate (400, 300) maps to remote (800, 600)
        rem_x, rem_y = unscale_coordinates(400, 300, scale=0.5)
        self.assertEqual(rem_x, 800)
        self.assertEqual(rem_y, 600)

        # At scale 1.0 (native), coordinates remain identical
        rem_x, rem_y = unscale_coordinates(1920, 1080, scale=1.0)
        self.assertEqual(rem_x, 1920)
        self.assertEqual(rem_y, 1080)


class DeskVNCExecutionTest(IsolatedAsyncioTestCase):
    """Test tool execution with mock dvv driver."""

    async def asyncSetUp(self) -> None:
        os.environ["DESKVNC_MOCK_MODE"] = "1"
        self.tool = DeskVNCTool()

    async def test_list_hosts(self) -> None:
        chunks = [chunk async for chunk in await self.tool(action="list_hosts")]

        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].state, ToolResultState.SUCCESS)
        text_block = chunks[0].content[0]
        self.assertIsInstance(text_block, TextBlock)
        payload = json.loads(text_block.text)
        self.assertIn("hosts", payload)
        self.assertTrue(len(payload["hosts"]) >= 3)

    async def test_connect_and_observe_multimodal(self) -> None:
        # Connect to host
        chunks = [chunk async for chunk in await self.tool(action="connect", host_id="host-win11")]
        self.assertEqual(chunks[0].state, ToolResultState.SUCCESS)

        # Observe screen returns both DataBlock (PNG) and TextBlock (metadata)
        obs_chunks = [
            chunk
            async for chunk in await self.tool(
                action="observe", limb_id="limb-ubuntu", scale=0.5
            )
        ]

        self.assertEqual(len(obs_chunks), 1)
        self.assertEqual(obs_chunks[0].state, ToolResultState.SUCCESS)
        blocks = obs_chunks[0].content
        self.assertEqual(len(blocks), 2)
        self.assertIsInstance(blocks[0], DataBlock)
        self.assertEqual(blocks[0].source.media_type, "image/png")
        self.assertIsInstance(blocks[1], TextBlock)

        meta = json.loads(blocks[1].text)
        self.assertEqual(meta["limb_id"], "limb-ubuntu")
        self.assertGreaterEqual(meta["generation"], 1)

    async def test_click_with_fencing_and_reason(self) -> None:
        chunks = [
            chunk
            async for chunk in await self.tool(
                action="click",
                limb_id="limb-ubuntu",
                x=250,
                y=150,
                generation=1,
                reason="Clicking system menu",
            )
        ]

        self.assertEqual(chunks[0].state, ToolResultState.SUCCESS)
        res = json.loads(chunks[0].content[0].text)
        self.assertEqual(res["status"], "clicked")
        self.assertEqual(res["coords"], [500, 300])  # Unscaled 250*2, 150*2

    async def test_type_and_key(self) -> None:
        # Type
        type_chunks = [
            chunk
            async for chunk in await self.tool(
                action="type",
                limb_id="limb-ubuntu",
                text="systemctl status nginx",
                reason="checking service",
            )
        ]
        self.assertEqual(type_chunks[0].state, ToolResultState.SUCCESS)

        # Key
        key_chunks = [
            chunk
            async for chunk in await self.tool(
                action="key",
                limb_id="limb-ubuntu",
                key="Return",
                reason="submit command",
            )
        ]
        self.assertEqual(key_chunks[0].state, ToolResultState.SUCCESS)

    async def test_control_lease_lifecycle(self) -> None:
        # Acquire
        chunks = [
            chunk
            async for chunk in await self.tool(
                action="lease_control",
                limb_id="limb-ubuntu",
                control_action="acquire",
                reason="Running diagnostics",
            )
        ]
        self.assertEqual(chunks[0].state, ToolResultState.SUCCESS)
        res = json.loads(chunks[0].content[0].text)
        self.assertEqual(res["control_status"]["holder"], "agentscope-agent")
        self.assertIn("limb-ubuntu", self.tool._active_leases)

        # Release all leases
        await self.tool.release_all_leases()
        self.assertEqual(len(self.tool._active_leases), 0)


class DeskVNCMCPFactoryTest(unittest.TestCase):
    """Test MCP client factory configuration for DeskVNC."""

    def test_create_stdio_client(self) -> None:
        client = create_deskvnc_mcp_client(command="dvv", args=["mcp", "--stdio"])
        self.assertIsInstance(client, MCPClient)
        self.assertEqual(client.name, "deskvnc")
        self.assertTrue(client.is_stateful)
        self.assertEqual(client.mcp_config.command, "dvv")
        self.assertEqual(client.mcp_config.args, ["mcp", "--stdio"])

    def test_create_http_client(self) -> None:
        client = create_deskvnc_mcp_client(
            http_url="http://127.0.0.1:24801/mcp",
            auth_token="test-token-123",
            name="deskvnc-http",
        )
        self.assertIsInstance(client, MCPClient)
        self.assertEqual(client.name, "deskvnc-http")
        self.assertEqual(client.mcp_config.url, "http://127.0.0.1:24801/mcp")
        self.assertIn("Authorization", client.mcp_config.headers)
        self.assertEqual(client.mcp_config.headers["Authorization"], "Bearer test-token-123")
