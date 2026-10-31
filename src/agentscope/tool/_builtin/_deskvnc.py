# -*- coding: utf-8 -*-
"""DeskVNC remote desktop automation tool for AgentScope."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
from typing import Any, AsyncGenerator, List

from .._base import ToolBase, ToolMiddlewareBase
from .._response import ToolChunk
from ...message import Base64Source, DataBlock, TextBlock, ToolResultState
from ...permission import (
    PermissionBehavior,
    PermissionContext,
    PermissionDecision,
    PermissionRule,
)

logger = logging.getLogger("agentscope.tool.deskvnc")

READ_ONLY_ACTIONS = frozenset({"list_hosts", "list_sessions", "observe"})


def unscale_coordinates(
    x: int | float,
    y: int | float,
    scale: float = 0.5,
) -> tuple[int, int]:
    """Convert coordinates from downscaled image back to framebuffer pixels.

    Args:
        x: X coordinate on the observed (downscaled) image.
        y: Y coordinate on the observed (downscaled) image.
        scale: The scale factor applied when capturing the screen.

    Returns:
        tuple[int, int]: Unscaled remote framebuffer pixel coordinates.
    """
    if scale <= 0 or scale == 1.0:
        return int(x), int(y)
    return int(round(x / scale)), int(round(y / scale))


class DeskVNCTool(ToolBase):
    """Operate, inspect, and automate remote machines (Windows, Linux, macOS)
    over VNC, RDP, and SSH with generation fencing and human takeover
    protection.
    """

    name: str = "DeskVNCTool"
    """The tool name presented to the agent."""

    description: str = (
        "Operates remote machines over VNC, RDP, and SSH via DeskVNC.\n\n"
        "No software installation is required on the remote target.\n\n"
        "# Features & Safety Guarantees:\n"
        "1. Multi-protocol: Connects to VNC (5900), RDP (3389), and "
        "SSH (22).\n"
        "2. Generation Fencing: Observations carry a generation token.\n"
        "   Stale actions are refused to prevent misclicks on repainted UI.\n"
        "3. Leased Machine Control: Machine control is leased. Human\n"
        "   operators take priority; when a human acts, the agent yields.\n\n"
        "# Action Reference:\n"
        "- list_hosts: Discover saved machines in DeskVNC.\n"
        "- list_sessions: List currently open sessions (limbs).\n"
        "- connect: Open a session to a host (requires host_id).\n"
        "- observe: Capture a screenshot and obtain current generation.\n"
        "- click: Send mouse click at (x, y) with coordinate scaling.\n"
        "- type: Send text string to active focused window.\n"
        "- key: Send special key combination (e.g. Return, ctrl+c).\n"
        "- lease_control: Acquire, inspect, or release control lease.\n"
        "- reconnect: Re-establish a stalled or frozen session.\n"
        "- disconnect: Close a session cleanly."
    )

    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "list_hosts",
                    "list_sessions",
                    "connect",
                    "observe",
                    "click",
                    "type",
                    "key",
                    "lease_control",
                    "reconnect",
                    "disconnect",
                ],
                "description": "The remote action to perform.",
            },
            "limb_id": {
                "type": "string",
                "description": (
                    "Target session ID (required for session actions)."
                ),
            },
            "host_id": {
                "type": "string",
                "description": "Host ID for 'connect'.",
            },
            "x": {
                "type": "number",
                "description": "X coordinate for mouse click.",
            },
            "y": {
                "type": "number",
                "description": "Y coordinate for mouse click.",
            },
            "text": {
                "type": "string",
                "description": "Text to type into active window.",
            },
            "key": {
                "type": "string",
                "description": (
                    "Key chord (e.g. 'Return', 'ctrl+c', 'super+r')."
                ),
            },
            "click_type": {
                "type": "string",
                "enum": ["single", "double", "right"],
                "default": "single",
                "description": "Mouse click flavor.",
            },
            "control_action": {
                "type": "string",
                "enum": ["acquire", "status", "release"],
                "default": "acquire",
                "description": "Control lease action.",
            },
            "generation": {
                "type": "integer",
                "description": (
                    "Screen generation number from last observation for "
                    "safety fencing."
                ),
            },
            "reason": {
                "type": "string",
                "description": (
                    "Concise human-readable explanation of why the action "
                    "is being performed."
                ),
            },
            "scale": {
                "type": "number",
                "default": 0.5,
                "description": (
                    "Screenshot downscaling factor (default 0.5)."
                ),
            },
            "timeout": {
                "type": "number",
                "default": 25.0,
                "description": "Operation timeout in seconds.",
            },
        },
        "required": ["action"],
    }

    is_concurrency_safe: bool = False
    is_read_only: bool = False

    def __init__(
        self,
        dvv_path: str | None = None,
        middlewares: List[ToolMiddlewareBase] | None = None,
    ) -> None:
        super().__init__(middlewares=middlewares)
        self._dvv_path = dvv_path
        self._generation_cache: dict[str, int] = {}
        self._active_leases: set[str] = set()
        self._mock_mode = os.getenv("DESKVNC_MOCK_MODE", "").lower() in (
            "1",
            "true",
            "yes",
        )

        # Mock state for deterministic unit testing
        self._mock_hosts = [
            {
                "id": "host-ubuntu",
                "name": "Ubuntu 24.04 Dev",
                "protocol": "vnc",
                "address": "192.168.1.100:5900",
            },
            {
                "id": "host-win11",
                "name": "Windows 11 Workstation",
                "protocol": "rdp",
                "address": "192.168.1.101:3389",
            },
            {
                "id": "host-bastion",
                "name": "Secure Bastion",
                "protocol": "ssh",
                "address": "bastion.corp:22",
            },
        ]
        self._mock_limbs = {
            "limb-ubuntu": {
                "id": "limb-ubuntu",
                "hostId": "host-ubuntu",
                "title": "Ubuntu 24.04 Dev",
                "protocol": "vnc",
                "connected": True,
                "geometry": {"width": 1920, "height": 1080},
                "generation": 1,
            },
        }
        self._mock_leases: dict[str, str] = {}

    def resolve_dvv(self) -> str | None:
        """Resolve the executable path to the DeskVNC dvv CLI binary."""
        if self._dvv_path and os.path.exists(self._dvv_path):
            return self._dvv_path
        env_path = os.getenv("DESKVNC_DVV_PATH")
        if env_path and os.path.exists(env_path):
            return env_path
        which = shutil.which("dvv")
        if which:
            return which
        if sys.platform == "win32":
            local = os.getenv("LOCALAPPDATA", "")
            prog = os.getenv("ProgramFiles", "C:\\Program Files")
            for c in [
                os.path.join(local, "DeskVNCViewer", "dvv.exe"),
                os.path.join(prog, "DeskVNCViewer", "dvv.exe"),
            ]:
                if os.path.exists(c):
                    return c
        return None

    async def check_permissions(
        self,
        tool_input: dict[str, Any],
        context: PermissionContext,
    ) -> PermissionDecision:
        action = tool_input.get("action", "")
        if action in READ_ONLY_ACTIONS:
            return PermissionDecision(
                behavior=PermissionBehavior.ALLOW,
                message=f"Safe read-only DeskVNC query: {action}",
            )
        if (
            action == "lease_control"
            and tool_input.get("control_action") == "status"
        ):
            return PermissionDecision(
                behavior=PermissionBehavior.ALLOW,
                message="Read-only DeskVNC lease status check",
            )
        return PermissionDecision(
            behavior=PermissionBehavior.ASK,
            message=f"DeskVNC remote action requires user approval: {action}",
            decision_reason=f"Action '{action}' mutates remote desktop state",
        )

    async def generate_suggestions(
        self,
        tool_input: dict[str, Any],
    ) -> List[PermissionRule]:
        return []

    async def _execute_dvv(
        self,
        args: list[str],
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        if self._mock_mode:
            return self._mock_dispatch(args)

        dvv_bin = self.resolve_dvv()
        if not dvv_bin:
            raise RuntimeError(
                "DeskVNC dvv binary not found. Set DESKVNC_DVV_PATH or "
                "install DeskVNC.",
            )

        cmd = [dvv_bin] + args + ["--json"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )
        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"dvv error ({proc.returncode}): {err}")
        out = stdout.decode(errors="replace").strip()
        return json.loads(out) if out else {}

    # pylint: disable=too-many-return-statements
    def _mock_dispatch(self, args: list[str]) -> dict[str, Any]:
        sub = args[0] if args else ""
        if sub == "hosts":
            return {"hosts": self._mock_hosts}
        if sub == "limbs":
            return {"limbs": list(self._mock_limbs.values())}
        if sub == "open":
            host_id = args[1] if len(args) > 1 else "host-ubuntu"
            limb_id = f"limb-{host_id}"
            limb = {
                "id": limb_id,
                "hostId": host_id,
                "title": f"Session {host_id}",
                "protocol": "vnc",
                "connected": True,
                "geometry": {"width": 1920, "height": 1080},
                "generation": 1,
            }
            self._mock_limbs[limb_id] = limb
            return limb
        if sub == "screen":
            limb_id = args[1] if len(args) > 1 else "limb-ubuntu"
            limb = self._mock_limbs.get(
                limb_id,
                {
                    "generation": 0,
                    "geometry": {"width": 1920, "height": 1080},
                },
            )
            raw_gen = limb.get("generation", 0)
            if isinstance(raw_gen, (int, str)):
                gen = int(raw_gen) + 1
            else:
                gen = 1
            limb["generation"] = gen
            # Transparent 1x1 test PNG base64
            test_png = (
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0l"
                "EQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
            )
            return {
                "limb_id": limb_id,
                "generation": gen,
                "geometry": limb["geometry"],
                "screenshot": test_png,
                "settled": True,
            }
        if sub in ("click", "type", "key"):
            return {"ok": True, "action": sub, "settled": True}
        if sub == "control":
            act = args[1] if len(args) > 1 else "status"
            limb_id = args[2] if len(args) > 2 else "limb-ubuntu"
            if act == "acquire":
                self._mock_leases[limb_id] = "agentscope-agent"
                return {
                    "holder": "agentscope-agent",
                    "is_human": False,
                    "idle_seconds": 0.0,
                }
            if act == "release":
                self._mock_leases.pop(limb_id, None)
                return {
                    "holder": "none",
                    "is_human": False,
                    "idle_seconds": 0.0,
                }
            holder = self._mock_leases.get(limb_id, "none")
            return {
                "holder": holder,
                "is_human": holder == "human",
                "idle_seconds": 0.0,
            }
        if sub in ("close", "reconnect"):
            return {"ok": True, "action": sub}
        return {"ok": True}

    # pylint: disable=too-many-return-statements,too-many-branches
    # pylint: disable=too-many-statements,arguments-differ
    async def call(  # type: ignore[override]
        self,
        *,
        action: str,
        limb_id: str | None = None,
        host_id: str | None = None,
        x: int | float | None = None,
        y: int | float | None = None,
        text: str | None = None,
        key: str | None = None,
        click_type: str = "single",
        control_action: str = "acquire",
        generation: int | None = None,
        reason: str | None = None,
        scale: float = 0.5,
        timeout: float = 25.0,
    ) -> AsyncGenerator[ToolChunk, None]:
        """Execute DeskVNC remote desktop actions."""
        reason_str = reason or ""
        try:
            if action == "list_hosts":
                res = await self._execute_dvv(["hosts"], timeout=timeout)
                yield ToolChunk(
                    content=[
                        TextBlock(type="text", text=json.dumps(res, indent=2)),
                    ],
                    state=ToolResultState.SUCCESS,
                )
                return

            if action == "list_sessions":
                res = await self._execute_dvv(["limbs"], timeout=timeout)
                yield ToolChunk(
                    content=[
                        TextBlock(type="text", text=json.dumps(res, indent=2)),
                    ],
                    state=ToolResultState.SUCCESS,
                )
                return

            if action == "connect":
                if not host_id:
                    yield ToolChunk(
                        content=[
                            TextBlock(
                                type="text",
                                text="Error: 'host_id' required for connect",
                            ),
                        ],
                        state=ToolResultState.ERROR,
                    )
                    return
                res = await self._execute_dvv(
                    ["open", host_id, "--perceive"],
                    timeout=timeout,
                )
                ret_limb = res.get("limbId") or res.get("id") or host_id
                self._generation_cache[ret_limb] = int(
                    res.get("generation") or 1,
                )
                yield ToolChunk(
                    content=[
                        TextBlock(type="text", text=json.dumps(res, indent=2)),
                    ],
                    state=ToolResultState.SUCCESS,
                )
                return

            if not limb_id:
                yield ToolChunk(
                    content=[
                        TextBlock(
                            type="text",
                            text=(
                                f"Error: 'limb_id' required for action "
                                f"'{action}'"
                            ),
                        ),
                    ],
                    state=ToolResultState.ERROR,
                )
                return

            if action == "observe":
                res = await self._execute_dvv(
                    ["screen", limb_id, "--scale", str(scale)],
                    timeout=timeout,
                )
                gen = int(res.get("generation") or 0)
                self._generation_cache[limb_id] = gen
                b64 = str(res.get("screenshot") or "")

                content_blocks: List[TextBlock | DataBlock] = []
                if b64:
                    content_blocks.append(
                        DataBlock(
                            source=Base64Source(
                                data=b64,
                                media_type="image/png",
                            ),
                        ),
                    )
                content_blocks.append(
                    TextBlock(
                        type="text",
                        text=json.dumps(
                            {
                                "limb_id": limb_id,
                                "generation": gen,
                                "geometry": res.get("geometry", {}),
                                "scale": scale,
                                "settled": res.get("settled", True),
                            },
                            indent=2,
                        ),
                    ),
                )
                yield ToolChunk(
                    content=content_blocks,
                    state=ToolResultState.SUCCESS,
                )
                return

            if action == "click":
                if x is None or y is None:
                    yield ToolChunk(
                        content=[
                            TextBlock(
                                type="text",
                                text="Error: 'x' and 'y' required for click",
                            ),
                        ],
                        state=ToolResultState.ERROR,
                    )
                    return
                rem_x, rem_y = unscale_coordinates(x, y, scale)
                tgen = (
                    generation
                    if generation is not None
                    else self._generation_cache.get(limb_id, 0)
                )
                args = ["click", limb_id, str(rem_x), str(rem_y)]
                if click_type in ("double", "right"):
                    args.extend(["--action", click_type])
                if tgen > 0:
                    args.extend(["--generation", str(tgen)])
                if reason_str:
                    args.extend(["--reason", reason_str])

                res = await self._execute_dvv(args, timeout=timeout)
                yield ToolChunk(
                    content=[
                        TextBlock(
                            type="text",
                            text=json.dumps(
                                {
                                    "status": "clicked",
                                    "coords": (rem_x, rem_y),
                                    "result": res,
                                },
                                indent=2,
                            ),
                        ),
                    ],
                    state=ToolResultState.SUCCESS,
                )
                return

            if action == "type":
                if text is None:
                    yield ToolChunk(
                        content=[
                            TextBlock(
                                type="text",
                                text="Error: 'text' required for type",
                            ),
                        ],
                        state=ToolResultState.ERROR,
                    )
                    return
                tgen = (
                    generation
                    if generation is not None
                    else self._generation_cache.get(limb_id, 0)
                )
                args = ["type", limb_id, text]
                if tgen > 0:
                    args.extend(["--generation", str(tgen)])
                if reason_str:
                    args.extend(["--reason", reason_str])

                res = await self._execute_dvv(args, timeout=timeout)
                yield ToolChunk(
                    content=[
                        TextBlock(
                            type="text",
                            text=json.dumps(
                                {
                                    "status": "typed",
                                    "chars": len(text),
                                    "result": res,
                                },
                                indent=2,
                            ),
                        ),
                    ],
                    state=ToolResultState.SUCCESS,
                )
                return

            if action == "key":
                if not key:
                    yield ToolChunk(
                        content=[
                            TextBlock(
                                type="text",
                                text="Error: 'key' required for key",
                            ),
                        ],
                        state=ToolResultState.ERROR,
                    )
                    return
                tgen = (
                    generation
                    if generation is not None
                    else self._generation_cache.get(limb_id, 0)
                )
                args = ["key", limb_id, key]
                if tgen > 0:
                    args.extend(["--generation", str(tgen)])
                if reason_str:
                    args.extend(["--reason", reason_str])

                res = await self._execute_dvv(args, timeout=timeout)
                yield ToolChunk(
                    content=[
                        TextBlock(
                            type="text",
                            text=json.dumps(
                                {
                                    "status": "key_sent",
                                    "key": key,
                                    "result": res,
                                },
                                indent=2,
                            ),
                        ),
                    ],
                    state=ToolResultState.SUCCESS,
                )
                return

            if action == "lease_control":
                args = ["control", control_action, limb_id]
                if control_action == "acquire" and reason_str:
                    args.extend(["--reason", reason_str])
                res = await self._execute_dvv(args, timeout=timeout)
                if control_action == "acquire":
                    self._active_leases.add(limb_id)
                elif control_action == "release":
                    self._active_leases.discard(limb_id)
                yield ToolChunk(
                    content=[
                        TextBlock(
                            type="text",
                            text=json.dumps({"control_status": res}, indent=2),
                        ),
                    ],
                    state=ToolResultState.SUCCESS,
                )
                return

            if action == "reconnect":
                res = await self._execute_dvv(
                    ["reconnect", limb_id],
                    timeout=timeout,
                )
                yield ToolChunk(
                    content=[
                        TextBlock(type="text", text=json.dumps(res, indent=2)),
                    ],
                    state=ToolResultState.SUCCESS,
                )
                return

            if action == "disconnect":
                self._active_leases.discard(limb_id)
                res = await self._execute_dvv(
                    ["close", limb_id],
                    timeout=timeout,
                )
                yield ToolChunk(
                    content=[
                        TextBlock(type="text", text=json.dumps(res, indent=2)),
                    ],
                    state=ToolResultState.SUCCESS,
                )
                return

            yield ToolChunk(
                content=[
                    TextBlock(
                        type="text",
                        text=f"Error: Unknown action '{action}'",
                    ),
                ],
                state=ToolResultState.ERROR,
            )

        except Exception as exc:
            logger.exception(
                "DeskVNCTool exception during '%s': %s",
                action,
                exc,
            )
            yield ToolChunk(
                content=[
                    TextBlock(type="text", text=f"DeskVNCTool Error: {exc}"),
                ],
                state=ToolResultState.ERROR,
            )

    async def release_all_leases(self) -> None:
        """Release all active control leases held by this tool instance."""
        for limb_id in list(self._active_leases):
            try:
                await self._execute_dvv(["control", "release", limb_id])
            except Exception:  # pylint: disable=broad-exception-caught
                pass
        self._active_leases.clear()
