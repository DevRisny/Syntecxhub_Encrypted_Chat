"""Wire format: length-prefixed frames carrying JSON messages."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict

MAX_FRAME = 64 * 1024  # largest frame we accept (protects against memory abuse)


class ProtocolError(Exception):
    """The peer sent something that is not valid protocol data."""


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    """Read one frame: 4-byte big-endian length, then that many bytes."""
    header = await reader.readexactly(4)
    length = int.from_bytes(header, "big")
    if length == 0 or length > MAX_FRAME:
        raise ProtocolError(f"invalid frame length {length}")
    return await reader.readexactly(length)


def write_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    """Queue one frame for sending (call drain() afterwards)."""
    if not payload or len(payload) > MAX_FRAME:
        raise ProtocolError("frame size not allowed")
    writer.write(len(payload).to_bytes(4, "big") + payload)


def encode_message(message: Dict[str, Any]) -> bytes:
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_message(data: bytes) -> Dict[str, Any]:
    """Parse a JSON message. It must be an object with a string 'type'."""
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtocolError("message is not valid UTF-8 JSON") from None
    if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
        raise ProtocolError("message must be a JSON object with a 'type'")
    return obj
