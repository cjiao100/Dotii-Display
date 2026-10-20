"""Transport-agnostic Dotii DTU framing and request session.

Wire (USB serial and the BLE data characteristics carry the same bytes):
  DTU1 | u32 LE body length | u32 LE CRC-32 | UTF-8 JSON body
  DTZ1 | u32 LE body length | u32 LE CRC-32 | u32 LE inflated length + zlib(JSON)

Requests carry id/op (+token on USB); replies echo id. Messages with an
"event" key are unsolicited device events. No credential is ever logged.
"""
from __future__ import annotations

import json
import struct
import time
import zlib
from typing import Any, Callable

MAGIC = b"DTU1"
MAGIC_ZLIB = b"DTZ1"
MAX_FRAME = 2 * 1024 * 1024
# Firmware inflate buffer cap for DTZ1 frames (connectivity.c BLE_INFLATED_MAX).
MAX_INFLATED = 96 * 1024


def json_body(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def encode_frame(payload: Any) -> bytes:
    body = json_body(payload)
    if not 0 < len(body) <= MAX_FRAME:
        raise ValueError("USB frame too large")
    return MAGIC + struct.pack("<II", len(body), zlib.crc32(body)) + body


def encode_compressed_frame(payload: Any, *, level: int = 9) -> bytes:
    body = json_body(payload)
    if not 0 < len(body) <= MAX_INFLATED:
        raise ValueError("compressed frame too large")
    inner = struct.pack("<I", len(body)) + zlib.compress(body, level)
    return MAGIC_ZLIB + struct.pack("<II", len(inner), zlib.crc32(inner)) + inner


def _find_magic(buffer: bytearray) -> int:
    positions = [position for position in (buffer.find(MAGIC), buffer.find(MAGIC_ZLIB)) if position >= 0]
    return min(positions) if positions else -1


def _inflate(inner: bytes) -> bytes | None:
    if len(inner) < 5:
        return None
    expected = struct.unpack_from("<I", inner)[0]
    if not 0 < expected <= MAX_INFLATED:
        return None
    try:
        inflater = zlib.decompressobj()
        body = inflater.decompress(inner[4:], expected + 1)
    except zlib.error:
        return None
    return body if len(body) == expected and inflater.eof else None


class FrameDecoder:
    """Incremental DTU1/DTZ1 decoder that resynchronises on noise."""

    def __init__(self, stale_after: float = 8.0):
        self.buffer = bytearray()
        self.started = 0.0
        self.stale_after = stale_after

    def reset(self) -> None:
        self.buffer.clear()

    def feed(self, data: bytes) -> list[dict[str, Any]]:
        if self.buffer and time.monotonic() - self.started > self.stale_after:
            self.buffer.clear()
        if not self.buffer:
            self.started = time.monotonic()
        self.buffer.extend(data)
        output: list[dict[str, Any]] = []
        while True:
            pos = _find_magic(self.buffer)
            if pos < 0:
                self.buffer[:] = self.buffer[-3:]
                break
            if pos:
                del self.buffer[:pos]
            if len(self.buffer) < 12:
                break
            compressed = bytes(self.buffer[:4]) == MAGIC_ZLIB
            length, crc = struct.unpack_from("<II", self.buffer, 4)
            if not 0 < length <= MAX_FRAME:
                del self.buffer[:4]
                continue
            if len(self.buffer) < 12 + length:
                break
            body = bytes(self.buffer[12:12 + length])
            if zlib.crc32(body) != crc:
                del self.buffer[:4]
                continue
            del self.buffer[:12 + length]
            if compressed:
                body = _inflate(body)
                if body is None:
                    continue
            try:
                item = json.loads(body)
                if isinstance(item, dict):
                    output.append(item)
            except (ValueError, UnicodeDecodeError):
                pass
        return output


class DeviceError(ValueError):
    """The device answered ok=false; str() is the stable device error code."""


class DtuSession:
    """Request ids, reply matching and event dispatch shared by every transport.

    The transport owns I/O; the session only builds requests and classifies
    decoded frames, so USB (blocking serial) and BLE (asyncio) share it.
    """

    def __init__(self, token: Callable[[], str] | None = None,
                 on_event: Callable[[dict[str, Any]], None] | None = None):
        self.seq = 0
        self._token = token
        self.on_event = on_event

    def request(self, op: str, *, include_token: bool = True, **payload: Any) -> tuple[int, dict[str, Any]]:
        self.seq += 1
        packet: dict[str, Any] = {"id": self.seq, "op": op}
        if include_token:
            packet["token"] = self._token() if self._token else ""
        packet.update(payload)
        return self.seq, packet

    def dispatch(self, items: list[dict[str, Any]], seq: int) -> dict[str, Any] | None:
        """Deliver events and return the reply for seq, if it is among items.

        A control event can share one read with the ACK: every item is
        consumed before returning so an event is never lost.
        """
        reply = None
        for item in items:
            if "event" in item:
                if self.on_event is not None:
                    self.on_event(item)
            elif item.get("id") == seq:
                reply = item
        return reply

    @staticmethod
    def check(reply: dict[str, Any]) -> dict[str, Any]:
        if not reply.get("ok"):
            raise DeviceError(str(reply.get("error", "device_error")))
        return reply


def handle_bambu_event(server: Any, item: dict[str, Any]) -> None:
    """Forward a device Bambu button press; never replay or retry it."""
    if item.get("event") != "bambu_command":
        return
    try:
        server.bambu.command(item.get("action"))
    except (AttributeError, OSError, ValueError):
        pass
