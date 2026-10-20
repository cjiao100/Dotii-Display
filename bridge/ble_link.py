"""Packet layer for the Dotii BLE data characteristics (7b4e0005 / 7b4e0006).

Every ATT write (Mac -> Dotii, DATA_RX) and notification (Dotii -> Mac,
DATA_TX) is ``[type u8][seq u8][payload]``. DATA payloads are a DTU1/DTZ1
byte stream, so packet boundaries are independent of frame boundaries.

bleak on macOS has no flow control for write-without-response, so the
firmware returns CREDIT packets carrying the cumulative payload bytes it has
received since the last RESET; the sender keeps at most ``window`` bytes in
flight. A sequence gap is reported with NAK and the current frame is lost;
callers reset the channel and retry the request.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from dtu_protocol import FrameDecoder

PKT_DATA = 0x01
PKT_RESET = 0x02
PKT_CREDIT = 0x03
PKT_NAK = 0x04
PKT_BENCH = 0x10
PKT_BENCH_RESET = 0x11
HEADER = 2
ATT_OVERHEAD = 3
MAX_PACKET = 524          # firmware DATA_PACKET_MAX (ATT MTU 527 - 3)
DEFAULT_WINDOW_PACKETS = 8
CREDIT_TIMEOUT = 3.0


class BleLinkError(OSError):
    """The data channel lost sync (NAK, credit stall or disconnect)."""


def payload_size(mtu_size: int, max_write_without_response: int | None = None) -> int:
    """Largest stream payload per packet for this connection."""
    att_payload = max(20, int(mtu_size) - ATT_OVERHEAD)
    if max_write_without_response:
        att_payload = min(att_payload, int(max_write_without_response))
    return max(1, min(att_payload, MAX_PACKET) - HEADER)


def packetize(stream: bytes, chunk: int, seq: int, kind: int = PKT_DATA) -> tuple[list[bytes], int]:
    if chunk < 1:
        raise ValueError("chunk must be positive")
    packets = []
    for offset in range(0, len(stream), chunk):
        packets.append(bytes((kind, seq & 0xFF)) + stream[offset:offset + chunk])
        seq = (seq + 1) & 0xFF
    return packets, seq


@dataclass
class Credit:
    received: int
    expected_seq: int
    queue_free: int


def parse_credit(payload: bytes) -> Credit:
    if len(payload) < 6:
        raise ValueError("short credit")
    received = struct.unpack_from("<I", payload)[0]
    return Credit(received, payload[4], payload[5])


def credit_epoch(packet: bytes) -> int:
    """RESET epoch carried in CREDIT packet byte 1 (firmware s_reset_epoch)."""
    return packet[1] if len(packet) > 1 else 0


@dataclass
class CreditWindow:
    window: int
    sent: int = 0
    acked: int = 0
    _changed: asyncio.Event = field(default_factory=asyncio.Event)

    def reset(self) -> None:
        self.sent = 0
        self.acked = 0
        self._changed.set()

    @property
    def in_flight(self) -> int:
        return (self.sent - self.acked) & 0xFFFFFFFF

    def can_send(self, size: int) -> bool:
        # Always allow one packet when nothing is in flight, even if the
        # window is smaller than a packet.
        return self.in_flight == 0 or self.in_flight + size <= self.window

    def on_sent(self, size: int) -> None:
        self.sent = (self.sent + size) & 0xFFFFFFFF

    def on_credit(self, received: int) -> None:
        # Ignore credits from before a reset or that run ahead of what we sent.
        if ((self.sent - received) & 0xFFFFFFFF) <= self.in_flight:
            self.acked = received & 0xFFFFFFFF
        self._changed.set()

    async def wait_for_room(self, size: int, timeout: float = CREDIT_TIMEOUT,
                            failed: Callable[[], str | None] = lambda: None) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while not self.can_send(size):
            reason = failed()
            if reason:
                raise BleLinkError(reason)
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise BleLinkError("credit_timeout")
            self._changed.clear()
            try:
                await asyncio.wait_for(self._changed.wait(), remaining)
            except (TimeoutError, asyncio.TimeoutError):
                pass


Writer = Callable[[bytes, bool], Awaitable[Any]]


class BleLink:
    """One connection's data channel: packetising, credits and reassembly."""

    def __init__(self, write: Writer, *, chunk: int, window: int | None = None,
                 with_response: bool = False,
                 on_frames: Callable[[list[dict[str, Any]]], None] | None = None):
        self.write = write
        self.chunk = chunk
        self.with_response = with_response
        self.credits = CreditWindow(window if window is not None else chunk * DEFAULT_WINDOW_PACKETS)
        self.decoder = FrameDecoder(stale_after=30.0)
        self.on_frames = on_frames
        self.seq = 0
        self.error: str | None = None
        self.last_credit: Credit | None = None
        self.credit_epoch: int | None = None  # locked from first CREDIT after RESET
        self.bytes_sent = 0
        self.packets_sent = 0
        self.naks = 0
        self.rx_seq: int | None = None
        self.rx_gaps = 0

    # -- notifications (called on the event loop by bleak) --
    def on_notify(self, _sender: Any, data: bytearray | bytes) -> None:
        data = bytes(data)
        if len(data) < HEADER:
            return
        kind, seq, payload = data[0], data[1], data[HEADER:]
        if kind == PKT_CREDIT:
            epoch = seq  # firmware puts s_reset_epoch in the CREDIT header seq byte
            if self.credit_epoch is None:
                self.credit_epoch = epoch
            elif epoch != self.credit_epoch:
                return  # late CREDIT from before the last RESET
            try:
                self.last_credit = parse_credit(payload)
            except ValueError:
                return
            self.credits.on_credit(self.last_credit.received)
        elif kind == PKT_NAK:
            self.naks += 1
            self.error = "sequence_gap"
            self.credits._changed.set()
        elif kind == PKT_DATA:
            if self.rx_seq is not None and seq != self.rx_seq:
                self.rx_gaps += 1
                self.decoder.reset()
            self.rx_seq = (seq + 1) & 0xFF
            items = self.decoder.feed(payload)
            if items and self.on_frames is not None:
                self.on_frames(items)

    def fail(self, reason: str) -> None:
        self.error = reason
        self.credits._changed.set()

    # -- sending --
    async def reset(self, *, bench: bool = False) -> None:
        self.error = None
        self.seq = 0
        self.credits.reset()
        self.credit_epoch = None  # accept the epoch from the CREDIT that follows RESET
        # Byte 2 tells the firmware our window in packets so it credits often
        # enough (older firmware ignores it and credits every 4 + tail flush).
        await self.write(bytes((PKT_BENCH_RESET if bench else PKT_RESET, 0, self.window_packets)), True)

    @property
    def window_packets(self) -> int:
        return max(1, min(255, self.credits.window // max(1, self.chunk)))

    async def send_stream(self, stream: bytes, kind: int = PKT_DATA) -> None:
        packets, self.seq = packetize(stream, self.chunk, self.seq, kind)
        for packet in packets:
            if self.error:
                raise BleLinkError(self.error)
            size = len(packet) - HEADER
            if not self.with_response:
                await self.credits.wait_for_room(size, failed=lambda: self.error)
            # Count before writing: the CREDIT for this packet can be delivered
            # before write_gatt_char returns and must not look like it ran ahead.
            self.credits.on_sent(size)
            await self.write(packet, self.with_response)
            self.bytes_sent += size
            self.packets_sent += 1

    async def drain(self, timeout: float = CREDIT_TIMEOUT) -> None:
        """Wait until the device has acknowledged everything sent."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while self.credits.in_flight:
            if self.error:
                raise BleLinkError(self.error)
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise BleLinkError("credit_timeout")
            self.credits._changed.clear()
            try:
                await asyncio.wait_for(self.credits._changed.wait(), remaining)
            except (TimeoutError, asyncio.TimeoutError):
                pass
