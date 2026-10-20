"""In-memory model of the Dotii BLE data channel firmware for unit tests.

Mirrors main/ble_bridge.c (packet layer, credits every 4 packets, NAK) and
the BLE half of process_request() in main/connectivity.c.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import secrets
import struct
from types import SimpleNamespace
from typing import Any, Callable

from ble_link import PKT_BENCH, PKT_BENCH_RESET, PKT_CREDIT, PKT_DATA, PKT_NAK, PKT_RESET, packetize
from dtu_protocol import FrameDecoder, encode_frame

DATA_RX = "7b4e0005-4db4-4c72-a729-ea5187241a43"
DATA_TX = "7b4e0006-4db4-4c72-a729-ea5187241a43"
STATUS = "7b4e0004-4db4-4c72-a729-ea5187241a43"


class FakeDotiiFirmware:
    def __init__(self, *, token: str = "local-test-token-0001", device_id: str = "AABBCCDDEEFF",
                 bound: bool = True, want_data: bool = True, send_credits: bool = True,
                 credit_delay: float = 0.0, credit_every: int = 4, mtu: int = 247):
        self.token = token
        self.device_id = device_id
        self.bound = bound
        self.want_data = want_data
        self.send_credits = send_credits
        self.credit_delay = credit_delay
        self.credit_every = credit_every
        self.mtu = mtu
        self.notify: Callable[[Any, bytes], None] | None = None
        self.decoder = FrameDecoder()
        self.reset_channel()
        self.tx_seq = 0
        self.requests: list[dict[str, Any]] = []
        self.snapshots: list[dict[str, Any]] = []
        self.heartbeats = 0
        self.authenticated = False
        self.challenge = ""
        self.last_reply: dict[str, Any] | None = None
        self.bench_bytes = 0
        self.used_response_for_data = False
        self.max_in_flight = 0
        self.credited = 0
        self.mode = "auto"

    def attach(self, notify: Callable[[Any, bytes], None]) -> None:
        self.notify = notify

    def reset_channel(self) -> None:
        self.decoder = FrameDecoder()
        self.expected_seq: int | None = None
        self.received_total = 0
        self.packets_since_credit = 0
        self.received_bytes = 0
        self.credited = 0
        self.reset_epoch = getattr(self, "reset_epoch", 0) + 1

    # -- radio --
    def _deliver(self, packet: bytes, credit_value: int | None = None) -> None:
        if credit_value is not None:
            self.credited = credit_value
        if self.notify is not None:
            self.notify(None, bytearray(packet))

    def _credit(self) -> None:
        self.packets_since_credit = 0
        if not self.send_credits:
            return
        total = self.received_total
        packet = bytes((PKT_CREDIT, self.reset_epoch & 0xFF)) + struct.pack("<I", total) + bytes(((self.expected_seq or 0) & 0xFF, 3))
        if self.credit_delay:
            asyncio.get_running_loop().call_later(self.credit_delay, self._deliver, packet, total)
        else:
            self._deliver(packet, total)

    async def write(self, packet: bytes, response: bool) -> None:
        kind, seq, payload = packet[0], packet[1], packet[2:]
        if kind in (PKT_RESET, PKT_BENCH_RESET):
            self.reset_channel()
            if kind == PKT_BENCH_RESET:
                self.bench_bytes = 0
            self._credit()
            return
        if kind not in (PKT_DATA, PKT_BENCH):
            raise OSError("request not supported")
        if response:
            self.used_response_for_data = True
        if self.expected_seq is not None and seq != self.expected_seq:
            self.decoder.reset()
            self._deliver(bytes((PKT_NAK, 0, self.expected_seq, seq)))
        self.expected_seq = (seq + 1) & 0xFF
        self.received_total = (self.received_total + len(payload)) & 0xFFFFFFFF
        self.received_bytes += len(payload)
        self.max_in_flight = max(self.max_in_flight, self.received_total - self.credited)
        frames = []
        if kind == PKT_DATA:
            frames = self.decoder.feed(payload)
        else:
            self.bench_bytes += len(payload)
        self.packets_since_credit += 1
        if self.packets_since_credit >= self.credit_every or frames:
            self._credit()
        for request in frames:
            # Firmware drops compressed / >512 B frames before JSON parse when unauthenticated.
            raw = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode()
            if not self.authenticated and len(raw) > 512:
                self.requests.append(request)
                self._send({"id": request.get("id", 0), "ok": False, "error": "unauthenticated"})
                continue
            self.requests.append(request)
            self._send(self.handle(request))

    def _send(self, message: dict[str, Any]) -> None:
        packets, self.tx_seq = packetize(encode_frame(message), self.mtu - 5, self.tx_seq)
        for packet in packets:
            self._deliver(packet)

    def push_event(self, **event: Any) -> None:
        self._send(event)

    # -- connectivity.c process_request (BLE) --
    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        op = request.get("op")
        reply: dict[str, Any] = {"id": request.get("id", 0)}
        error = None
        if "token" in request:
            error = "token_over_ble_not_expected"
        elif not self.authenticated:
            diag_ok = op == "ble_diag" and not self.bound
            if op not in ("hello", "auth") and not diag_ok:
                error = "unauthenticated"
        if error:
            pass
        elif op == "hello":
            self.challenge = secrets.token_hex(16)
            reply.update(product="Dotii", protocol=1, device_id=self.device_id, firmware="1.3-test",
                         challenge=self.challenge, auth="hmac-sha256", bound=self.bound)
        elif op == "auth":
            message = f"dotii-ble-auth-v1|{self.device_id}|{self.challenge}".encode()
            expected = hmac.new(self.token.encode(), message, hashlib.sha256).hexdigest()
            host_nonce = str(request.get("host_nonce") or "")
            if not self.bound:
                error = "not_bound"
            elif not self.challenge:
                error = "no_challenge"
            elif len(host_nonce) != 32 or any(c not in "0123456789abcdef" for c in host_nonce):
                error = "invalid_nonce"
            elif not hmac.compare_digest(expected, str(request.get("mac", ""))):
                error = "binding_mismatch"
            else:
                proof = hmac.new(self.token.encode(),
                                 f"dotii-ble-auth-v1|{self.device_id}|{host_nonce}".encode(),
                                 hashlib.sha256).hexdigest()
                reply["device_mac"] = proof
                reply["auth"] = "hmac-sha256"
                self.authenticated = True
            self.challenge = ""
        elif op == "ble_diag":
            reply.update(ble={"mtu": self.mtu, "bench": {"bytes": self.bench_bytes, "bytes_per_s": 1000}},
                         heap={"internal": {"free": 40000, "largest": 20000, "minimum": 30000},
                               "spiram": {"free": 7000000, "largest": 6000000, "minimum": 6900000}})
        elif op == "snapshot":
            if not isinstance(request.get("snapshot"), dict):
                error = "invalid_snapshot"
            elif self.want_data:
                self.snapshots.append(copy.deepcopy(request))
            self.mode = request.get("connection_mode", self.mode)
        elif op == "heartbeat":
            self.heartbeats += 1
            self.mode = request.get("connection_mode", self.mode)
        else:
            error = "unsupported_transport" if op in ("image", "provision") else "unknown_operation"
        reply["ok"] = error is None
        if error:
            reply["error"] = error
        # Minimal reply on unauthenticated / failed auth (mirrors connectivity.c).
        minimal = error is not None and (error == "unauthenticated" or op == "auth" or
                                         (not self.authenticated and op not in ("hello", "ble_diag")))
        if not minimal:
            reply.update(transport="ble", want_data=self.want_data, wifi=False, wifi_bridge=False,
                         mode=self.mode, ssid="Studio", uptime=1, free_internal=40000)
        self.last_reply = dict(reply)
        return reply

    def status(self) -> bytes:
        return json.dumps({"v": 1, "name": "Dotii", "firmware": "1.3-test", "provisioned": True,
                           "wifi": False, "bridge": "x", "sync": 1}).encode()


class FakeBleakClient:
    """Enough of bleak.BleakClient for BleSyncWorker, backed by FakeDotiiFirmware."""

    firmware: FakeDotiiFirmware
    instances: list["FakeBleakClient"] = []
    has_data_characteristics = True

    def __init__(self, address: Any, disconnected_callback: Callable[[Any], None] | None = None, **kwargs: Any):
        self.address = address
        self.kwargs = kwargs
        self.disconnected_callback = disconnected_callback
        self.is_connected = False
        self.mtu_size = self.firmware.mtu
        has_data = self.has_data_characteristics
        rx = SimpleNamespace(max_write_without_response_size=self.firmware.mtu - 3)
        self.services = SimpleNamespace(
            get_characteristic=lambda uuid: (rx if uuid == DATA_RX else SimpleNamespace()) if has_data else None)
        type(self).instances.append(self)

    async def connect(self) -> None:
        self.is_connected = True
        self.firmware.authenticated = False

    async def disconnect(self) -> None:
        if self.is_connected:
            self.is_connected = False
            if self.disconnected_callback is not None:
                self.disconnected_callback(self)

    async def start_notify(self, uuid: str, callback: Callable[[Any, bytearray], None]) -> None:
        assert uuid == DATA_TX
        self.firmware.attach(callback)

    async def write_gatt_char(self, uuid: str, data: bytes, response: bool = False) -> None:
        assert uuid == DATA_RX and self.is_connected
        await self.firmware.write(bytes(data), response)

    async def read_gatt_char(self, uuid: str) -> bytearray:
        assert uuid == STATUS
        return bytearray(self.firmware.status())
