#!/usr/bin/env python3
"""Dotii BLE data-channel bench (phase 0) — run on the Mac next to the board.

Measures the 7b4e0005/7b4e0006 data channel with bleak 3.x on CoreBluetooth:
negotiated ATT MTU, write-with-response vs write-without-response under
several credit windows, Mac-side and device-side throughput, link
parameters (conn interval/latency/timeout, PHY, DLE, encryption) and the
device heap (INTERNAL / SPIRAM free, largest block, minimum free).

Nothing is written to flash or NVS: BENCH packets are counted and dropped by
the firmware, ble_diag is read-only and allowed before authentication.

Usage (from the repository root, using the bridge virtualenv that has bleak):
    .codex/venv/bin/python scripts/ble_bench.py                 # scan for "Dotii"
    .codex/venv/bin/python scripts/ble_bench.py --address <CoreBluetooth UUID>
    .codex/venv/bin/python scripts/ble_bench.py --bytes 65536 --windows 2,4,8,16 --modes wwr,wr
    .codex/venv/bin/python scripts/ble_bench.py --json bench.json   # machine-readable result
    # Optional end-to-end check of the authenticated sync path (bound device only):
    .codex/venv/bin/python scripts/ble_bench.py --token-file /path/to/file-with-bridge-token --snapshot

The token file is read but never printed or written anywhere. macOS asks for
Bluetooth permission for the terminal on first use. Encryption (pairing) is
required by the data characteristics, so the first write may show the system
pairing prompt for Dotii.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bridge"))

from ble_caps import cap_snapshot_for_ble  # noqa: E402
from ble_link import PKT_BENCH, BleLink, BleLinkError, payload_size  # noqa: E402
from bluetooth_bridge import (  # noqa: E402
    DATA_RX_UUID, DATA_TX_UUID, SERVICE_UUID, STATUS_UUID, AsyncDtuClient, ble_auth_mac,
)
from dtu_protocol import DtuSession  # noqa: E402

try:
    from bleak import BleakClient, BleakScanner
except ImportError:  # pragma: no cover - environment guidance
    sys.exit("bleak is missing: .codex/venv/bin/pip install 'bleak>=3.0.2,<4'")


def heap_line(heap: dict[str, Any]) -> str:
    parts = []
    for region in ("internal", "spiram"):
        item = heap.get(region) or {}
        parts.append(f"{region}: free={item.get('free')} largest={item.get('largest')} min={item.get('minimum')}")
    return " | ".join(parts)


def link_line(ble: dict[str, Any]) -> str:
    keys = ("mtu", "preferred_mtu", "conn_interval_ms", "conn_latency", "supervision_timeout_ms", "encrypted",
            "bonded", "key_size", "tx_phy", "rx_phy", "dle_tx_octets", "dle_tx_time", "dle_rx_octets",
            "dle_rx_time", "dle_request_rc", "conn_update_rc", "phy_request_rc", "mtu_request_rc")
    return " ".join(f"{key}={ble.get(key)}" for key in keys if key in ble)


async def find_address(name: str, timeout: float) -> str:
    device = await BleakScanner.find_device_by_filter(
        lambda dev, adv: (dev.name or adv.local_name or "").startswith(name)
        or SERVICE_UUID in [uuid.lower() for uuid in (adv.service_uuids or [])],
        timeout=timeout,
    )
    if device is None:
        raise SystemExit(f"no BLE device named {name!r} or advertising the Dotii service found")
    return device.address


async def bench_once(client: Any, chunk: int, rpc: AsyncDtuClient, link: BleLink, total: int,
                     with_response: bool, window_packets: int) -> dict[str, Any]:
    link.with_response = with_response
    link.credits.window = chunk * window_packets
    await link.reset(bench=True)
    started = time.perf_counter()
    await link.send_stream(b"\xa5" * total, kind=PKT_BENCH)
    if not with_response:
        await link.drain(timeout=10)
    elapsed = time.perf_counter() - started
    diag = await rpc.call("ble_diag")
    bench = (diag.get("ble") or {}).get("bench") or {}
    await link.reset()
    return {
        "mode": "write-with-response" if with_response else "write-without-response",
        "window_packets": None if with_response else window_packets,
        "bytes": total,
        "mac_seconds": round(elapsed, 3),
        "mac_bytes_per_s": int(total / elapsed) if elapsed else 0,
        "device_bytes": bench.get("bytes"),
        "device_gaps": bench.get("gaps"),
        "device_bytes_per_s": bench.get("bytes_per_s"),
        "heap": diag.get("heap"),
    }


async def snapshot_check(rpc: AsyncDtuClient, token: str) -> dict[str, Any]:
    hello = await rpc.call("hello")
    if not hello.get("bound"):
        return {"ok": False, "error": "not_bound"}
    started = time.perf_counter()
    await rpc.call("auth", mac=ble_auth_mac(token, hello["device_id"], hello["challenge"]))
    auth_ms = (time.perf_counter() - started) * 1000
    snapshot = {"generated_at_epoch": int(time.time() * 1000),
                "codex": {"task": {"title": "BLE bench", "last_user_message": "蓝牙同步测试 " * 60}, "tasks": []}}
    epoch = int(time.time())
    capped, size = cap_snapshot_for_ble(snapshot, {"id": rpc.session.seq + 1, "op": "snapshot", "epoch": epoch})
    started = time.perf_counter()
    reply = await rpc.call("snapshot", compressed=True, snapshot=capped, epoch=epoch)
    return {"ok": True, "auth_ms": round(auth_ms, 1), "snapshot_bytes": size,
            "snapshot_rtt_ms": round((time.perf_counter() - started) * 1000, 1),
            "want_data": reply.get("want_data"), "transport": reply.get("transport")}


async def main(args: argparse.Namespace) -> int:
    address = args.address or await find_address(args.name, args.scan_timeout)
    token = Path(args.token_file).read_text(encoding="utf-8").strip() if args.token_file else ""
    result: dict[str, Any] = {"address": address, "runs": []}
    async with BleakClient(address, timeout=20.0) as client:
        status = json.loads(bytes(await client.read_gatt_char(STATUS_UUID)).decode("utf-8"))
        rx = client.services.get_characteristic(DATA_RX_UUID)
        if rx is None or client.services.get_characteristic(DATA_TX_UUID) is None or not status.get("sync"):
            print("firmware has no BLE data channel (flash the feat/ble-sync build first)")
            return 2
        max_wwr = getattr(rx, "max_write_without_response_size", None)
        chunk = payload_size(client.mtu_size, max_wwr)
        result.update(mtu_size=client.mtu_size, max_write_without_response_size=max_wwr, chunk=chunk,
                      firmware=status.get("firmware"))
        print(f"connected {address}  firmware={status.get('firmware')}  mtu_size={client.mtu_size}  "
              f"max_wwr={max_wwr}  chunk={chunk}")
        link = BleLink(lambda packet, response: client.write_gatt_char(DATA_RX_UUID, packet, response=response),
                       chunk=chunk)
        rpc = AsyncDtuClient(link, DtuSession(on_event=lambda item: print("event:", item)), timeout=10)
        await client.start_notify(DATA_TX_UUID, link.on_notify)
        await link.reset()
        await asyncio.sleep(args.settle)  # firmware tunes the link ~1 s after connect
        diag = await rpc.call("ble_diag")
        result["link"], result["heap_before"] = diag.get("ble"), diag.get("heap")
        print("link:", link_line(diag.get("ble") or {}))
        print("heap:", heap_line(diag.get("heap") or {}))
        modes = [mode.strip() for mode in args.modes.split(",") if mode.strip()]
        windows = [int(value) for value in args.windows.split(",") if value.strip()]
        plan = [(mode == "wr", window) for mode in modes for window in ([0] if mode == "wr" else windows)]
        print(f"{'mode':<24}{'window':>7}{'mac B/s':>10}{'dev B/s':>10}{'gaps':>6}")
        for with_response, window in plan:
            try:
                run = await bench_once(client, chunk, rpc, link, args.bytes, with_response, window or 8)
            except BleLinkError as error:
                run = {"mode": "wr" if with_response else "wwr", "window_packets": window, "error": str(error)}
                await link.reset()
                print(f"{run['mode']:<24}{window:>7}  failed: {error}")
            else:
                print(f"{run['mode']:<24}{str(run['window_packets'] or '-'):>7}{run['mac_bytes_per_s']:>10}"
                      f"{str(run['device_bytes_per_s']):>10}{str(run['device_gaps']):>6}")
            result["runs"].append(run)
        diag = await rpc.call("ble_diag")
        result["heap_after"], result["counters"] = diag.get("heap"), diag.get("ble")
        print("heap after:", heap_line(diag.get("heap") or {}))
        if args.snapshot:
            if not token:
                print("--snapshot needs --token-file")
            else:
                result["snapshot"] = await snapshot_check(rpc, token)
                print("snapshot:", result["snapshot"])
    if args.json:
        Path(args.json).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--address", help="CoreBluetooth UUID of the board (skip scanning)")
    parser.add_argument("--name", default="Dotii", help="advertised name prefix to scan for")
    parser.add_argument("--scan-timeout", type=float, default=10.0)
    parser.add_argument("--bytes", type=int, default=32 * 1024, help="payload bytes per run")
    parser.add_argument("--modes", default="wwr,wr", help="wwr (write without response), wr (with response)")
    parser.add_argument("--windows", default="2,4,8,16", help="credit windows in packets for wwr")
    parser.add_argument("--settle", type=float, default=2.0, help="seconds to wait for link tuning")
    parser.add_argument("--token-file", help="file containing the bound bridge token (never printed)")
    parser.add_argument("--snapshot", action="store_true", help="also run hello/auth/compressed snapshot")
    parser.add_argument("--json", help="write the result (no token) to this file")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(asyncio.run(main(parse_args())))
