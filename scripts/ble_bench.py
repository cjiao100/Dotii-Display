#!/usr/bin/env python3
"""Dotii BLE data-channel bench — run on the Mac next to the board.

Measures the 7b4e0005/7b4e0006 data channel with bleak 3.x on CoreBluetooth:
negotiated ATT MTU, write-with-response vs write-without-response under
several credit windows, Mac-side and device-side throughput, link
parameters (conn interval/latency/timeout, PHY, DLE, encryption/bond) and the
device heap (INTERNAL / SPIRAM free, largest block, minimum free).

Nothing is written to flash or NVS: BENCH packets are counted and dropped by
the firmware and ble_diag is read-only.

Authentication (firmware >= feat/ble-sync hardening):
  * hello is always allowed; the bench then authenticates with the same
    mutual HMAC as the management center (mac + host_nonce, device_mac
    checked with hmac.compare_digest).
  * A bound device only answers ble_diag after auth, so device-side metrics
    need --token-file. Without it the bench still measures Mac-side
    throughput and says what is missing.
  * An unbound device allows ble_diag before auth.

Usage (repository root, bridge virtualenv with bleak):
    .codex/venv/bin/python scripts/ble_bench.py --bytes 65536
    .codex/venv/bin/python scripts/ble_bench.py --token-file "$HOME/Library/Application Support/Dotii/bridge-token" \\
        --bytes 65536 --json .codex/ble_bench.json [--snapshot]

The token file is read but never printed, logged or written to the JSON.
Exit codes: 0 ok, 2 no data channel, 3 encryption insufficient,
4 device impersonation, 5 hello unanswered (after one retry).
macOS asks for Bluetooth permission for the terminal on first use, and the
board requests pairing (Just Works) right after connecting.
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
    DATA_RX_UUID, DATA_TX_UUID, SERVICE_UUID, STATUS_UUID, AsyncDtuClient, BleSyncError, ble_hello,
    ble_mutual_auth, wait_link_ready,
)
from dtu_protocol import DeviceError, DtuSession  # noqa: E402

ENCRYPTION_HINT = (
    "BLE encryption is required for the data channel but the link is not encrypted.\n"
    "  * Look for a macOS pairing prompt for \"Dotii\" and accept it, then run the bench again.\n"
    "  * If no prompt appears, open System Settings > Bluetooth, remove (Forget) \"Dotii\" if listed,\n"
    "    and run again. The board deletes its stale bond automatically when the Mac re-pairs.\n"
    "  * Still failing: power-cycle the board; as a last resort use Dotii Settings > Reset provisioning\n"
    "    (clears Wi-Fi, token and bonds; the board must be provisioned again)."
)
TOKEN_HINT = (
    "Device is bound: device-side metrics (link params, heap, device B/s, packet loss) need auth.\n"
    "  Re-run with --token-file \"$HOME/Library/Application Support/Dotii/bridge-token\"\n"
    "  (the management center's bridge token; it is read locally and never printed or saved)."
)


def is_encryption_error(error: BaseException) -> bool:
    text = str(error)
    return any(marker in text for marker in (
        "Encryption is insufficient", "CBATTErrorDomain Code=15",
        "Authentication is insufficient", "CBATTErrorDomain Code=5",
    ))


def read_token(path: str | None) -> str:
    if not path:
        return ""
    try:
        token = Path(path).expanduser().read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise SystemExit(f"cannot read --token-file: {type(error).__name__}") from None
    if not 16 <= len(token) <= 64:
        raise SystemExit("--token-file does not contain a bridge token (expected 16-64 characters)")
    return token


def heap_line(heap: dict[str, Any]) -> str:
    parts = []
    for region in ("internal", "spiram"):
        item = heap.get(region) or {}
        parts.append(f"{region}: free={item.get('free')} largest={item.get('largest')} min={item.get('minimum')}")
    return " | ".join(parts)


LINK_KEYS = ("mtu", "preferred_mtu", "conn_interval_ms", "conn_latency", "supervision_timeout_ms", "encrypted",
             "bonded", "key_size", "tx_phy", "rx_phy", "dle_tx_octets", "dle_tx_time", "dle_rx_octets",
             "dle_rx_time", "dle_request_rc", "conn_update_rc", "phy_request_rc", "mtu_request_rc",
             "security_rc", "security_requests", "enc_status", "enc_changes", "enc_failures",
             "repeat_pairings", "bond_resets", "credits_sent", "credit_flushes", "credit_every")
RC_KEYS = ("dle_request_rc", "conn_update_rc", "phy_request_rc", "mtu_request_rc", "security_rc", "enc_status")


def link_line(ble: dict[str, Any]) -> str:
    return " ".join(f"{key}={ble.get(key)}" for key in LINK_KEYS if key in ble)


def nonzero_return_codes(ble: dict[str, Any]) -> dict[str, Any]:
    return {key: ble[key] for key in RC_KEYS if key in ble and ble[key] not in (0, None)}


async def authenticate(rpc: AsyncDtuClient, token: str) -> dict[str, Any]:
    """hello, then mutual auth when bound and a token is available.

    Returns a JSON-safe summary (never the token): bound, authenticated,
    diag_allowed, device_id, firmware, error, note.
    """
    hello = await ble_hello(rpc)
    device_id = str(hello.get("device_id") or "")
    summary: dict[str, Any] = {
        "device_id": device_id, "firmware": hello.get("firmware"), "bound": bool(hello.get("bound")),
        "authenticated": False, "diag_allowed": False, "error": None, "note": "",
    }
    if hello.get("product") != "Dotii" or not device_id:
        summary["error"] = "unsupported_device"
        return summary
    if not summary["bound"]:
        summary["diag_allowed"] = True
        summary["note"] = "device not bound: ble_diag allowed before auth" + ("; token unused" if token else "")
        return summary
    if not token:
        summary["note"] = TOKEN_HINT
        return summary
    started = time.perf_counter()
    try:
        await ble_mutual_auth(rpc, token, device_id, str(hello.get("challenge") or ""))
    except DeviceError as error:
        summary["error"] = str(error)
        summary["note"] = "auth refused by the device (wrong token file or device bound to another center)"
        return summary
    except BleSyncError as error:
        summary["error"] = str(error)
        summary["note"] = "device could not prove it holds the bound token; not trusting it"
        return summary
    summary.update(authenticated=True, diag_allowed=True, auth_ms=round((time.perf_counter() - started) * 1000, 1))
    return summary


async def find_address(name: str, timeout: float) -> str:
    from bleak import BleakScanner

    device = await BleakScanner.find_device_by_filter(
        lambda dev, adv: (dev.name or adv.local_name or "").startswith(name)
        or SERVICE_UUID in [uuid.lower() for uuid in (adv.service_uuids or [])],
        timeout=timeout,
    )
    if device is None:
        raise SystemExit(f"no BLE device named {name!r} or advertising the Dotii service found")
    return device.address


async def bench_once(rpc: AsyncDtuClient, link: BleLink, chunk: int, total: int, with_response: bool,
                     window_packets: int, diag_allowed: bool) -> dict[str, Any]:
    link.with_response = with_response
    link.credits.window = chunk * window_packets
    await link.reset(bench=True)
    started = time.perf_counter()
    await link.send_stream(b"\xa5" * total, kind=PKT_BENCH)
    if not with_response:
        await link.drain(timeout=10)
    elapsed = time.perf_counter() - started
    bench: dict[str, Any] = {}
    heap = None
    if diag_allowed:
        diag = await rpc.call("ble_diag")
        ble = diag.get("ble") or {}
        bench = ble.get("bench") or {}
        bench["credit_every"] = ble.get("credit_every")
        heap = diag.get("heap")
    await link.reset()
    gaps = bench.get("gaps")
    return {
        "mode": "write-with-response" if with_response else "write-without-response",
        "window_packets": None if with_response else window_packets,
        "bytes": total,
        "mac_seconds": round(elapsed, 3),
        "mac_bytes_per_s": int(total / elapsed) if elapsed else 0,
        "device_bytes": bench.get("bytes"),
        "device_gaps": gaps,
        "device_bytes_per_s": bench.get("bytes_per_s"),
        "lost": None if gaps is None else (gaps != 0 or bench.get("bytes") != total),
        "mac_naks": link.naks,
        "device_credit_every": bench.get("credit_every"),
        "heap": heap,
    }


async def snapshot_check(rpc: AsyncDtuClient) -> dict[str, Any]:
    """Compressed snapshot over the already authenticated session."""
    snapshot = {"generated_at_epoch": int(time.time() * 1000),
                "codex": {"task": {"title": "BLE bench", "last_user_message": "蓝牙同步测试 " * 60}, "tasks": []}}
    epoch = int(time.time())
    capped, size = cap_snapshot_for_ble(snapshot, {"id": rpc.session.seq + 1, "op": "snapshot", "epoch": epoch})
    started = time.perf_counter()
    reply = await rpc.call("snapshot", compressed=True, snapshot=capped, epoch=epoch)
    return {"ok": True, "snapshot_bytes": size, "snapshot_rtt_ms": round((time.perf_counter() - started) * 1000, 1),
            "want_data": reply.get("want_data"), "transport": reply.get("transport")}


async def subscribe(client: Any, link: BleLink, retry_wait: float) -> bool:
    """start_notify; one retry after the board's own security request had time to pair."""
    for attempt in range(2):
        try:
            await client.start_notify(DATA_TX_UUID, link.on_notify)
            return True
        except Exception as error:  # bleak raises backend-specific errors
            if not is_encryption_error(error):
                raise
            if attempt == 0:
                print(f"data channel not encrypted yet; waiting {retry_wait:.0f}s for pairing ...")
                await asyncio.sleep(retry_wait)
    print(ENCRYPTION_HINT)
    return False


async def main(args: argparse.Namespace) -> int:
    from bleak import BleakClient

    token = read_token(args.token_file)
    address = args.address or await find_address(args.name, args.scan_timeout)
    result: dict[str, Any] = {"address": address, "runs": []}
    exit_code = 0
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
        rpc = AsyncDtuClient(link, DtuSession(on_event=lambda item: print("event:", item.get("event"))), timeout=10)
        if not await subscribe(client, link, args.pair_wait):
            result["error"] = "encryption_insufficient"
            exit_code = 3
        else:
            ready = await wait_link_ready(lambda: client.read_gatt_char(STATUS_UUID), timeout=args.ready_timeout)
            result["ble_ready"] = ready
            if ready is False:
                print(f"device did not report an encrypted, subscribed link within {args.ready_timeout:.0f}s; "
                      "trying hello anyway")
            await link.reset()
            await asyncio.sleep(args.settle)  # firmware tunes the link ~1 s after connect
            try:
                auth = await authenticate(rpc, token)
            except BleSyncError as error:
                result["error"] = f"hello_{error}"
                print(f"hello failed twice ({error}); the board did not answer on the data channel")
                if args.json:
                    Path(args.json).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
                return 5
            result["auth"] = auth
            print(f"device {auth['device_id']} bound={auth['bound']} authenticated={auth['authenticated']}"
                  + (f" error={auth['error']}" if auth["error"] else ""))
            if auth["note"]:
                print(auth["note"])
            if auth["error"] == "device_impersonation":
                exit_code = 4
            else:
                if auth["diag_allowed"]:
                    diag = await rpc.call("ble_diag")
                    result["link"], result["heap_before"] = diag.get("ble"), diag.get("heap")
                    result["nonzero_rc"] = nonzero_return_codes(diag.get("ble") or {})
                    print("link:", link_line(diag.get("ble") or {}))
                    print("heap:", heap_line(diag.get("heap") or {}))
                    if result["nonzero_rc"]:
                        print("non-zero return codes:", result["nonzero_rc"])
                modes = [mode.strip() for mode in args.modes.split(",") if mode.strip()]
                windows = [int(value) for value in args.windows.split(",") if value.strip()]
                plan = [(mode == "wr", window) for mode in modes for window in ([0] if mode == "wr" else windows)]
                print(f"{'mode':<24}{'window':>7}{'mac B/s':>10}{'dev B/s':>10}{'gaps':>6}{'lost':>6}")
                for with_response, window in plan:
                    try:
                        run = await bench_once(rpc, link, chunk, args.bytes, with_response, window or 8,
                                               auth["diag_allowed"])
                    except BleLinkError as error:
                        run = {"mode": "wr" if with_response else "wwr", "window_packets": window, "error": str(error)}
                        await link.reset()
                        print(f"{run['mode']:<24}{window:>7}  failed: {error}")
                    else:
                        print(f"{run['mode']:<24}{str(run['window_packets'] or '-'):>7}{run['mac_bytes_per_s']:>10}"
                              f"{str(run['device_bytes_per_s']):>10}{str(run['device_gaps']):>6}{str(run['lost']):>6}")
                    result["runs"].append(run)
                if auth["diag_allowed"]:
                    diag = await rpc.call("ble_diag")
                    result["heap_after"], result["counters"] = diag.get("heap"), diag.get("ble")
                    print("heap after:", heap_line(diag.get("heap") or {}))
                if args.snapshot:
                    if auth["authenticated"]:
                        result["snapshot"] = await snapshot_check(rpc)
                        print("snapshot:", result["snapshot"])
                    else:
                        print("--snapshot needs an authenticated session (bound device + --token-file)")
    if args.json:
        Path(args.json).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return exit_code


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--address", help="CoreBluetooth UUID of the board (skip scanning)")
    parser.add_argument("--name", default="Dotii", help="advertised name prefix to scan for")
    parser.add_argument("--scan-timeout", type=float, default=10.0)
    parser.add_argument("--bytes", type=int, default=32 * 1024, help="payload bytes per run")
    parser.add_argument("--modes", default="wwr,wr", help="wwr (write without response), wr (with response)")
    parser.add_argument("--windows", default="2,4,8,16", help="credit windows in packets for wwr")
    parser.add_argument("--settle", type=float, default=2.0, help="seconds to wait for link tuning")
    parser.add_argument("--pair-wait", type=float, default=8.0, help="seconds to wait for pairing before retrying")
    parser.add_argument("--ready-timeout", type=float, default=8.0,
                        help="seconds to wait for STATUS ble_ready (encrypted + subscribed) before hello")
    parser.add_argument("--token-file", help="file containing the bound bridge token (never printed)")
    parser.add_argument("--snapshot", action="store_true", help="also send a compressed snapshot (needs auth)")
    parser.add_argument("--json", help="write the result (no token) to this file")
    return parser.parse_args(argv)


if __name__ == "__main__":
    try:
        import bleak  # noqa: F401
    except ImportError:
        sys.exit("bleak is missing: .codex/venv/bin/pip install 'bleak>=3.0.2,<4'")
    sys.exit(asyncio.run(main(parse_args())))
