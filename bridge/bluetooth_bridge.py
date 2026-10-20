"""BLE provisioning, recovery and (phase 1) text data-sync channel behind the platform boundary."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import importlib
import json
import re
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path
from typing import Any, Callable

from ble_caps import cap_snapshot_for_ble, snapshot_digest
from ble_link import BleLink, BleLinkError, payload_size
from dtu_protocol import DeviceError, DtuSession, encode_compressed_frame, encode_frame, handle_bambu_event
from platforms import PlatformAdapter, current_platform
from runtime_paths import is_frozen


SERVICE_UUID = "7b4e0001-4db4-4c72-a729-ea5187241a43"
COMMAND_UUID = "7b4e0002-4db4-4c72-a729-ea5187241a43"
RESPONSE_UUID = "7b4e0003-4db4-4c72-a729-ea5187241a43"
STATUS_UUID = "7b4e0004-4db4-4c72-a729-ea5187241a43"
DATA_RX_UUID = "7b4e0005-4db4-4c72-a729-ea5187241a43"
DATA_TX_UUID = "7b4e0006-4db4-4c72-a729-ea5187241a43"
# Keep in sync with bridge/requirements.txt and packaging/*requirements*.txt.
BLEAK_REQUIREMENT = "bleak>=3.0.2,<4"
MAX_CONFIG_BYTES = 1024
BLUETOOTH_AVAILABILITY_STATES = {"denied", "bluetooth_off", "unavailable"}
COREBLUETOOTH_IDENTIFIER_PATTERN = re.compile(
    r"\b[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\b"
)


def _is_stale_windows_pairing_error(error: BaseException) -> bool:
    message = str(error).casefold()
    return "could not start notify" in message and "unreachable" in message


def _bluetooth_error(error: Exception) -> tuple[str, str]:
    """Return a stable availability state and a user-facing diagnostic."""
    message = str(error)
    if "peer removed pairing information" in message.casefold():
        return (
            "stale_pairing",
            "Dotii 已重置配对，但这台 Mac 仍保留旧记录；请在系统设置 > 蓝牙中忽略 Dotii，然后重新扫描",
        )
    if "device with address" in message.casefold() and "was not found" in message.casefold():
        return "not_found", "暂时无法重新连接已识别的 Dotii，请点击“扫描 Dotii”重试"
    if isinstance(error, TimeoutError):
        return "timeout", "等待蓝牙连接或系统配对确认超时，请确认 Dotii 在附近后重试"
    reason = str(getattr(getattr(error, "reason", None), "name", "")).upper()
    if reason == "POWERED_OFF":
        return "bluetooth_off", "蓝牙已关闭，请先在系统设置中打开蓝牙"
    if reason in {"DENIED_BY_USER", "DENIED_BY_SYSTEM", "DENIED_BY_UNKNOWN"}:
        return (
            "denied",
            "蓝牙权限已被拒绝，请在系统设置 > 隐私与安全性 > 蓝牙中允许 Dotii 管理中心",
        )
    if reason in {"NO_BLUETOOTH", "NO_BLE_CENTRAL_ROLE"}:
        return "unavailable", "当前 Mac 没有可用的低功耗蓝牙功能"
    if reason == "UNKNOWN":
        return "unavailable", "macOS 暂时无法使用蓝牙，请检查系统蓝牙与隐私设置"
    public_message = COREBLUETOOTH_IDENTIFIER_PATTERN.sub("本机蓝牙标识", message)
    return "error", public_message[:170] or "未知蓝牙错误"


def _hidden_creation_flags() -> int:
    return current_platform().hidden_creation_flags()


def _configuration_payload(
    *,
    ssid: Any,
    password: Any,
    bridge_url: str,
    bridge_token: str,
    current_token: Any = "",
) -> bytes:
    if not isinstance(ssid, str) or not 1 <= len(ssid.encode("utf-8")) <= 32:
        raise ValueError("Wi-Fi 名称必须为 1–32 字节")
    if not isinstance(password, str) or len(password.encode("utf-8")) > 64:
        raise ValueError("Wi-Fi 密码不能超过 64 字节")
    if not isinstance(bridge_url, str) or not bridge_url.startswith(("http://", "https://")):
        raise ValueError("管理中心地址无效")
    if len(bridge_url.encode("utf-8")) >= 256:
        raise ValueError("管理中心地址过长")
    if not isinstance(bridge_token, str) or not 16 <= len(bridge_token) <= 64:
        raise ValueError("设备访问令牌无效")
    if not isinstance(current_token, str):
        raise ValueError("当前设备令牌无效")
    if current_token and not 16 <= len(current_token) <= 64:
        raise ValueError("当前设备令牌无效")
    body = json.dumps(
        {
            "v": 1,
            "op": "configure",
            "auth": current_token or bridge_token,
            "ssid": ssid,
            "password": password,
            "bridge_url": bridge_url,
            "bridge_token": bridge_token,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(body) > MAX_CONFIG_BYTES:
        raise ValueError("蓝牙配置数据过长")
    return body


def _configuration_packets(body: bytes, chunk_size: int = 180) -> list[bytes]:
    if not 1 <= len(body) <= MAX_CONFIG_BYTES or not 1 <= chunk_size <= 240:
        raise ValueError("invalid Bluetooth packet size")
    checksum = zlib.crc32(body) & 0xFFFFFFFF
    packets = [bytes((1, len(body) & 0xFF, len(body) >> 8)) + checksum.to_bytes(4, "little")]
    packets.extend(bytes((2,)) + body[offset : offset + chunk_size]
                   for offset in range(0, len(body), chunk_size))
    packets.append(bytes((3,)))
    return packets


class BluetoothBridge:
    def __init__(
        self,
        runtime_folder: Path,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        platform_adapter: PlatformAdapter | None = None,
    ) -> None:
        self.runtime_folder = runtime_folder
        self.dependencies = runtime_folder / "bluetooth-deps"
        self.settings_path = runtime_folder / "bluetooth.json"
        self.runner = runner
        self.platform = platform_adapter or current_platform()
        self.lock = threading.RLock()
        self.operation_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.monitor: threading.Thread | None = None
        self.devices: list[dict[str, Any]] = []
        self._ble_devices: dict[str, Any] = {}
        self.last_address = self._load_last_address()
        self.device_status: dict[str, Any] = {}
        self.device_connected = False
        self.connection_state = "idle"
        self.connection_detail = ""
        self.operation_state = "idle"
        self.operation_detail = "尚未扫描 Dotii"
        self.operation_log = ""
        self.updated_at_epoch = 0
        self.permission_state = "unknown" if self.platform.name == "macos" else "not_applicable"
        self.sync: BleSyncWorker | None = None
        self._sync_pause = 0
        self._add_dependency_path()

    @property
    def sync_supported(self) -> bool:
        # Phase 1 is validated against CoreBluetooth (bleak 3.0.2) only.
        return self.platform.bluetooth_available and self.platform.name == "macos"

    def attach_sync(self, server: Any, *, start: bool = True) -> None:
        """Create the persistent BLE data-sync worker once the server exists."""
        if self.sync is None:
            self.sync = BleSyncWorker(self, server)
        if start and self.sync_supported:
            self.sync.start()

    def sync_paused(self) -> bool:
        with self.lock:
            return self._sync_pause > 0

    @contextlib.contextmanager
    def _exclusive(self, timeout: float = 20.0):
        """Preempt the sync session for scan/configure and own the radio."""
        with self.lock:
            self._sync_pause += 1
        try:
            if self.sync is not None:
                self.sync.poke()
            if not self.operation_lock.acquire(timeout=timeout):
                raise TimeoutError("蓝牙同步会话仍在占用连接")
            try:
                yield
            finally:
                self.operation_lock.release()
        finally:
            with self.lock:
                self._sync_pause -= 1
            if self.sync is not None:
                self.sync.poke()

    def _record_sync_status(self, status: dict[str, Any]) -> None:
        with self.lock:
            self.permission_state = "allowed"
            self.device_status = status
            self.device_connected = True
            self.connection_state = "connected"
            self.connection_detail = ""

    def _add_dependency_path(self) -> None:
        path = str(self.dependencies)
        if path not in sys.path:
            sys.path.insert(0, path)
        importlib.invalidate_caches()

    def _load_last_address(self) -> str:
        try:
            payload = json.loads(self.settings_path.read_text(encoding="utf-8"))
            address = payload.get("address") if isinstance(payload, dict) else ""
            return str(address)[:80] if isinstance(address, str) else ""
        except (OSError, ValueError, json.JSONDecodeError):
            return ""

    def _save_last_address(self, address: str) -> None:
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.settings_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps({"address": address}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        temporary.replace(self.settings_path)

    def _bleak(self) -> tuple[Any, Any]:
        self._add_dependency_path()
        from bleak import BleakClient, BleakScanner  # type: ignore[import-not-found]
        return BleakClient, BleakScanner

    def dependency_ready(self) -> bool:
        if not self.platform.bluetooth_available:
            return False
        try:
            self._bleak()
            return True
        except (ImportError, OSError):
            return False

    def start(self) -> None:
        if not self.platform.bluetooth_available:
            return
        if self.monitor is None or not self.monitor.is_alive():
            self.monitor = threading.Thread(target=self._monitor, name="dotii-ble-monitor", daemon=True)
            self.monitor.start()
        if self.platform.name == "macos" and not self.last_address and self.dependency_ready():
            if self._start_worker(self._scan, name="dotii-ble-startup-scan"):
                with self.lock:
                    self.operation_detail = "正在自动识别附近的 Dotii"

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "available": self.platform.bluetooth_available,
                "dependency_ready": self.dependency_ready(),
                "permission_state": self.permission_state,
                "devices": [dict(item) for item in self.devices],
                "last_address": self.last_address,
                "device_status": dict(self.device_status),
                "device_connected": self.device_connected,
                "connection_state": self.connection_state,
                "connection_detail": self.connection_detail,
                "operation_state": self.operation_state,
                "operation_detail": self.operation_detail,
                "operation_log": self.operation_log,
                "updated_at_epoch": self.updated_at_epoch,
                "sync_supported": self.sync_supported,
                "sync": self.sync.status() if self.sync is not None else {"state": "disabled", "detail": ""},
            }

    def _start_worker(self, target: Callable[..., None], *arguments: Any, name: str) -> bool:
        with self.lock:
            if self.worker is not None and self.worker.is_alive():
                return False
            self.operation_state = "running"
            self.operation_detail = "正在处理蓝牙连接"
            self.operation_log = ""
            self.updated_at_epoch = int(time.time())
            self.worker = threading.Thread(target=target, args=arguments, name=name, daemon=True)
            self.worker.start()
            return True

    def start_install(self) -> bool:
        if not self.platform.bluetooth_available:
            raise OSError("当前平台尚未支持 Dotii 蓝牙配网")
        if is_frozen():
            if self.dependency_ready():
                return False
            raise OSError("当前安装包缺少蓝牙组件，请重新安装 Dotii 管理中心")
        return self._start_worker(self._install, name="dotii-ble-installer")

    def _install(self) -> None:
        state = "error"
        detail = "蓝牙组件安装失败"
        output = ""
        try:
            self.dependencies.mkdir(parents=True, exist_ok=True)
            result = self.runner(
                [sys.executable, "-m", "pip", "install", "--target", str(self.dependencies),
                 "--upgrade", BLEAK_REQUIREMENT],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", timeout=600,
                creationflags=_hidden_creation_flags(), check=False,
            )
            output = result.stdout or ""
            if result.returncode != 0:
                raise OSError(f"pip 退出码 {result.returncode}")
            self._add_dependency_path()
            if not self.dependency_ready():
                raise OSError("安装结束，但蓝牙组件仍无法加载")
            state = "success"
            detail = "蓝牙组件已就绪"
        except (OSError, subprocess.SubprocessError) as error:
            detail = f"蓝牙组件安装失败：{error}"
        finally:
            lines = [line.strip() for line in output.replace("\r", "").split("\n") if line.strip()]
            with self.lock:
                self.operation_state = state
                self.operation_detail = detail[:240]
                self.operation_log = "\n".join(lines[-30:])[-5000:]
                self.updated_at_epoch = int(time.time())

    def start_scan(self) -> bool:
        if not self.platform.bluetooth_available:
            raise ValueError("当前平台尚未支持 Dotii 蓝牙配网")
        if not self.dependency_ready():
            raise ValueError("请先安装蓝牙连接组件")
        return self._start_worker(self._scan, name="dotii-ble-scan")

    async def _discover(self) -> list[dict[str, Any]]:
        _, scanner = self._bleak()
        scan_timeout = 10.0 if self.platform.name == "macos" else 5.0
        discovered = await scanner.discover(timeout=scan_timeout, return_adv=True)
        output: list[dict[str, Any]] = []
        native_devices: dict[str, Any] = {}
        pairs = discovered.values() if isinstance(discovered, dict) else ((item, None) for item in discovered)
        for device, advertisement in pairs:
            name = str(getattr(advertisement, "local_name", "") or getattr(device, "name", "") or "")
            services = [str(value).lower() for value in getattr(advertisement, "service_uuids", [])]
            if name.lower().startswith("dotii") or SERVICE_UUID in services:
                address = str(device.address)[:80]
                native_devices[address] = device
                output.append({
                    "address": address,
                    "name": name[:80] or "Dotii",
                    "rssi": int(getattr(advertisement, "rssi", -127)),
                })
        output.sort(key=lambda item: item["rssi"], reverse=True)
        with self.lock:
            self._ble_devices = native_devices
        return output

    async def _discover_with_status(
        self,
    ) -> tuple[list[dict[str, Any]], str, dict[str, Any], Exception | None]:
        """Discover and connect on one event loop for CoreBluetooth objects."""
        devices = await self._discover()
        known_addresses = {item["address"] for item in devices}
        with self.lock:
            remembered_address = self.last_address
        selected_address = remembered_address if remembered_address in known_addresses else (
            devices[0]["address"] if devices else ""
        )
        if not selected_address:
            return devices, "", {}, None
        try:
            status = await self._read_status(selected_address)
            return devices, selected_address, status, None
        except Exception as error:  # Bleak exposes backend-specific failures.
            return devices, selected_address, {}, error

    def _scan(self) -> None:
        try:
            with self._exclusive():
                devices, selected_address, status, connection_error = asyncio.run(
                    self._discover_with_status()
                )
            with self.lock:
                if self.platform.name == "macos":
                    # CoreBluetooth BLEDevice objects belong to the discovery
                    # event loop. Persist only the stable UUID across workers.
                    self._ble_devices = {}
                self.devices = devices
                self.device_status = status
                self.device_connected = bool(status)
                self.connection_state = "connected" if status else "idle"
                self.connection_detail = ""
                if selected_address and selected_address != self.last_address:
                    self.last_address = selected_address
            scan_permission_state = "allowed"
            if connection_error is not None:
                connection_state, connection_detail = _bluetooth_error(connection_error)
                if connection_state in BLUETOOTH_AVAILABILITY_STATES:
                    scan_permission_state = connection_state
                with self.lock:
                    self.connection_state = connection_state
                    self.connection_detail = connection_detail
            if selected_address:
                self._save_last_address(selected_address)
            with self.lock:
                self.permission_state = scan_permission_state
                self.operation_state = "success"
                self.operation_detail = (
                    f"发现 {len(devices)} 台 Dotii，已读取当前设备状态"
                    if devices and self.device_connected
                    else f"发现 {len(devices)} 台 Dotii；{self.connection_detail or '状态连接暂未完成'}"
                    if devices
                    else "未发现附近的 Dotii"
                )
                self.updated_at_epoch = int(time.time())
        except Exception as error:  # BLE backends expose platform-specific exceptions.
            permission_state, detail = _bluetooth_error(error)
            with self.lock:
                self.permission_state = permission_state
                self.operation_state = "error"
                self.operation_detail = f"蓝牙扫描失败：{detail}"
                self.updated_at_epoch = int(time.time())

    def start_configure(
        self,
        *,
        address: Any,
        ssid: Any,
        password: Any,
        bridge_url: str,
        bridge_token: str,
        current_token: Any = "",
    ) -> bool:
        if not self.platform.bluetooth_available:
            raise ValueError("当前平台尚未支持 Dotii 蓝牙配网")
        if not self.dependency_ready():
            raise ValueError("请先安装蓝牙连接组件")
        if not isinstance(address, str) or not address or len(address) > 80:
            raise ValueError("请选择 Dotii")
        known = {item["address"] for item in self.devices}
        if address not in known and address != self.last_address:
            raise ValueError("请重新扫描并选择 Dotii")
        body = _configuration_payload(
            ssid=ssid,
            password=password,
            bridge_url=bridge_url,
            bridge_token=bridge_token,
            current_token=current_token,
        )
        return self._start_worker(self._configure, address, body, name="dotii-ble-configure")

    async def _configure_once(self, client_class: Any, target: Any, body: bytes) -> dict[str, Any]:
        response_event = asyncio.Event()
        response: dict[str, Any] = {}

        def notification(_: Any, data: bytearray) -> None:
            nonlocal response
            try:
                payload = json.loads(bytes(data).decode("utf-8"))
                if isinstance(payload, dict):
                    response = payload
                    if payload.get("state") == "restarting" or payload.get("ok") is False:
                        response_event.set()
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass

        # Windows requests pairing during connect. CoreBluetooth has no explicit
        # pairing API and prompts when the encrypted characteristic is accessed.
        async with client_class(
            target,
            timeout=45.0 if self.platform.name == "macos" else 30.0,
            pair=self.platform.bluetooth_pair_on_connect,
        ) as client:
            await client.start_notify(RESPONSE_UUID, notification)
            for packet in _configuration_packets(body):
                await client.write_gatt_char(COMMAND_UUID, packet, response=True)
            try:
                await asyncio.wait_for(response_event.wait(), timeout=8.0)
            except TimeoutError:
                raw = await client.read_gatt_char(RESPONSE_UUID)
                response = json.loads(bytes(raw).decode("utf-8"))
            return response

    async def _configure_async(self, address: str, body: bytes) -> dict[str, Any]:
        client_class, _ = self._bleak()
        with self.lock:
            target = address if self.platform.name == "macos" else self._ble_devices.get(address, address)

        try:
            return await self._configure_once(client_class, target, body)
        except Exception as error:
            if self.platform.name != "windows" or not _is_stale_windows_pairing_error(error):
                raise

            with self.lock:
                self.operation_detail = "检测到旧蓝牙配对，正在自动重新配对"
                self.updated_at_epoch = int(time.time())

            recovery_client = client_class(target, timeout=15.0)
            try:
                await recovery_client.unpair()
            except Exception as recovery_error:
                raise OSError(
                    f"检测到失效的 Windows 蓝牙配对，但自动清除失败：{recovery_error}"
                ) from error
            finally:
                if getattr(recovery_client, "is_connected", False):
                    await recovery_client.disconnect()

            await asyncio.sleep(0.75)
            return await self._configure_once(client_class, target, body)

    def _configure(self, address: str, body: bytes) -> None:
        try:
            with self._exclusive():
                response = asyncio.run(self._configure_async(address, body))
            if response.get("ok") is not True:
                raise OSError(f"Dotii 拒绝配置：{response.get('error', 'unknown')}" )
            self.last_address = address
            self._save_last_address(address)
            with self.lock:
                self.permission_state = "allowed"
                self.operation_state = "success"
                self.operation_detail = "配置已保存，Dotii 正在重启并连接局域网"
                self.device_connected = False
                self.connection_state = "restarting"
                self.connection_detail = "Dotii 正在重启"
                self.updated_at_epoch = int(time.time())
        except Exception as error:
            permission_state, detail = _bluetooth_error(error)
            with self.lock:
                if permission_state in BLUETOOTH_AVAILABILITY_STATES:
                    self.permission_state = permission_state
                self.operation_state = "error"
                self.operation_detail = f"蓝牙配置失败：{detail}"
                self.updated_at_epoch = int(time.time())

    async def _read_status(self, address: str) -> dict[str, Any]:
        client_class, _ = self._bleak()
        with self.lock:
            target = self._ble_devices.get(address, address)
        async with client_class(target, timeout=10.0) as client:
            raw = await client.read_gatt_char(STATUS_UUID)
            payload = json.loads(bytes(raw).decode("utf-8"))
            return payload if isinstance(payload, dict) else {}

    def _monitor(self) -> None:
        first_run = True
        while first_run or not self.stop_event.wait(15):
            first_run = False
            if not self.last_address or not self.dependency_ready() or not self.operation_lock.acquire(False):
                continue
            try:
                status = asyncio.run(self._read_status(self.last_address))
                with self.lock:
                    self.permission_state = "allowed"
                    self.device_status = status
                    self.device_connected = bool(status)
                    self.connection_state = "connected" if status else "error"
                    self.connection_detail = "" if status else "设备状态响应为空"
                    if status and not any(
                        item.get("address") == self.last_address for item in self.devices
                    ):
                        self.devices.append({
                            "address": self.last_address,
                            "name": str(status.get("name") or "Dotii")[:80],
                            "rssi": None,
                            "remembered": True,
                        })
            except Exception as error:
                permission_state, detail = _bluetooth_error(error)
                with self.lock:
                    if permission_state in BLUETOOTH_AVAILABILITY_STATES:
                        self.permission_state = permission_state
                    self.device_connected = False
                    if (
                        self.connection_state != "stale_pairing"
                        or permission_state in BLUETOOTH_AVAILABILITY_STATES
                    ):
                        self.connection_state = permission_state
                        self.connection_detail = detail
                    if not any(
                        item.get("address") == self.last_address for item in self.devices
                    ):
                        self.devices.append({
                            "address": self.last_address,
                            "name": str(self.device_status.get("name") or "Dotii")[:80],
                            "rssi": None,
                            "remembered": True,
                        })
            finally:
                self.operation_lock.release()

    def stop(self) -> None:
        self.stop_event.set()
        if self.sync is not None:
            self.sync.stop()


# ---------------------------------------------------------------------------
# Persistent BLE data-sync session (phase 1: text snapshots only).
# ---------------------------------------------------------------------------

SYNC_HEARTBEAT_SECONDS = 6.0        # 5-8 s keeps the firmware 12 s window fresh
SYNC_FULL_REFRESH_SECONDS = 30.0    # resend even when unchanged
SYNC_MIN_SNAPSHOT_SECONDS = 2.0     # collector updates at ~2 s
SYNC_STATUS_SECONDS = 15.0          # same cadence as the status monitor
SYNC_STANDBY_DISCONNECT_SECONDS = 30.0
SYNC_REQUEST_TIMEOUT = 8.0
SYNC_TICK_SECONDS = 1.0             # session loop granularity
SYNC_BACKOFF_SECONDS = (2, 4, 8, 16, 30, 60)
SYNC_SAFE_ERRORS = {
    "not_bound", "binding_mismatch", "different_device", "unsupported_device",
    "firmware_update_required", "timeout", "sequence_gap", "credit_timeout",
    "disconnected", "unauthenticated", "snapshot_too_large_for_ble", "invalid_frame",
    "stale_pairing", "not_found", "bluetooth_off", "denied", "unavailable",
}
BLE_AUTH_CONTEXT = "dotii-ble-auth-v1"


def ble_auth_mac(token: str, device_id: str, challenge: str) -> str:
    """HMAC-SHA256 proof of the bound bridge token (connectivity.c)."""
    message = f"{BLE_AUTH_CONTEXT}|{device_id}|{challenge}".encode("utf-8")
    return hmac.new(token.encode("utf-8"), message, hashlib.sha256).hexdigest()


class BleSyncError(OSError):
    """A stable, user-safe sync failure code."""


class AsyncDtuClient:
    """Request/reply over a BleLink on one asyncio loop."""

    def __init__(self, link: BleLink, session: DtuSession, *, timeout: float = SYNC_REQUEST_TIMEOUT):
        self.link = link
        self.session = session
        self.timeout = timeout
        self.pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        link.on_frames = self._on_frames

    def _on_frames(self, items: list[dict[str, Any]]) -> None:
        for item in items:
            if "event" in item:
                if self.session.on_event is not None:
                    self.session.on_event(item)
                continue
            if item.get("id") == 0 and item.get("ok") is False:
                # The firmware could not decode a frame; fail what is waiting.
                for future in self.pending.values():
                    if not future.done():
                        future.set_exception(DeviceError(str(item.get("error", "invalid_frame"))))
                continue
            future = self.pending.get(item.get("id"))
            if future is not None and not future.done():
                future.set_result(item)

    async def call(self, op: str, *, compressed: bool = False, **payload: Any) -> dict[str, Any]:
        seq, packet = self.session.request(op, include_token=False, **payload)
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self.pending[seq] = future
        try:
            frame = encode_compressed_frame(packet) if compressed else encode_frame(packet)
            await self.link.send_stream(frame)
            try:
                reply = await asyncio.wait_for(future, self.timeout)
            except (TimeoutError, asyncio.TimeoutError) as error:
                raise BleSyncError("timeout") from error
        finally:
            self.pending.pop(seq, None)
        return DtuSession.check(reply)


class BleSyncWorker:
    """One background thread running one asyncio loop for the BLE session.

    It holds BluetoothBridge.operation_lock while connected, so the 15 s
    status monitor skips its own connection and scan/configure preempt the
    session through BluetoothBridge._exclusive().
    """

    def __init__(self, bridge: "BluetoothBridge", server: Any):
        self.bridge = bridge
        self.server = server
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.wake: asyncio.Event | None = None
        self.want_data = False
        self.force_snapshot = True
        self.connected = False
        self.state: dict[str, Any] = {
            "state": "idle", "detail": "", "device_id": "", "firmware": "", "last_sync": 0,
            "last_heartbeat": 0, "want_data": False, "mtu": 0, "chunk": 0, "last_snapshot_bytes": 0,
            "last_rtt_ms": 0, "bytes_sent": 0, "reconnects": 0, "wifi": False, "wifi_bridge": False,
            "device_mode": "", "usb_active": False,
        }

    # -- thread control --
    def start(self) -> None:
        if self.thread is not None and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._thread_main, name="dotii-ble-sync", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.poke()
        if self.thread is not None:
            self.thread.join(timeout=8)

    def poke(self) -> None:
        loop, wake = self.loop, self.wake
        if loop is not None and wake is not None and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(wake.set)
            except RuntimeError:
                pass

    def status(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.state)

    def _update(self, **values: Any) -> None:
        with self.lock:
            self.state.update(values)

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._main())
        except Exception:  # never let the worker thread die silently with the lock held
            self._update(state="error", detail="ble_connection_failed")

    # -- policy --
    def _usb_live(self) -> bool:
        usb = self.server.usb.snapshot()
        return usb.get("state") == "connected" and time.time() - float(usb.get("last_sync") or 0) < 12

    def _wifi_live(self) -> bool:
        device_id = self.server.connections.read()["device_id"]
        return bool(device_id) and time.time() - float(self.server.wifi_data_seen.get(device_id, 0)) < 20

    def desired(self) -> tuple[bool, str]:
        """Whether a BLE session should exist now. Auto: USB > Wi-Fi > BLE."""
        if not self.bridge.sync_supported:
            return False, "unsupported_platform"
        if not self.bridge.dependency_ready():
            return False, "bluetooth_component_missing"
        if not self.bridge.last_address:
            return False, "no_device"
        mode = self.server.connections.read()["mode"]
        if mode not in ("auto", "ble"):
            return False, "mode_disabled"
        if self.bridge.sync_paused():
            return False, "paused"
        if mode == "auto" and self._usb_live():
            return False, "usb_active"
        if mode == "auto" and not self.connected and self._wifi_live():
            return False, "wifi_active"
        return True, ""

    async def _sleep(self, seconds: float) -> None:
        if self.wake is None:
            await asyncio.sleep(seconds)
            return
        self.wake.clear()
        try:
            await asyncio.wait_for(self.wake.wait(), seconds)
        except (TimeoutError, asyncio.TimeoutError):
            pass

    async def _main(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.wake = asyncio.Event()
        failures = 0
        while not self.stop_event.is_set():
            wanted, reason = self.desired()
            if not wanted:
                self._update(state="idle", detail=reason)
                await self._sleep(2)
                continue
            if not self.bridge.operation_lock.acquire(False):
                self._update(state="waiting", detail="bluetooth_busy")
                await self._sleep(1)
                continue
            try:
                await self._session()
                failures = 0
            except Exception as error:  # bleak raises backend-specific errors
                failures += 1
                self._update(state="error", detail=self._classify(error))
            finally:
                self.connected = False
                self.bridge.operation_lock.release()
            if not self.stop_event.is_set():
                delay = SYNC_BACKOFF_SECONDS[min(failures, len(SYNC_BACKOFF_SECONDS)) - 1] if failures else 1
                await self._sleep(delay)

    def _classify(self, error: BaseException) -> str:
        code = str(error)
        if code in SYNC_SAFE_ERRORS:
            return code
        if isinstance(error, (TimeoutError, asyncio.TimeoutError)):
            return "timeout"
        state, _ = _bluetooth_error(error if isinstance(error, Exception) else Exception(code))
        if state in SYNC_SAFE_ERRORS:
            if state in BLUETOOTH_AVAILABILITY_STATES:
                with self.bridge.lock:
                    self.bridge.permission_state = state
            return state
        return "ble_connection_failed"

    # -- one connection --
    def _on_event(self, item: dict[str, Any]) -> None:
        if item.get("event") == "want_data":
            self.want_data = bool(item.get("want_data"))
            self.force_snapshot = self.force_snapshot or self.want_data
            self._update(want_data=self.want_data, device_mode=str(item.get("mode", ""))[:8])
            if self.wake is not None:
                self.wake.set()
        elif item.get("event") == "bambu_command" and self.loop is not None:
            # Off the loop: BambuService.command() may block on the network.
            self.loop.run_in_executor(None, handle_bambu_event, self.server, item)

    async def _session(self) -> None:
        client_class, _ = self.bridge._bleak()
        address = self.bridge.last_address
        loop = asyncio.get_running_loop()
        disconnected = asyncio.Event()

        def on_disconnect(_client: Any) -> None:
            loop.call_soon_threadsafe(disconnected.set)

        self._update(state="connecting", detail="")
        client = client_class(address, disconnected_callback=on_disconnect, timeout=20.0,
                              pair=self.bridge.platform.bluetooth_pair_on_connect)
        await client.connect()
        try:
            characteristic = client.services.get_characteristic(DATA_RX_UUID)
            if characteristic is None or client.services.get_characteristic(DATA_TX_UUID) is None:
                raise BleSyncError("firmware_update_required")
            chunk = payload_size(client.mtu_size,
                                 getattr(characteristic, "max_write_without_response_size", None))

            async def write(packet: bytes, response: bool) -> None:
                await client.write_gatt_char(DATA_RX_UUID, packet, response=response)

            link = BleLink(write, chunk=chunk)
            rpc = AsyncDtuClient(link, DtuSession(on_event=self._on_event))
            await client.start_notify(DATA_TX_UUID, link.on_notify)
            await link.reset()
            await self._handshake(rpc)
            self.connected = True
            with self.lock:
                self.state["reconnects"] += 1
            self._update(state="connected", detail="", mtu=int(client.mtu_size), chunk=chunk)
            await self._run(client, link, rpc, disconnected)
        finally:
            self.connected = False
            try:
                await client.disconnect()
            except Exception:
                pass

    async def _handshake(self, rpc: AsyncDtuClient) -> None:
        hello = await rpc.call("hello")
        device_id = str(hello.get("device_id") or "")
        if not device_id or hello.get("product") != "Dotii" or hello.get("protocol") != 1:
            raise BleSyncError("unsupported_device")
        settings = self.server.connections.read()
        if settings["device_id"] and settings["device_id"] != device_id:
            raise BleSyncError("different_device")
        challenge = str(hello.get("challenge") or "")
        if not hello.get("bound"):
            raise BleSyncError("not_bound")
        if not re.fullmatch(r"[0-9a-f]{32}", challenge):
            raise BleSyncError("firmware_update_required")
        try:
            reply = await rpc.call("auth", mac=ble_auth_mac(self.server.token, device_id, challenge))
        except DeviceError as error:
            raise BleSyncError(str(error) if str(error) in SYNC_SAFE_ERRORS else "binding_mismatch") from error
        if not settings["device_id"]:
            self.server.connections.write({"device_id": device_id})
        self.want_data = bool(reply.get("want_data"))
        self.force_snapshot = True
        self._update(device_id=device_id, firmware=str(hello.get("firmware", ""))[:40], want_data=self.want_data)

    def _record_reply(self, reply: dict[str, Any]) -> None:
        self.want_data = bool(reply.get("want_data"))
        self._update(want_data=self.want_data, wifi=bool(reply.get("wifi")), wifi_bridge=bool(reply.get("wifi_bridge")),
                     device_mode=str(reply.get("mode", ""))[:8], usb_active=bool(reply.get("usb_active")))

    async def _run(self, client: Any, link: BleLink, rpc: AsyncDtuClient, disconnected: asyncio.Event) -> None:
        last_digest = ""
        last_snapshot = last_send = last_status = 0.0
        standby_since: float | None = None
        link_failures = 0
        while not self.stop_event.is_set():
            if disconnected.is_set():
                raise BleSyncError("disconnected")
            wanted, reason = self.desired()
            if not wanted:
                self._update(state="idle", detail=reason)
                return
            now = time.monotonic()
            if self.want_data:
                standby_since = None
            else:
                standby_since = standby_since or now
                if now - standby_since > SYNC_STANDBY_DISCONNECT_SECONDS and (self._usb_live() or self._wifi_live()):
                    self._update(state="idle", detail="standby")
                    return
            device = self.server.connections.device()
            try:
                if self.want_data:
                    snapshot = self.server.snapshot()
                    digest = snapshot_digest(snapshot, device)
                    due = self.force_snapshot or digest != last_digest or now - last_snapshot >= SYNC_FULL_REFRESH_SECONDS
                    if due and now - last_snapshot >= SYNC_MIN_SNAPSHOT_SECONDS:
                        epoch = int(time.time())
                        envelope = {"id": rpc.session.seq + 1, "op": "snapshot", "epoch": epoch, **device}
                        capped, size = cap_snapshot_for_ble(snapshot, envelope)
                        started = loop_time()
                        reply = await rpc.call("snapshot", compressed=True, snapshot=capped, epoch=epoch, **device)
                        self._record_reply(reply)
                        last_digest, last_snapshot, last_send = digest, now, now
                        self.force_snapshot = False
                        self._update(last_sync=int(time.time()), last_snapshot_bytes=size,
                                     last_rtt_ms=int((loop_time() - started) * 1000), bytes_sent=link.bytes_sent)
                if now - last_send >= SYNC_HEARTBEAT_SECONDS:
                    reply = await rpc.call("heartbeat", epoch=int(time.time()), **device)
                    self._record_reply(reply)
                    last_send = now
                    self._update(last_heartbeat=int(time.time()), bytes_sent=link.bytes_sent)
                link_failures = 0
            except BleLinkError:
                link_failures += 1
                if link_failures > 3:
                    raise
                await link.reset()
                continue
            if now - last_status >= SYNC_STATUS_SECONDS:
                last_status = now
                try:
                    raw = await client.read_gatt_char(STATUS_UUID)
                    status = json.loads(bytes(raw).decode("utf-8"))
                    if isinstance(status, dict):
                        self.bridge._record_sync_status(status)
                except Exception:  # a status read failure is not a sync failure
                    pass
            await self._sleep(SYNC_TICK_SECONDS)


def loop_time() -> float:
    return asyncio.get_running_loop().time()
