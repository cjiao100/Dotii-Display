"""Minimal JSON-RPC 2.0 client over a child process's stdin/stdout.

Used for the Agent Client Protocol (``grok agent stdio``). The child's stderr
is discarded so nothing it prints (which might include account data) reaches
the bridge log.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .base import STATUS_UNAVAILABLE, QuotaError


class RpcError(RuntimeError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


class StdioJsonRpc:
    def __init__(self, command: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
        self.command = command
        self.cwd = cwd
        self.env = env
        self.process: subprocess.Popen[str] | None = None
        self._next_id = 1
        self._responses: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self._write_lock = threading.Lock()

    def __enter__(self) -> "StdioJsonRpc":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def start(self) -> None:
        try:
            self.process = subprocess.Popen(
                self.command,
                cwd=str(self.cwd) if self.cwd else None,
                env=self.env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                start_new_session=os.name == "posix",
            )
        except OSError as error:
            raise QuotaError(f"无法启动 {Path(self.command[0]).name}：{error.strerror or type(error).__name__}",
                             STATUS_UNAVAILABLE) from None
        threading.Thread(target=self._read, name="agent-quota-rpc", daemon=True).start()

    def _read(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        for line in self.process.stdout:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if not isinstance(message, dict):
                continue
            if "method" in message and "id" in message:
                # Agent -> client request (permissions, fs, ...): we expose no capabilities.
                self._write({"jsonrpc": "2.0", "id": message["id"],
                             "error": {"code": -32601, "message": "Method not found"}})
            elif "id" in message:
                self._responses.put(message)

    def _write(self, message: dict[str, Any]) -> None:
        process = self.process
        if process is None or process.stdin is None or process.poll() is not None:
            return
        try:
            with self._write_lock:
                process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
                process.stdin.flush()
        except (OSError, ValueError):
            pass

    def request(self, method: str, params: dict[str, Any] | None, deadline: float) -> Any:
        request_id = self._next_id
        self._next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._write(message)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QuotaError(f"请求超时：{method}", STATUS_UNAVAILABLE)
            if self.process is not None and self.process.poll() is not None and self._responses.empty():
                raise QuotaError("CLI 进程提前退出", STATUS_UNAVAILABLE)
            try:
                response = self._responses.get(timeout=min(0.25, remaining))
            except queue.Empty:
                continue
            if response.get("id") != request_id:
                continue
            if "error" in response:
                error = response.get("error") or {}
                if not isinstance(error, dict):
                    error = {"message": str(error)}
                code = error.get("code")
                raise RpcError(int(code) if isinstance(code, int) else 0, str(error.get("message") or "")[:200])
            return response.get("result")

    def close(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass
        terminate_process_tree(process)


def terminate_process_tree(process: subprocess.Popen[Any], grace: float = 3.0) -> None:
    """Terminate the child and anything it spawned in its session (MCP helpers etc.)."""
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=grace)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            pass
