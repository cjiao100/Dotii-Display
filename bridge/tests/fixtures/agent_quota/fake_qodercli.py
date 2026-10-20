"""Synthetic stand-in for `qodercli --print --input-format stream-json` (tests only)."""
import json
import os
import sys
from pathlib import Path

lines = Path(__file__).with_name("qoder_usage_info.jsonl").read_text(encoding="utf-8").splitlines()
mode = os.environ.get("FAKE_QODER_MODE", "ok")
for raw in sys.stdin:
    request = json.loads(raw)
    request_id = request["request_id"]
    if request.get("request", {}).get("subtype") != "get_usage_info":
        continue
    if mode == "error":
        print(json.dumps({"type": "control_response", "response": {
            "subtype": "error", "request_id": request_id, "error": "Not logged in"}}), flush=True)
        continue
    print(lines[0], flush=True)
    print(json.dumps({"type": "control_response", "response": {"subtype": "success", "request_id": "other"}}), flush=True)
    print(lines[1].replace("REQUEST_ID", request_id), flush=True)
