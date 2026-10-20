"""Synthetic stand-in for `grok agent stdio` used by tests (no network, no real data)."""
import json
import os
import sys
from pathlib import Path

FIXTURE = Path(__file__).with_name("grok_billing.json")
mode = os.environ.get("FAKE_ACP_MODE", "ok")
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if "id" not in message:
        continue
    if method == "initialize":
        result = {"protocolVersion": 1, "agentCapabilities": {}}
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
    elif method == "_x.ai/billing" and mode == "ok":
        # Exercise agent -> client requests before answering.
        print(json.dumps({"jsonrpc": "2.0", "id": "srv-1", "method": "session/request_permission", "params": {}}), flush=True)
        print("not json noise", flush=True)
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"],
                          "result": json.loads(FIXTURE.read_text(encoding="utf-8"))}), flush=True)
    elif method == "_x.ai/billing" and mode == "auth":
        error = {"code": -32603, "message": "Billing data requires auth with grok.com. Run `grok login`"}
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "error": error}), flush=True)
    elif mode == "hang":
        continue
    else:
        error = {"code": -32601, "message": "Method not found"}
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "error": error}), flush=True)
