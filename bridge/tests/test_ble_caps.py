from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ble_caps import COMPRESSED_BUDGET, MAX_TASKS, cap_snapshot_for_ble, snapshot_digest, truncate_utf8  # noqa: E402
from dtu_protocol import encode_compressed_frame  # noqa: E402


def noisy(size: int, seed: int) -> str:
    import random
    rng = random.Random(seed)
    return "".join(rng.choice("码农蓝牙同步abcdefXYZ0123456789 ") for _ in range(size))


class CapTests(unittest.TestCase):
    def test_truncate_never_splits_utf8(self):
        self.assertEqual(truncate_utf8("abc", 3), "abc")
        cut = truncate_utf8("蓝牙蓝牙蓝牙", 8)
        self.assertLessEqual(len(cut.encode()), 8)
        self.assertTrue(cut.endswith("…"))
        self.assertEqual(truncate_utf8(None, 2), None)
        self.assertLessEqual(len(truncate_utf8("蓝牙", 2).encode()), 2)

    def test_images_and_camera_are_never_advertised(self):
        capped, size = cap_snapshot_for_ble({"custom": {"image_available": True}, "bambu": {"camera_available": True}})
        self.assertFalse(capped["custom"]["image_available"])
        self.assertFalse(capped["bambu"]["camera_available"])
        self.assertLess(size, 200)

    def test_large_snapshot_fits_budget_and_keeps_newest(self):
        task = {
            "title": "T" * 500,
            "last_user_message": noisy(20000, 1),
            "last_assistant_message": noisy(20000, 2),
            "codex_messages": [noisy(5000, index) + f"#{index}" for index in range(40)],
        }
        snapshot = {"codex": {"task": dict(task), "tasks": [dict(task) for _ in range(20)]}}
        envelope = {"id": 9, "op": "snapshot", "epoch": 1, "language": "zh-CN", "connection_mode": "ble"}
        capped, size = cap_snapshot_for_ble(snapshot, envelope)
        self.assertLessEqual(size, COMPRESSED_BUDGET)
        self.assertEqual(size, len(encode_compressed_frame({**envelope, "snapshot": capped})))
        self.assertLessEqual(len(capped["codex"]["tasks"]), MAX_TASKS)
        current = capped["codex"]["task"]
        self.assertLessEqual(len(current["title"].encode()), 95)
        self.assertLessEqual(len(current["last_user_message"].encode()), 1200)
        self.assertTrue(current["codex_messages"][-1].startswith(noisy(5000, 39)[:16]))  # newest kept
        self.assertEqual(snapshot["codex"]["task"]["title"], "T" * 500)  # input untouched

    def test_impossible_snapshot_raises_stable_code(self):
        snapshot = {"blob": noisy(200000, 3)}
        with self.assertRaisesRegex(ValueError, "snapshot_too_large_for_ble"):
            cap_snapshot_for_ble(snapshot)

    def test_digest_ignores_generation_time_only(self):
        a = snapshot_digest({"generated_at_epoch": 1, "x": 1}, {"language": "en"})
        self.assertEqual(a, snapshot_digest({"generated_at_epoch": 2, "x": 1}, {"language": "en"}))
        self.assertNotEqual(a, snapshot_digest({"generated_at_epoch": 1, "x": 2}, {"language": "en"}))
        self.assertNotEqual(a, snapshot_digest({"generated_at_epoch": 1, "x": 1}, {"language": "zh-CN"}))


if __name__ == "__main__":
    unittest.main()


class AgentCapTests(unittest.TestCase):
    def test_agents_capped_in_count_and_text(self):
        agents = [{"id": "x" * 30, "nm": "n" * 40, "st": "ok", "up": 10,
                   "w": [{"l": "周" * 20, "u": 10.0, "r": 1},
                         {"l": "b", "u": 5.0, "r": 2},
                         {"l": "c", "u": 1.0, "r": 3}]} for _ in range(20)]
        capped, size = cap_snapshot_for_ble({"codex": {"task": {}}, "agents": agents})
        out = capped["agents"]
        self.assertEqual(len(out), 8)
        self.assertLessEqual(len(out[0]["id"].encode("utf-8")), 12)
        self.assertLessEqual(len(out[0]["nm"].encode("utf-8")), 16)
        self.assertEqual(len(out[0]["w"]), 2)
        self.assertLessEqual(len(out[0]["w"][0]["l"].encode("utf-8")), 16)
