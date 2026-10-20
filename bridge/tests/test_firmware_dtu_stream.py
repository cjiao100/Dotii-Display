"""Builds main/dtu_stream.c for the host and checks it against dtu_protocol.py."""
from __future__ import annotations

import shutil
import struct
import subprocess
import sys
import unittest
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
from dotii_test_support import temporary_directory  # noqa: E402
from dtu_protocol import encode_compressed_frame, encode_frame  # noqa: E402

COMPILER = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")


@unittest.skipUnless(COMPILER and (ROOT / "main" / "dtu_stream.c").exists(), "host C compiler not available")
class FirmwareStreamParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = temporary_directory()
        cls.binary = Path(cls.folder.name) / "dtu_stream_host_test"
        subprocess.run([COMPILER, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-I", str(ROOT / "main"),
                        str(ROOT / "main" / "dtu_stream.c"), str(HERE / "dtu_stream_host_test.c"),
                        "-o", str(cls.binary)], check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def run_parser(self, stream: bytes, max_frame: int = 4096) -> tuple[list[tuple[int, int, int]], list[int]]:
        output = subprocess.run([str(self.binary), str(max_frame)], input=stream, capture_output=True,
                                check=True).stdout.decode()
        frames, counters = [], []
        for line in output.splitlines():
            parts = line.split()
            if parts[0] == "F":
                self.assertEqual(parts[4], "1", "body must be NUL terminated")
                frames.append((int(parts[1]), int(parts[2]), int(parts[3], 16)))
            else:
                counters = [int(value) for value in parts[1:]]
        return frames, counters

    @staticmethod
    def expected(frame: bytes) -> tuple[int, int, int]:
        length, crc = struct.unpack_from("<II", frame, 4)
        return int(frame[:4] == b"DTZ1"), length, crc

    def test_matches_python_encoder_across_chunk_boundaries(self):
        frames = [encode_frame({"id": 1, "op": "hello"}), encode_compressed_frame({"id": 2, "text": "蓝牙" * 300}),
                  encode_frame({"id": 3, "op": "heartbeat", "pad": "x" * 2000})]
        stream = b"DTgarbageDT" + frames[0] + b"\x00\xff" + frames[1] + b"DTU" + frames[2]
        parsed, counters = self.run_parser(stream)
        self.assertEqual(parsed, [self.expected(frame) for frame in frames])
        self.assertEqual(counters, [3, 0, 0, 0, 1])

    def test_crc_and_size_errors_resynchronise(self):
        good = encode_frame({"id": 5})
        corrupt = bytearray(encode_frame({"id": 4, "pad": "y" * 100}))
        corrupt[-3] ^= 0x40
        body = b"z" * 5000
        oversize = b"DTU1" + struct.pack("<II", len(body), zlib.crc32(body)) + body
        zero = b"DTU1" + struct.pack("<II", 0, 0)
        parsed, counters = self.run_parser(bytes(corrupt) + zero + oversize + good)
        self.assertEqual(parsed, [self.expected(good)])
        self.assertEqual(counters[0], 1)
        self.assertGreaterEqual(counters[1], 1)
        self.assertGreaterEqual(counters[2], 2)

    def test_crc_matches_zlib(self):
        frame = encode_compressed_frame({"id": 6, "x": list(range(500))})
        parsed, _ = self.run_parser(frame)
        inner = frame[12:]
        self.assertEqual(parsed, [(1, len(inner), zlib.crc32(inner))])


if __name__ == "__main__":
    unittest.main()
