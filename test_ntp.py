"""ntp.py encode-packet / decode-packet 的行为测试。"""

import json
import os
import random
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ntp  # noqa: E402

NTP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ntp.py")

BASE_PACKET = {
    "leap_indicator": 0,
    "version": 4,
    "mode": 3,
    "stratum": 2,
    "poll": 6,
    "precision": -20,
    "root_delay": -65536,
    "root_dispersion": 65536,
    "reference_id": "7f000001",
    "reference_timestamp": 0,
    "origin_timestamp": 0,
    "receive_timestamp": 1234567890000000,
    "transmit_timestamp": 1234567890123456,
    "extensions": [],
}


def run_cli(subcommand, payload):
    """以子进程运行 CLI，返回 (returncode, stdout_obj_or_text, stderr_obj_or_text)。"""
    stdin = payload if isinstance(payload, (bytes, str)) else json.dumps(payload)
    proc = subprocess.run(
        [sys.executable, NTP, subcommand],
        input=stdin.encode("utf-8") if isinstance(stdin, str) else stdin,
        capture_output=True,
    )
    out = proc.stdout.decode("utf-8")
    err = proc.stderr.decode("utf-8")
    try:
        out = json.loads(out) if out else None
    except json.JSONDecodeError:
        pass
    try:
        err = json.loads(err) if err else None
    except json.JSONDecodeError:
        pass
    return proc.returncode, out, err


def encode(obj):
    return ntp.encode_packet(json.loads(json.dumps(obj)))


def decode_hex(packet_hex, digest_len):
    return ntp.decode_packet(
        {"packet_hex": packet_hex, "auth_digest_bytes": digest_len}
    )


class TimestampRoundingTests(unittest.TestCase):
    def test_decode_ties_to_even(self):
        # f * 15625 在模 2^26 下恰余 2^25 时为半微秒半点。
        mod = 1 << 26
        f0 = (1 << 25) * pow(15625, -1, mod) % mod
        q0 = (f0 * 15625 - (1 << 25)) // mod
        # q0 半点：向偶取整；邻接定点单位分别落到 q0-侧/上侧。
        self.assertEqual(ntp._fixed_to_usec(f0), q0 if q0 % 2 == 0 else q0 + 1)
        self.assertEqual(ntp._fixed_to_usec(f0 - 1), q0)
        self.assertEqual(ntp._fixed_to_usec(f0 + 1), q0 + 1)
        # f1 = f0 + 2^26：商增加 15625（奇数），半点奇偶翻转。
        f1 = f0 + mod
        q1 = q0 + 15625
        tie1 = q1 if q1 % 2 == 0 else q1 + 1
        self.assertEqual(ntp._fixed_to_usec(f1), tie1)
        self.assertEqual(ntp._fixed_to_usec(f1 - 1), q1)
        self.assertEqual(ntp._fixed_to_usec(f1 + 1), q1 + 1)

    def test_encode_never_ties_microsecond_granularity(self):
        # us*2^26/15625 的余数不可能为半点（15625 为奇数）；误差不超过 0.5 定点单位。
        for us in (0, 1, 7, 15625, 1234567890123456):
            f = ntp._usec_to_fixed(us)
            self.assertLessEqual(abs(f * 15625 - us * (1 << 26)), 15625 // 2)

    def test_timestamp_extremes(self):
        max_us = 4_294_967_295_999_999
        f = ntp._usec_to_fixed(max_us)
        self.assertLessEqual(f, (1 << 64) - 1)
        self.assertEqual(ntp._fixed_to_usec(f), max_us)
        # 恰好映射到 2^64 的微秒值越界。
        with self.assertRaises(ntp.ParamError):
            obj = dict(BASE_PACKET, transmit_timestamp=4_294_967_296_000_000)
            encode(obj)

    def test_negative_timestamp_rejected(self):
        with self.assertRaises(ntp.ParamError):
            encode(dict(BASE_PACKET, reference_timestamp=-1))


class RoundTripTests(unittest.TestCase):
    def _assert_identical(self, packet):
        enc = encode(packet)
        digest_len = 0
        if packet.get("authentication"):
            digest_len = len(bytes.fromhex(packet["authentication"]["digest"]))
        decoded = decode_hex(enc["packet_hex"], digest_len)
        for key in ntp.PACKET_FIELDS:
            self.assertEqual(decoded[key], packet[key], key)
        if packet.get("authentication"):
            self.assertEqual(decoded["authentication"], packet["authentication"])
        enc2 = encode(decoded)
        self.assertEqual(enc2, enc)  # 解码后再编码逐字节一致
        self.assertEqual(enc2["length"], len(bytes.fromhex(enc["packet_hex"])))

    def test_header_only_all_field_boundaries(self):
        packet = dict(
            BASE_PACKET,
            leap_indicator=3,
            version=1,
            mode=1,
            stratum=0,
            poll=-128,
            precision=-128,
            root_delay=-(1 << 31),
            root_dispersion=0,
            reference_id="00000000",
            reference_timestamp=0,
            origin_timestamp=0,
            receive_timestamp=0,
            transmit_timestamp=0,
        )
        self._assert_identical(packet)

        packet.update(
            version=4, mode=5, stratum=16, poll=127, precision=127,
            root_delay=(1 << 31) - 1, root_dispersion=(1 << 32) - 1,
            reference_id="aabbccdd",
            reference_timestamp=4_294_967_295_999_999,
            origin_timestamp=1,
            receive_timestamp=4_294_967_295_999_998,
            transmit_timestamp=15625,
        )
        self._assert_identical(packet)

    def test_extensions_and_auth_16(self):
        packet = dict(
            BASE_PACKET,
            extensions=[
                {"type": 0, "value": "00" * 12},
                {"type": 0xFFFF, "value": "deadbeef" * 4},
                {"type": 7, "value": "ab" * 100},
            ],
            authentication={"key_id": 0, "digest": "cd" * 16},
        )
        self._assert_identical(packet)

    def test_auth_20_without_extensions(self):
        packet = dict(
            BASE_PACKET,
            extensions=[],
            authentication={"key_id": 0xFFFFFFFF, "digest": "0123456789abcdef" * 2 + "00112233"},
        )
        self.assertEqual(len(bytes.fromhex(packet["authentication"]["digest"])), 20)
        self._assert_identical(packet)

    def test_fuzz_encode_decode_encode(self):
        rng = random.Random(20261005)
        for _ in range(300):
            ext_count = rng.randrange(0, 4)
            extensions = []
            for _ in range(ext_count):
                n = rng.choice([12, 16, 24, 100])
                extensions.append(
                    {"type": rng.randrange(0, 0x10000),
                     "value": bytes(rng.randrange(256) for _ in range(n)).hex()}
                )
            packet = {
                "leap_indicator": rng.randrange(4),
                "version": rng.randrange(1, 5),
                "mode": rng.randrange(1, 6),
                "stratum": rng.randrange(0, 17),
                "poll": rng.randrange(-128, 128),
                "precision": rng.randrange(-128, 128),
                "root_delay": rng.randrange(-(1 << 31), 1 << 31),
                "root_dispersion": rng.randrange(0, 1 << 32),
                "reference_id": bytes(rng.randrange(256) for _ in range(4)).hex(),
                "reference_timestamp": rng.randrange(0, 1 << 42),
                "origin_timestamp": rng.randrange(0, 1 << 42),
                "receive_timestamp": rng.randrange(0, 1 << 42),
                "transmit_timestamp": rng.randrange(0, 1 << 42),
                "extensions": extensions,
            }
            if rng.randrange(2):
                n = rng.choice([16, 20])
                packet["authentication"] = {
                    "key_id": rng.randrange(1 << 32),
                    "digest": bytes(rng.randrange(256) for _ in range(n)).hex(),
                }
            self._assert_identical(packet)


class EncodingParamErrorTests(unittest.TestCase):
    def _param_error(self, obj):
        code, out, err = run_cli("encode-packet", obj)
        self.assertEqual(code, 2)
        self.assertIsNone(out)
        self.assertEqual(list(err.keys()), ["error", "message"])
        self.assertEqual(err["error"], "ParamError")

    def test_unknown_subcommand(self):
        code, out, err = run_cli("bogus", BASE_PACKET)
        self.assertEqual(code, 2)
        self.assertEqual(err["error"], "ParamError")

    def test_missing_and_extra_keys(self):
        for key in ntp.PACKET_FIELDS:
            obj = {k: BASE_PACKET[k] for k in ntp.PACKET_FIELDS if k != key}
            self._param_error(obj)
        self._param_error(dict(BASE_PACKET, bogus=1))
        self._param_error("not an object")
        self._param_error("not json at all")

    def test_bool_is_not_integer(self):
        self._param_error(dict(BASE_PACKET, mode=True))

    def test_field_ranges(self):
        bad = [
            ("leap_indicator", -1), ("leap_indicator", 4),
            ("version", 0), ("version", 5),
            ("mode", 0), ("mode", 6),
            ("stratum", -1), ("stratum", 17),
            ("poll", -129), ("poll", 128),
            ("precision", -129), ("precision", 128),
            ("root_delay", -(1 << 31) - 1), ("root_delay", 1 << 31),
            ("root_dispersion", -1), ("root_dispersion", 1 << 32),
        ]
        for key, value in bad:
            self._param_error(dict(BASE_PACKET, **{key: value}))

    def test_wrong_types(self):
        self._param_error(dict(BASE_PACKET, mode="3"))
        self._param_error(dict(BASE_PACKET, reference_id=1234))
        self._param_error(dict(BASE_PACKET, extensions={}))
        obj = dict(BASE_PACKET, extensions=[{"type": 1}])
        self._param_error(obj)
        obj = dict(BASE_PACKET, extensions=[{"type": "1", "value": "00" * 12}])
        self._param_error(obj)
        obj = dict(BASE_PACKET, extensions=[{"type": 1, "value": 123}])
        self._param_error(obj)
        obj = dict(BASE_PACKET, extensions=[{"type": 1, "value": "00" * 12, "x": 1}])
        self._param_error(obj)
        self._param_error(dict(BASE_PACKET, authentication={"key_id": 1}))
        self._param_error(
            dict(BASE_PACKET, authentication={"key_id": -1, "digest": "ab" * 16})
        )
        self._param_error(dict(BASE_PACKET, authentication=None))


class EncodingPacketErrorTests(unittest.TestCase):
    def _packet_error(self, obj):
        code, out, err = run_cli("encode-packet", obj)
        self.assertEqual(code, 3)
        self.assertIsNone(out)
        self.assertEqual(err["error"], "PacketError")

    def test_reference_id(self):
        self._packet_error(dict(BASE_PACKET, reference_id="7f0000"))    # 3 字节
        self._packet_error(dict(BASE_PACKET, reference_id="7f00000102"))  # 5 字节
        self._packet_error(dict(BASE_PACKET, reference_id="zz000001"))
        self._packet_error(dict(BASE_PACKET, reference_id="abc"))

    def test_extension_length(self):
        # value 8 字节 -> 总长 12，不足 16。
        obj = dict(BASE_PACKET, extensions=[{"type": 1, "value": "00" * 8}])
        self._packet_error(obj)
        # value 13 字节 -> 总长 17，不是 4 的倍数。
        obj = dict(BASE_PACKET, extensions=[{"type": 1, "value": "00" * 13}])
        self._packet_error(obj)
        obj = dict(BASE_PACKET, extensions=[{"type": 1, "value": "xyz"}])
        self._packet_error(obj)

    def test_digest_length_and_hex(self):
        obj = dict(BASE_PACKET,
                   authentication={"key_id": 1, "digest": "ab" * 15})
        self._packet_error(obj)
        obj = dict(BASE_PACKET,
                   authentication={"key_id": 1, "digest": "ab" * 17})
        self._packet_error(obj)
        obj = dict(BASE_PACKET,
                   authentication={"key_id": 1, "digest": "zz" * 16})
        self._packet_error(obj)

    def test_packet_too_long(self):
        # 48 头 + 65488 扩展总长 = 65536，超过上限。
        obj = dict(BASE_PACKET,
                   extensions=[{"type": 1, "value": "00" * 65484}])
        self._packet_error(obj)

    def test_packet_at_limit_ok(self):
        # 48 + 65484（value 65480，总长 65484）= 65532。
        obj = dict(BASE_PACKET,
                   extensions=[{"type": 1, "value": "00" * 65480}])
        code, out, err = run_cli("encode-packet", obj)
        self.assertEqual(code, 0, err)
        self.assertEqual(out["length"], 65532)
        # value 65484（总长 65488）-> 65536 越界。
        obj["extensions"][0]["value"] = "00" * 65484
        self._packet_error(obj)


class DecodeErrorTests(unittest.TestCase):
    def _param_error(self, payload):
        code, out, err = run_cli("decode-packet", payload)
        self.assertEqual(code, 2)
        self.assertEqual(err["error"], "ParamError")

    def _packet_error(self, packet_hex, digest_len=0):
        code, out, err = run_cli(
            "decode-packet",
            {"packet_hex": packet_hex, "auth_digest_bytes": digest_len},
        )
        self.assertEqual(code, 3)
        self.assertIsNone(out)
        self.assertEqual(err["error"], "PacketError")

    def test_param_errors(self):
        enc = encode(BASE_PACKET)
        self._param_error({"packet_hex": enc["packet_hex"]})
        self._param_error({"auth_digest_bytes": 0})
        self._param_error({"packet_hex": enc["packet_hex"],
                           "auth_digest_bytes": 4})
        self._param_error({"packet_hex": enc["packet_hex"],
                           "auth_digest_bytes": "0"})
        self._param_error({"packet_hex": 123, "auth_digest_bytes": 0})
        self._param_error({"packet_hex": enc["packet_hex"],
                           "auth_digest_bytes": 0, "extra": 1})

    def test_short_and_long_packets(self):
        self._packet_error("")
        self._packet_error("00" * 47)
        self._packet_error("00" * (65536))

    def test_bad_hex(self):
        self._packet_error("abc")
        self._packet_error("zz" * 48)

    def test_illegal_header_fields(self):
        enc = bytearray.fromhex(encode(BASE_PACKET)["packet_hex"])
        for bad_first in (0x00, 0x0E, 0x18, 0x3E):  # 含非法 version / mode
            data = bytearray(enc)
            data[0] = bad_first
            self._packet_error(data.hex())
        # 非法层数 17。
        data = bytearray(enc)
        data[1] = 17
        self._packet_error(data.hex())

    def test_trailer_declared_but_missing(self):
        enc = encode(BASE_PACKET)
        self._packet_error(enc["packet_hex"], 16)

    def test_extension_overrun_and_residual(self):
        # 声明一个越界扩展。
        packet = dict(BASE_PACKET,
                      extensions=[{"type": 1, "value": "00" * 12}],
                      authentication={"key_id": 9, "digest": "ab" * 16})
        good = bytearray.fromhex(encode(packet)["packet_hex"])
        # 尾部完整：按 16 字节摘要解析成功。
        code, out, err = run_cli(
            "decode-packet",
            {"packet_hex": good.hex(), "auth_digest_bytes": 16},
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out["authentication"],
                         {"key_id": 9, "digest": "ab" * 16})

        # 篡改扩展长度字段为越界值。
        bad = bytearray(good)
        bad[50:52] = (80).to_bytes(2, "big")
        self._packet_error(bad.hex(), 16)
        # 非法扩展长度（< 16）。
        bad = bytearray(good)
        bad[50:52] = (12).to_bytes(2, "big")
        self._packet_error(bad.hex(), 16)
        # 非 4 倍数长度。
        bad = bytearray(good)
        bad[50:52] = (17).to_bytes(2, "big")
        self._packet_error(bad.hex(), 16)

        # 残留 2 字节无法构成扩展。
        self._packet_error(good.hex() + "0000", 16)

    def test_extension_length_mismatch_into_trailer(self):
        # 20 字节摘要的报文按 16 字节声明：扩展区吃掉尾部 4 字节，扩展越界。
        packet = dict(BASE_PACKET,
                      extensions=[{"type": 1, "value": "00" * 12}],
                      authentication={"key_id": 9, "digest": "ab" * 20})
        raw = encode(packet)["packet_hex"]
        self._packet_error(raw, 16)


class OutputFormatTests(unittest.TestCase):
    def test_encode_output_key_order_and_one_line(self):
        proc = subprocess.run(
            [sys.executable, NTP, "encode-packet"],
            input=json.dumps(BASE_PACKET).encode(),
            capture_output=True,
        )
        line = proc.stdout.decode()
        self.assertTrue(line.endswith("\n"))
        self.assertEqual(line.count("\n"), 1)
        self.assertTrue(line.startswith('{"packet_hex":'))
        self.assertIn('"length":48', line)

    def test_decode_output_key_order(self):
        enc = encode(BASE_PACKET)
        decoded = decode_hex(enc["packet_hex"], 0)
        self.assertEqual(
            list(decoded.keys()),
            ntp.PACKET_FIELDS,
        )
        packet = dict(BASE_PACKET,
                      authentication={"key_id": 1, "digest": "ab" * 16})
        enc = encode(packet)
        decoded = decode_hex(enc["packet_hex"], 16)
        self.assertEqual(list(decoded.keys())[-2:], ["extensions", "authentication"])
        self.assertEqual(list(decoded["authentication"].keys()), ["key_id", "digest"])

    def test_hex_output_is_lowercase(self):
        packet = dict(
            BASE_PACKET,
            reference_id="ABCDEF01",
            extensions=[{"type": 1, "value": "DEADBEEF" * 3}],
            authentication={"key_id": 1, "digest": "FF" * 16},
        )
        enc = encode(packet)
        decoded = decode_hex(enc["packet_hex"], 16)
        self.assertEqual(decoded["reference_id"], "abcdef01")
        self.assertEqual(decoded["extensions"][0]["value"], "deadbeef" * 3)
        self.assertEqual(decoded["authentication"]["digest"], "ff" * 16)

    def test_deterministic_bytes(self):
        raw = json.dumps(BASE_PACKET)
        proc1 = subprocess.run([sys.executable, NTP, "encode-packet"],
                               input=raw.encode(), capture_output=True)
        proc2 = subprocess.run([sys.executable, NTP, "encode-packet"],
                               input=raw.encode(), capture_output=True)
        self.assertEqual(proc1.stdout, proc2.stdout)
        dec_in = json.dumps(
            {"packet_hex": proc1.stdout.decode().split('"')[3],
             "auth_digest_bytes": 0}
        )
        proc3 = subprocess.run([sys.executable, NTP, "decode-packet"],
                               input=dec_in.encode(), capture_output=True)
        proc4 = subprocess.run([sys.executable, NTP, "decode-packet"],
                               input=dec_in.encode(), capture_output=True)
        self.assertEqual(proc3.stdout, proc4.stdout)


if __name__ == "__main__":
    unittest.main()
