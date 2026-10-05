import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

import ntp  # noqa: E402


def run_cli(subcommand, payload):
    proc = subprocess.run(
        [sys.executable, str(REPO / "ntp.py"), subcommand],
        input=json.dumps(payload).encode(),
        capture_output=True,
    )
    return proc


def base_model(**overrides):
    model = {
        "leap": 0,
        "version": 4,
        "mode": 4,
        "stratum": 2,
        "poll": 6,
        "precision": -20,
        "root_delay": -125000,
        "root_dispersion": 78125,
        "reference_id": "c0a80001",
        "reference_timestamp": 3858489600000000,
        "originate_timestamp": 3858489601123456,
        "receive_timestamp": 3858489602500000,
        "transmit_timestamp": 3858489603999999,
        "extensions": [],
    }
    model.update(overrides)
    return model


class RoundingTests(unittest.TestCase):
    def test_half_even(self):
        r = ntp.round_half_even
        self.assertEqual(r(5, 2), 2)       # tie -> even 2
        self.assertEqual(r(7, 2), 4)       # tie -> even 4
        self.assertEqual(r(1, 3), 0)
        self.assertEqual(r(2, 3), 1)
        self.assertEqual(r(-5, 2), -2)
        self.assertEqual(r(-7, 2), -4)

    def test_timestamp_tie_to_even(self):
        # 500000 us maps exactly to fraction 0x80000000 and back.
        wire = ntp.encode_timestamp("t", 500000)
        self.assertEqual(wire, struct.pack(">II", 0, 0x80000000))
        self.assertEqual(ntp.decode_timestamp(wire), 500000)

    def test_timestamp_bounds(self):
        ntp.encode_timestamp("t", (2 ** 32 - 1) * 10 ** 6 + 999999)
        with self.assertRaises(ntp.ParamError):
            ntp.encode_timestamp("t", 2 ** 32 * 10 ** 6)
        with self.assertRaises(ntp.ParamError):
            ntp.encode_timestamp("t", -1)

    def test_fixed_exactness_and_bounds(self):
        self.assertEqual(
            ntp.encode_fixed("d", 65535984375, signed=False),
            struct.pack(">I", 4294966272),
        )
        # one microsecond more cannot land exactly on the wire format
        with self.assertRaises(ntp.ParamError):
            ntp.encode_fixed("d", 65535984376, signed=False)
        with self.assertRaises(ntp.ParamError):
            ntp.encode_fixed("d", 1, signed=False)
        ntp.encode_fixed("d", -32768000000, signed=True)
        with self.assertRaises(ntp.ParamError):
            ntp.encode_fixed("d", -32768000001, signed=True)

    def test_fixed_decode_nearest_and_signed(self):
        # wire unit 1/65536 s = 15.625ms/1024 ... nearest microsecond
        self.assertEqual(
            ntp.decode_fixed(struct.pack(">I", 1024), signed=False), 15625)
        self.assertEqual(
            ntp.decode_fixed(struct.pack(">i", 1), signed=True), 15)
        self.assertEqual(
            ntp.decode_fixed(struct.pack(">i", -1), signed=True), -15)
        # exact grid points survive a decode -> encode cycle
        for wire in (0, 1024, 0x7FFFFC00, -1024, -0x80000000):
            octets = struct.pack(">i", wire)
            micros = ntp.decode_fixed(octets, signed=True)
            self.assertEqual(
                ntp.encode_fixed("d", micros, signed=True), octets)


class RoundTripTests(unittest.TestCase):
    def encode(self, model):
        proc = run_cli("encode-packet", model)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(list(out), ["packet_hex", "length"])
        self.assertEqual(out["length"], len(bytes.fromhex(out["packet_hex"])))
        return out

    def decode(self, packet_hex, digest_bytes):
        proc = run_cli("decode-packet",
                       {"packet_hex": packet_hex,
                        "auth_digest_bytes": digest_bytes})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def assert_model_roundtrip(self, model, digest_bytes):
        encoded = self.encode(model)
        decoded = self.decode(encoded["packet_hex"], digest_bytes)
        expected = dict(model)
        if "auth" not in expected:
            expected["auth"] = None
        self.assertEqual(decoded, expected)
        self.assertEqual(list(decoded), ntp.ENCODE_FIELDS)
        re_encoded = self.encode(decoded)
        self.assertEqual(re_encoded["packet_hex"], encoded["packet_hex"])

    def test_plain_header(self):
        self.assert_model_roundtrip(base_model(), 0)

    def test_extremes(self):
        model = base_model(
            leap=3, version=1, mode=1, stratum=0, poll=-128, precision=-128,
            root_delay=-32768000000,
            root_dispersion=65535984375,
            reference_id="00000000",
            reference_timestamp=0,
            originate_timestamp=0,
            receive_timestamp=0,
            transmit_timestamp=0,
        )
        self.assert_model_roundtrip(model, 0)

    def test_extensions_preserve_order(self):
        model = base_model(extensions=[
            {"type": 0x0102, "value": "aa" * 12},                 # 16 total
            {"type": 0xFFFF, "value": "bb" * 100},                # 104 total
        ])
        decoded = self.decode(self.encode(model)["packet_hex"], 0)
        self.assertEqual(decoded["extensions"], model["extensions"])

    def test_auth_16(self):
        model = base_model(
            extensions=[{"type": 7, "value": "cd" * 12}],
            auth={"key_id": 0xDEADBEEF, "digest": "01" * 16},
        )
        self.assert_model_roundtrip(model, 16)

    def test_auth_20_header_only(self):
        model = base_model(
            auth={"key_id": 1, "digest": "ab" * 20},
        )
        self.assert_model_roundtrip(model, 20)

    def test_max_packet_length(self):
        # 65535 is not 4-aligned relative to the 48-byte header; the
        # largest single-extension packet is 65532 bytes.
        payload_len = 65532 - ntp.HEADER_LENGTH - 4
        model = base_model(extensions=[{"type": 1, "value": "00" * payload_len}])
        out = self.encode(model)
        self.assertEqual(out["length"], 65532)
        self.assertEqual(
            self.decode(out["packet_hex"], 0)["extensions"][0]["value"],
            model["extensions"][0]["value"],
        )


class ErrorTests(unittest.TestCase):
    def assert_param_error(self, subcommand, payload):
        proc = run_cli(subcommand, payload)
        self.assertEqual(proc.returncode, 2, proc.stdout)
        err = json.loads(proc.stderr)
        self.assertEqual(list(err), ["error", "message"])
        self.assertEqual(err["error"], "ParamError")
        return proc

    def assert_packet_error_decode(self, packet_hex, digest_bytes=0):
        proc = run_cli("decode-packet",
                       {"packet_hex": packet_hex,
                        "auth_digest_bytes": digest_bytes})
        self.assertEqual(proc.returncode, 3, proc.stdout)
        err = json.loads(proc.stderr)
        self.assertEqual(err["error"], "PacketError")
        return proc

    def test_unknown_subcommand(self):
        proc = subprocess.run(
            [sys.executable, str(REPO / "ntp.py"), "frobnicate"],
            input=b"{}", capture_output=True)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stderr)["error"], "ParamError")

    def test_missing_extra_mistyped_keys(self):
        model = base_model()
        missing = dict(model)
        del missing["mode"]
        self.assert_param_error("encode-packet", missing)
        extra = base_model(surprise=1)
        self.assert_param_error("encode-packet", extra)
        wrong = base_model(mode="4")
        self.assert_param_error("encode-packet", wrong)
        wrong = base_model(leap=True)
        self.assert_param_error("encode-packet", wrong)

    def test_field_ranges(self):
        self.assert_param_error("encode-packet", base_model(leap=4))
        self.assert_param_error("encode-packet", base_model(version=0))
        self.assert_param_error("encode-packet", base_model(version=5))
        self.assert_param_error("encode-packet", base_model(mode=0))
        self.assert_param_error("encode-packet", base_model(mode=6))
        self.assert_param_error("encode-packet", base_model(stratum=17))
        self.assert_param_error("encode-packet", base_model(poll=-129))
        self.assert_param_error("encode-packet", base_model(precision=128))

    def test_hex_fields(self):
        self.assert_param_error("encode-packet",
                                base_model(reference_id="C0A80001"))
        self.assert_param_error("encode-packet",
                                base_model(reference_id="c0a8001"))
        self.assert_param_error("encode-packet",
                                base_model(reference_id="zz000000"))
        self.assert_param_error("encode-packet",
                                base_model(reference_id="c0a800"))
        self.assert_param_error("encode-packet", base_model(
            extensions=[{"type": 1, "value": "abc"}]))

    def test_extension_length(self):
        self.assert_param_error("encode-packet", base_model(
            extensions=[{"type": 1, "value": "aa" * 8}]))   # 12 total
        self.assert_param_error("encode-packet", base_model(
            extensions=[{"type": 1, "value": "aa" * 13}]))  # 17 total

    def test_auth_digest_length(self):
        bad = base_model(auth={"key_id": 1, "digest": "00" * 4})
        self.assert_param_error("encode-packet", bad)
        bad = base_model(extensions="nope")
        self.assert_param_error("encode-packet", bad)

    def test_decode_param_errors(self):
        self.assert_param_error("decode-packet", {"packet_hex": ""})
        self.assert_param_error("decode-packet",
                                {"packet_hex": "aa", "auth_digest_bytes": 4})
        self.assert_param_error("decode-packet",
                                {"packet_hex": "aa", "auth_digest_bytes": -1})
        self.assert_param_error("decode-packet",
                                {"packet_hex": "aa", "auth_digest_bytes": 21})
        self.assert_param_error("decode-packet",
                                {"packet_hex": "aa", "auth_digest_bytes": "0"})

    def test_invalid_json(self):
        proc = subprocess.run(
            [sys.executable, str(REPO / "ntp.py"), "encode-packet"],
            input=b"not json", capture_output=True)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(json.loads(proc.stderr)["error"], "ParamError")

    def test_packet_errors(self):
        good = run_cli("encode-packet", base_model())
        hexen = json.loads(good.stdout)["packet_hex"]
        raw = bytes.fromhex(hexen)

        self.assert_packet_error_decode(raw[:47].hex())           # too short
        self.assert_packet_error_decode(raw.hex() + "00")         # stray byte
        self.assert_packet_error_decode(raw.hex() + "000000")     # 3 residual

        bad_mode = bytes([raw[0] & 0xF8]) + raw[1:]
        self.assert_packet_error_decode(bad_mode.hex())

        bad_version = bytes([(raw[0] & 0xC7)]) + raw[1:]
        self.assert_packet_error_decode(bad_version.hex())

        bad_stratum = raw[:1] + bytes([17]) + raw[2:]
        self.assert_packet_error_decode(bad_stratum.hex())

        # corrupt extension declared length
        ext_model = base_model(extensions=[{"type": 1, "value": "aa" * 12}])
        ext_hex = json.loads(run_cli("encode-packet", ext_model).stdout)["packet_hex"]
        ext_raw = bytearray.fromhex(ext_hex)
        struct.pack_into(">H", ext_raw, 50, 32)  # declared beyond packet end
        self.assert_packet_error_decode(ext_raw.hex())
        struct.pack_into(">H", ext_raw, 50, 12)  # declared below minimum
        self.assert_packet_error_decode(ext_raw.hex())

        # MAC declared but packet too short
        self.assert_packet_error_decode(raw.hex(), 16)

        self.assert_packet_error_decode("zz")        # not hex
        self.assert_packet_error_decode("abc")       # odd length

    def test_oversize_packet(self):
        model = base_model(extensions=[
            {"type": 1, "value": "00" * (65536 - 48 - 4)}])
        proc = run_cli("encode-packet", model)
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(json.loads(proc.stderr)["error"], "PacketError")

        self.assert_packet_error_decode("00" * 65536)

    def test_deterministic(self):
        model = base_model(extensions=[{"type": 3, "value": "ee" * 16}],
                           auth={"key_id": 9, "digest": "0f" * 20})
        first = run_cli("encode-packet", model).stdout
        second = run_cli("encode-packet", model).stdout
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
