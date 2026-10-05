#!/usr/bin/env python3
"""Deterministic NTP packet model with encode/decode subcommands.

CLI:
    python ntp.py encode-packet   # JSON packet model  -> {"packet_hex", "length"}
    python ntp.py decode-packet   # {"packet_hex", "auth_digest_bytes"} -> model

No networking, wall-clock reads or randomness are used; identical input
always produces identical output bytes.
"""

import json
import struct
import sys

MICROS_PER_SECOND = 10 ** 6
FRAC_UNITS_PER_SECOND = 1 << 32
FIXED_UNITS_PER_SECOND = 1 << 16
MAX_U32 = (1 << 32) - 1
MIN_I32 = -(1 << 31)
MAX_I32 = (1 << 31) - 1
MAX_U16 = (1 << 16) - 1

HEADER_LENGTH = 48
MAX_PACKET_LENGTH = 65535
EXT_HEADER_LENGTH = 4
MIN_EXT_TOTAL = 16
MAC_KEY_ID_LENGTH = 4
VALID_DIGEST_LENGTHS = (0, 16, 20)

ENCODE_FIELDS = [
    "leap",
    "version",
    "mode",
    "stratum",
    "poll",
    "precision",
    "root_delay",
    "root_dispersion",
    "reference_id",
    "reference_timestamp",
    "originate_timestamp",
    "receive_timestamp",
    "transmit_timestamp",
    "extensions",
    "auth",
]
OPTIONAL_ENCODE_FIELDS = frozenset({"auth"})

EXT_FIELDS = ("type", "value")
AUTH_FIELDS = ("key_id", "digest")
DECODE_FIELDS = ("packet_hex", "auth_digest_bytes")

HEX_DIGITS = frozenset("0123456789abcdef")


class ParamError(Exception):
    """The JSON request itself is malformed (exit code 2)."""


class PacketError(Exception):
    """The binary packet / its wire structure is malformed (exit code 3)."""


def round_half_even(numerator, denominator):
    """Round the rational numerator/denominator to the nearest integer.

    Ties (exact one-half) resolve to the nearest even integer.
    """
    if denominator <= 0:
        raise AssertionError("denominator must be positive")
    negative = numerator < 0
    whole, remainder = divmod(abs(numerator), denominator)
    doubled = 2 * remainder
    if doubled > denominator:
        whole += 1
    elif doubled == denominator and (whole & 1):
        whole += 1
    return -whole if negative else whole


def as_int(value, name, low, high):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ParamError("field %r must be an integer" % name)
    if not low <= value <= high:
        raise ParamError("field %r out of range" % name)
    return value


def parse_lower_hex(value, name):
    """Strict lowercase even-length hexadecimal string -> bytes."""
    if not isinstance(value, str) or len(value) % 2:
        raise ParamError("field %r must be lowercase even-length hex" % name)
    for ch in value:
        if ch not in HEX_DIGITS:
            raise ParamError("field %r must be lowercase even-length hex" % name)
    return bytes.fromhex(value)


def parse_packet_hex(value):
    """Hex string for a packet; either letter case is accepted."""
    if not isinstance(value, str) or len(value) % 2:
        raise PacketError("packet_hex must be even-length hexadecimal")
    for ch in value:
        if not (ch in HEX_DIGITS or "A" <= ch <= "F"):
            raise PacketError("packet_hex must be hexadecimal")
    return bytes.fromhex(value)


def encode_timestamp(name, micros):
    if not isinstance(micros, int) or isinstance(micros, bool) or micros < 0:
        raise ParamError("field %r must be a non-negative integer" % name)
    seconds, remainder = divmod(micros, MICROS_PER_SECOND)
    if seconds > MAX_U32:
        raise ParamError("field %r out of range" % name)
    fraction = round_half_even(remainder * FRAC_UNITS_PER_SECOND,
                               MICROS_PER_SECOND)
    if fraction > MAX_U32:
        raise ParamError("field %r out of range" % name)
    return struct.pack(">II", seconds, fraction)


def decode_timestamp(octets):
    seconds, fraction = struct.unpack(">II", octets)
    return seconds * MICROS_PER_SECOND + round_half_even(
        fraction * MICROS_PER_SECOND, FRAC_UNITS_PER_SECOND
    )


def encode_fixed(name, micros, signed):
    if not isinstance(micros, int) or isinstance(micros, bool):
        raise ParamError("field %r must be an integer" % name)
    scaled = micros * FIXED_UNITS_PER_SECOND
    if scaled % MICROS_PER_SECOND:
        raise ParamError("field %r is not exactly representable in 16.16"
                         % name)
    wire = scaled // MICROS_PER_SECOND
    low, high = (MIN_I32, MAX_I32) if signed else (0, MAX_U32)
    if not low <= wire <= high:
        raise ParamError("field %r out of range" % name)
    return struct.pack(">i" if signed else ">I", wire)


def decode_fixed(octets, signed):
    (wire,) = struct.unpack(">i" if signed else ">I", octets)
    return round_half_even(wire * MICROS_PER_SECOND, FIXED_UNITS_PER_SECOND)


def validate_object(obj, allowed, required, what):
    if not isinstance(obj, dict):
        raise ParamError("%s must be a JSON object" % what)
    keys = set(obj)
    missing = required - keys
    if missing:
        raise ParamError("missing key %r" % sorted(missing)[0])
    extra = keys - allowed
    if extra:
        raise ParamError("unexpected key %r" % sorted(extra)[0])


def encode_extensions(raw):
    if not isinstance(raw, list):
        raise ParamError("field 'extensions' must be a list")
    chunks = []
    for index, item in enumerate(raw):
        name = "extensions[%d]" % index
        validate_object(item, set(EXT_FIELDS), set(EXT_FIELDS), name)
        ext_type = as_int(item["type"], name + ".type", 0, MAX_U16)
        payload = parse_lower_hex(item["value"], name + ".value")
        total = EXT_HEADER_LENGTH + len(payload)
        if total < MIN_EXT_TOTAL or total % 4:
            raise ParamError("%s total length must be >= %d and a multiple "
                             "of 4" % (name, MIN_EXT_TOTAL))
        if total > MAX_PACKET_LENGTH:
            raise PacketError("packet exceeds %d bytes" % MAX_PACKET_LENGTH)
        chunks.append(struct.pack(">HH", ext_type, total))
        chunks.append(payload)
    return b"".join(chunks)


def encode_auth(raw):
    if raw is None:
        return b""
    name = "auth"
    validate_object(raw, set(AUTH_FIELDS), set(AUTH_FIELDS), name)
    key_id = as_int(raw["key_id"], name + ".key_id", 0, MAX_U32)
    digest = parse_lower_hex(raw["digest"], name + ".digest")
    if len(digest) not in (16, 20):
        raise ParamError("auth.digest must be 16 or 20 bytes")
    return struct.pack(">I", key_id) + digest


def encode_packet(model):
    allowed = set(ENCODE_FIELDS)
    required = allowed - OPTIONAL_ENCODE_FIELDS
    validate_object(model, allowed, required, "packet")

    leap = as_int(model["leap"], "leap", 0, 3)
    version = as_int(model["version"], "version", 1, 4)
    mode = as_int(model["mode"], "mode", 1, 5)
    stratum = as_int(model["stratum"], "stratum", 0, 16)
    poll = as_int(model["poll"], "poll", -128, 127)
    precision = as_int(model["precision"], "precision", -128, 127)

    header = bytearray()
    header.append((leap << 6) | (version << 3) | mode)
    header.append(stratum)
    header += struct.pack(">bb", poll, precision)
    header += encode_fixed("root_delay", model["root_delay"], signed=True)
    header += encode_fixed("root_dispersion", model["root_dispersion"],
                           signed=False)

    reference_id = parse_lower_hex(model["reference_id"], "reference_id")
    if len(reference_id) != 4:
        raise ParamError("reference_id must be exactly 4 bytes")
    header += reference_id

    for key in ("reference_timestamp", "originate_timestamp",
                "receive_timestamp", "transmit_timestamp"):
        header += encode_timestamp(key, model[key])

    if len(header) != HEADER_LENGTH:
        raise AssertionError("bad base header length")

    body = header + encode_extensions(model["extensions"])
    body += encode_auth(model.get("auth"))

    if len(body) > MAX_PACKET_LENGTH:
        raise PacketError("packet exceeds %d bytes" % MAX_PACKET_LENGTH)
    return bytes(body)


def decode_extensions(octets, end):
    """Parse extension TLVs spanning octets[HEADER_LENGTH:end]."""
    result = []
    offset = HEADER_LENGTH
    while offset < end:
        if end - offset < EXT_HEADER_LENGTH:
            raise PacketError("truncated extension field header")
        ext_type, declared = struct.unpack_from(">HH", octets, offset)
        if declared < MIN_EXT_TOTAL or declared % 4:
            raise PacketError("invalid extension field length")
        if offset + declared > end:
            raise PacketError("extension field runs past packet end")
        payload = octets[offset + EXT_HEADER_LENGTH:offset + declared]
        result.append({"type": ext_type, "value": payload.hex()})
        offset += declared
    return result


def decode_packet(model):
    validate_object(model, set(DECODE_FIELDS), set(DECODE_FIELDS), "request")
    digest_length = as_int(model["auth_digest_bytes"],
                           "auth_digest_bytes", 0, 20)
    if digest_length not in VALID_DIGEST_LENGTHS:
        raise ParamError("auth_digest_bytes must be 0, 16 or 20")
    packet = parse_packet_hex(model["packet_hex"])

    total = len(packet)
    if total < HEADER_LENGTH:
        raise PacketError("packet shorter than 48-byte base header")
    if total > MAX_PACKET_LENGTH:
        raise PacketError("packet exceeds %d bytes" % MAX_PACKET_LENGTH)

    flags = packet[0]
    leap = flags >> 6
    version = (flags >> 3) & 0x7
    mode = flags & 0x7
    if not 1 <= version <= 4:
        raise PacketError("unsupported NTP version")
    if not 1 <= mode <= 5:
        raise PacketError("illegal NTP mode")
    stratum = packet[1]
    if stratum > 16:
        raise PacketError("stratum out of range")
    poll, precision = struct.unpack_from(">bb", packet, 2)

    body_end = total
    auth = None
    if digest_length:
        mac_length = MAC_KEY_ID_LENGTH + digest_length
        if total - HEADER_LENGTH < mac_length:
            raise PacketError("packet too short for declared auth trailer")
        body_end = total - mac_length

    extensions = decode_extensions(packet, body_end)

    if digest_length:
        mac_start = body_end
        key_id = struct.unpack_from(">I", packet, mac_start)[0]
        digest = packet[mac_start + MAC_KEY_ID_LENGTH:
                        mac_start + MAC_KEY_ID_LENGTH + digest_length]
        auth = {"key_id": key_id, "digest": digest.hex()}

    return {
        "leap": leap,
        "version": version,
        "mode": mode,
        "stratum": stratum,
        "poll": poll,
        "precision": precision,
        "root_delay": decode_fixed(packet[4:8], signed=True),
        "root_dispersion": decode_fixed(packet[8:12], signed=False),
        "reference_id": packet[12:16].hex(),
        "reference_timestamp": decode_timestamp(packet[16:24]),
        "originate_timestamp": decode_timestamp(packet[24:32]),
        "receive_timestamp": decode_timestamp(packet[32:40]),
        "transmit_timestamp": decode_timestamp(packet[40:48]),
        "extensions": extensions,
        "auth": auth,
    }


def emit_error(kind, message):
    sys.stderr.write(json.dumps(
        {"error": kind, "message": message}, separators=(",", ":")
    ) + "\n")


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ParamError("duplicate key %r" % key)
        obj[key] = value
    return obj


def main(argv):
    if len(argv) != 2:
        emit_error("ParamError", "usage: python ntp.py <subcommand>")
        return 2
    command = argv[1]
    if command == "encode-packet":
        handler = encode_packet
    elif command == "decode-packet":
        handler = decode_packet
    else:
        emit_error("ParamError", "unknown subcommand")
        return 2

    try:
        try:
            request = json.loads(sys.stdin.buffer.read(),
                                 object_pairs_hook=_reject_duplicate_keys)
        except (ValueError, UnicodeDecodeError):
            raise ParamError("invalid JSON input")
        result = handler(request)
    except ParamError as exc:
        emit_error("ParamError", str(exc))
        return 2
    except PacketError as exc:
        emit_error("PacketError", str(exc))
        return 3

    if command == "encode-packet":
        packet_hex = result.hex()
        output = {"packet_hex": packet_hex, "length": len(result)}
    else:
        output = result
    sys.stdout.write(json.dumps(output, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
