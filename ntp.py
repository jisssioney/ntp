#!/usr/bin/env python3
"""NTP 报文模型与编解码（仅标准库、确定性、不联网）。

公开入口::

    python ntp.py encode-packet   # stdin JSON -> {"packet_hex":..., "length":...}
    python ntp.py decode-packet   # stdin JSON -> 同字段顺序的报文 JSON

成功退出码 0；参数错误（ParamError）退出码 2；报文结构错误（PacketError）退出码 3。
"""

import json
import sys

HEADER_LEN = 48
MAX_PACKET_LEN = 65535
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1

# 四个时间戳：线上为 32 位秒 + 32 位小数（1/2^32 秒），模型为整数微秒。
# 微秒 -> 定点: f = us * 2^32 / 10^6 = us * 2^26 / 15625
_FRAC_NUM = 1 << 26
_FRAC_DEN = 15625

_HEX_CHARS = set("0123456789abcdefABCDEF")

# 编码输入的固定字段顺序（authentication 为可选字段）。
PACKET_FIELDS = [
    "leap_indicator",
    "version",
    "mode",
    "stratum",
    "poll",
    "precision",
    "root_delay",
    "root_dispersion",
    "reference_id",
    "reference_timestamp",
    "origin_timestamp",
    "receive_timestamp",
    "transmit_timestamp",
    "extensions",
]
AUTH_FIELDS = ("key_id", "digest")
EXT_FIELDS = ("type", "value")
TIMESTAMP_FIELDS = PACKET_FIELDS[9:13]
DIGEST_LENGTHS = (16, 20)


class ParamError(Exception):
    """请求参数错误：退出码 2。"""


class PacketError(Exception):
    """报文二进制结构错误：退出码 3。"""


def _is_int(value):
    # JSON 布尔在 Python 中也是 int 子类，但类型语义不符。
    return isinstance(value, int) and not isinstance(value, bool)


def _require_key(obj, key):
    if key not in obj:
        raise ParamError("missing key: %s" % key)


def _int_field(obj, key, low, high):
    _require_key(obj, key)
    value = obj[key]
    if not _is_int(value):
        raise ParamError("key must be an integer: %s" % key)
    if value < low or value > high:
        raise ParamError("key out of range [%d, %d]: %s" % (low, high, key))
    return value


def _usec_to_fixed(usec):
    """整数微秒 -> 64 位 NTP 定点值；最近值，恰好居中向偶数取整。"""
    q, r = divmod(usec * _FRAC_NUM, _FRAC_DEN)
    twice = 2 * r
    if twice > _FRAC_DEN:
        q += 1
    elif twice == _FRAC_DEN and (q & 1):
        q += 1
    return q


def _fixed_to_usec(fixed):
    """64 位 NTP 定点值 -> 整数微秒；最近值，恰好居中向偶数取整。"""
    q, r = divmod(fixed * _FRAC_DEN, _FRAC_NUM)
    twice = 2 * r
    if twice > _FRAC_NUM:
        q += 1
    elif twice == _FRAC_NUM and (q & 1):
        q += 1
    return q


def _hex_bytes(value, what):
    """严格偶数位十六进制字符串 -> bytes。

    非字符串属于 JSON 类型错误（ParamError）；字符串但奇数位或含非十六进制
    字符属于报文结构错误（PacketError）。
    """
    if not isinstance(value, str):
        raise ParamError("%s must be a hexadecimal string" % what)
    if len(value) % 2 or any(c not in _HEX_CHARS for c in value):
        raise PacketError("%s is not valid even-length hexadecimal" % what)
    return bytes.fromhex(value)


# --------------------------------------------------------------------------- #
# encode-packet
# --------------------------------------------------------------------------- #

def _encode_schema(obj):
    """第一遍：校验 JSON 结构与取值范围，只抛 ParamError。"""
    if not isinstance(obj, dict):
        raise ParamError("request body must be a JSON object")

    for key in PACKET_FIELDS:
        _require_key(obj, key)
    allowed = set(PACKET_FIELDS) | {"authentication"}
    for key in obj:
        if key not in allowed:
            raise ParamError("unexpected key: %s" % key)

    spec = {}
    spec["leap_indicator"] = _int_field(obj, "leap_indicator", 0, 3)
    spec["version"] = _int_field(obj, "version", 1, 4)
    spec["mode"] = _int_field(obj, "mode", 1, 5)
    spec["stratum"] = _int_field(obj, "stratum", 0, 16)
    spec["poll"] = _int_field(obj, "poll", -128, 127)
    spec["precision"] = _int_field(obj, "precision", -128, 127)
    spec["root_delay"] = _int_field(obj, "root_delay", -(1 << 31), U32_MAX >> 1)
    spec["root_dispersion"] = _int_field(obj, "root_dispersion", 0, U32_MAX)

    for key in TIMESTAMP_FIELDS:
        value = _int_field(obj, key, 0, U64_MAX)
        fixed = _usec_to_fixed(value)
        if fixed > U64_MAX:
            raise ParamError("key out of range for 64-bit NTP timestamp: %s" % key)
        spec[key] = fixed

    raw_id = obj["reference_id"]
    if not isinstance(raw_id, str):
        raise ParamError("reference_id must be a hexadecimal string")
    spec["reference_id"] = raw_id

    extensions = obj["extensions"]
    if not isinstance(extensions, list):
        raise ParamError("extensions must be an array")
    ext_specs = []
    for i, item in enumerate(extensions):
        where = "extensions[%d]" % i
        if not isinstance(item, dict):
            raise ParamError("%s must be an object" % where)
        for key in EXT_FIELDS:
            if key not in item:
                raise ParamError("%s missing key: %s" % (where, key))
        for key in item:
            if key not in EXT_FIELDS:
                raise ParamError("%s has unexpected key: %s" % (where, key))
        ext_type = item["type"]
        if not _is_int(ext_type) or not 0 <= ext_type <= 0xFFFF:
            raise ParamError("%s.type must be an integer in [0, 65535]" % where)
        ext_value = item["value"]
        if not isinstance(ext_value, str):
            raise ParamError("%s.value must be a hexadecimal string" % where)
        ext_specs.append((ext_type, ext_value))
    spec["extensions"] = ext_specs

    if "authentication" in obj:
        auth = obj["authentication"]
        if not isinstance(auth, dict):
            raise ParamError("authentication must be an object")
        for key in AUTH_FIELDS:
            if key not in auth:
                raise ParamError("authentication missing key: %s" % key)
        for key in auth:
            if key not in AUTH_FIELDS:
                raise ParamError("authentication has unexpected key: %s" % key)
        key_id = auth["key_id"]
        if not _is_int(key_id) or not 0 <= key_id <= U32_MAX:
            raise ParamError("authentication.key_id must be an integer in [0, 2^32-1]")
        digest = auth["digest"]
        if not isinstance(digest, str):
            raise ParamError("authentication.digest must be a hexadecimal string")
        spec["authentication"] = (key_id, digest)
    else:
        spec["authentication"] = None

    return spec


def encode_packet(obj):
    spec = _encode_schema(obj)

    # 第二遍：构造二进制，十六进制与结构问题在此抛 PacketError。
    packet = bytearray()
    packet.append(
        (spec["leap_indicator"] << 6)
        | (spec["version"] << 3)
        | spec["mode"]
    )
    packet.append(spec["stratum"])
    packet.append(spec["poll"] & 0xFF)
    packet.append(spec["precision"] & 0xFF)
    packet += spec["root_delay"].to_bytes(4, "big", signed=True)
    packet += spec["root_dispersion"].to_bytes(4, "big", signed=False)

    ref_id = _hex_bytes(spec["reference_id"], "reference_id")
    if len(ref_id) != 4:
        raise PacketError("reference_id must encode exactly 4 bytes")
    packet += ref_id

    for key in TIMESTAMP_FIELDS:
        packet += spec[key].to_bytes(8, "big", signed=False)

    for ext_type, ext_value in spec["extensions"]:
        value = _hex_bytes(ext_value, "extension value")
        total = 4 + len(value)
        if total < 16 or total % 4:
            raise PacketError(
                "extension field total length must be >= 16 and a multiple of 4"
            )
        packet += ext_type.to_bytes(2, "big", signed=False)
        packet += total.to_bytes(2, "big", signed=False)
        packet += value

    if spec["authentication"] is not None:
        key_id, digest_hex = spec["authentication"]
        digest = _hex_bytes(digest_hex, "authentication.digest")
        if len(digest) not in DIGEST_LENGTHS:
            raise PacketError("authentication digest must be 16 or 20 bytes")
        packet += key_id.to_bytes(4, "big", signed=False)
        packet += digest

    if len(packet) > MAX_PACKET_LEN:
        raise PacketError(
            "packet length %d exceeds upper limit %d" % (len(packet), MAX_PACKET_LEN)
        )

    return {
        "packet_hex": packet.hex(),
        "length": len(packet),
    }


# --------------------------------------------------------------------------- #
# decode-packet
# --------------------------------------------------------------------------- #

def _decode_schema(obj):
    if not isinstance(obj, dict):
        raise ParamError("request body must be a JSON object")
    for key in ("packet_hex", "auth_digest_bytes"):
        _require_key(obj, key)
    for key in obj:
        if key not in ("packet_hex", "auth_digest_bytes"):
            raise ParamError("unexpected key: %s" % key)
    packet_hex = obj["packet_hex"]
    if not isinstance(packet_hex, str):
        raise ParamError("packet_hex must be a hexadecimal string")
    digest_len = obj["auth_digest_bytes"]
    if not _is_int(digest_len) or digest_len not in (0, 16, 20):
        raise ParamError("auth_digest_bytes must be one of 0, 16, 20")
    return packet_hex, digest_len


def decode_packet(obj):
    packet_hex, digest_len = _decode_schema(obj)

    if len(packet_hex) % 2 or any(c not in _HEX_CHARS for c in packet_hex):
        raise PacketError("packet_hex is not valid even-length hexadecimal")
    data = bytes.fromhex(packet_hex)

    if len(data) < HEADER_LEN:
        raise PacketError("packet shorter than fixed 48-byte header")
    if len(data) > MAX_PACKET_LEN:
        raise PacketError(
            "packet length %d exceeds upper limit %d" % (len(data), MAX_PACKET_LEN)
        )

    first = data[0]
    leap_indicator = first >> 6
    version = (first >> 3) & 0x07
    mode = first & 0x07
    stratum = data[1]
    poll = data[2]
    if poll >= 128:
        poll -= 256
    precision = data[3]
    if precision >= 128:
        precision -= 256

    # 线上非法模式/版本/层数属于报文结构错误，而非请求参数错误。
    if not 1 <= version <= 4:
        raise PacketError("illegal NTP version in packet: %d" % version)
    if not 1 <= mode <= 5:
        raise PacketError("illegal NTP mode in packet: %d" % mode)
    if stratum > 16:
        raise PacketError("illegal stratum in packet: %d" % stratum)

    root_delay = int.from_bytes(data[4:8], "big", signed=True)
    root_dispersion = int.from_bytes(data[8:12], "big", signed=False)
    reference_id = data[12:16].hex()

    timestamps = [
        _fixed_to_usec(int.from_bytes(data[off:off + 8], "big", signed=False))
        for off in range(16, 48, 8)
    ]

    trailer_len = 4 + digest_len if digest_len else 0
    if len(data) - HEADER_LEN < trailer_len:
        raise PacketError("packet too short for the declared authentication trailer")
    ext_end = len(data) - trailer_len

    extensions = []
    pos = HEADER_LEN
    while pos < ext_end:
        if ext_end - pos < 4:
            raise PacketError("residual bytes do not form a complete extension field")
        ext_type = int.from_bytes(data[pos:pos + 2], "big", signed=False)
        ext_len = int.from_bytes(data[pos + 2:pos + 4], "big", signed=False)
        if ext_len < 16 or ext_len % 4:
            raise PacketError(
                "extension field total length must be >= 16 and a multiple of 4"
            )
        if ext_len > ext_end - pos:
            raise PacketError("extension field length exceeds packet boundary")
        value = data[pos + 4:pos + ext_len]
        extensions.append({"type": ext_type, "value": value.hex()})
        pos += ext_len

    result = {
        "leap_indicator": leap_indicator,
        "version": version,
        "mode": mode,
        "stratum": stratum,
        "poll": poll,
        "precision": precision,
        "root_delay": root_delay,
        "root_dispersion": root_dispersion,
        "reference_id": reference_id,
        "reference_timestamp": timestamps[0],
        "origin_timestamp": timestamps[1],
        "receive_timestamp": timestamps[2],
        "transmit_timestamp": timestamps[3],
        "extensions": extensions,
    }

    if digest_len:
        key_id = int.from_bytes(data[ext_end:ext_end + 4], "big", signed=False)
        digest = data[ext_end + 4:ext_end + 4 + digest_len]
        result["authentication"] = {
            "key_id": key_id,
            "digest": digest.hex(),
        }

    return result


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #

def _error_line(error, message):
    return json.dumps(
        {"error": error, "message": message},
        separators=(",", ":"),
        ensure_ascii=False,
    )


def main(argv):
    if len(argv) != 2 or argv[1] not in ("encode-packet", "decode-packet"):
        sys.stderr.write(
            _error_line(
                "ParamError",
                "usage: python ntp.py {encode-packet|decode-packet} < JSON",
            )
            + "\n"
        )
        return 2
    subcommand = argv[1]

    try:
        raw = sys.stdin.buffer.read()
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ParamError("standard input is not a valid JSON object")
        if subcommand == "encode-packet":
            result = encode_packet(obj)
        else:
            result = decode_packet(obj)
    except ParamError as exc:
        sys.stderr.write(_error_line("ParamError", str(exc)) + "\n")
        return 2
    except PacketError as exc:
        sys.stderr.write(_error_line("PacketError", str(exc)) + "\n")
        return 3

    # 全部校验与构造成功后才写 stdout，失败时不产生任何部分结果。
    out = json.dumps(result, separators=(",", ":"), ensure_ascii=False)
    sys.stdout.buffer.write(out.encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
