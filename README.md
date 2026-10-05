# ntp

从零实现的网络时间同步协议客户端与选源框架，仅用 Python 标准库、不联网。

- 入口：`python ntp.py <子命令>`
- 所有时间推进与轮询必须由显式事件时钟驱动；时间以定点微秒表示，同一报文序列必须产生逐字节一致的同步决策。
- 结果与统计统一写成 JSON，浮点数按固定小数位格式化。

## 测试

    python -m unittest discover

## 报文编解码

两个子命令均从标准输入读取一个 JSON 对象，向标准输出写一行 JSON：

    python ntp.py encode-packet   # 报文描述 -> {"packet_hex":..., "length":...}
    python ntp.py decode-packet   # {"packet_hex":..., "auth_digest_bytes":0|16|20} -> 报文描述

- 基础头固定 48 字节；扩展字段总长 ≥16 且为 4 的倍数，按输入顺序原样保留 `type`/`value`；
  认证尾部为 4 字节 key_id 加 16 或 20 字节摘要。
- 四个时间戳统一为相对 NTP 纪元的非负整数微秒，与线上 64 位定点互转采用最接近值、
  居中向偶取整，保证解码后再编码逐字节一致。
- `reference_id`、扩展值与摘要使用小写偶数位十六进制；报文总长上限 65535 字节。
- 参数错误向 stderr 输出 `{"error":"ParamError",...}` 并以 2 退出；
  报文结构错误输出 `PacketError` 并以 3 退出；成功退出码为 0。
