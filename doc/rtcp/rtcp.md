# RTCP 协议文档

> RTCP是Reverse Tcp的缩写，对应核心的协议动作ROpen

本文基于当前代码实现和近期语义修订整理，目标是说明 `cyfs-gateway` 中 RTCP 的线协议、建链流程、开流流程和关键字段语义。实现入口主要在：

- `src/components/cyfs-gateway-lib/src/rtcp/package.rs`
- `src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs`
- `src/components/cyfs-gateway-lib/src/rtcp/datagram.rs`
- `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs`

这里的 RTCP 是项目内自定义协议，不是 RFC 里的 Real-time Transport Control Protocol。

配置 `on_new_tunnel_hook_point` 控制 tunnel 来源的示例见：[rtcp_on_new_tunnel_hook_point_example.md](/Users/liuzhicong/project/cyfs-gateway/doc/rtcp_on_new_tunnel_hook_point_example.md)

通过固定 SOCKS5 端口把客户端接入 RTCP 网络的示例见：[rtcp_socks_proxy_example.md](/Users/liuzhicong/project/cyfs-gateway/doc/rtcp_socks_proxy_example.md)

## 1. 协议目标

RTCP 解决的是“设备之间只有 RTCP 端口可达，业务端口不可直连”时的服务访问问题。它有三个核心能力：

- 建立 A 和 B 之间的长连接 tunnel。
- 在 tunnel 上协商新的加密数据流，用来访问对端 TCP 服务。
- 在同一套机制上承载“伪 UDP”Datagram。

RTCP 的默认监听端口是 `2980/TCP`。

## 2. 角色与连接模型

RTCP 区分两类承载连接：

- `Tunnel`：长连接控制通道，用来收发 `Hello`、`Ping`、`Open`、`ROpen` 等控制包。
- `Stream`：为某个业务流单独建立的新 stream leg。direct tunnel 下它是新的 TCP 连接；bootstrap-backed tunnel 下它是通过 tunnel 框架拿到的新底层 stream。建立后立即切到对称加密，承载真实业务字节流或 datagram 字节流。

一个 tunnel 建立后，两端都可以基于该 tunnel 再创建新的 stream。但两端对“谁来主动建立 stream leg”判断不同：

- 主动发起 tunnel 的一侧：`can_direct = true`，后续优先走 `Open`。
- 被动接受 tunnel 的一侧：`can_direct = false`，后续优先走 `ROpen`。

这不是协议层的对等性差异，而是当前实现里的建流策略差异。

### 2.1 Tunnel URL 与 stack id

RTCP 在 tunnel 框架里使用的 URL 形态是：

```text
rtcp://<stack-id>/<target-stream-id>
```

其中 `<stack-id>` 由 `parse_rtcp_stack_id()` 解析，当前支持两种形式：

- `<did>[:port]`：直连目标 RTCP stack，未写端口时使用默认 `2980`。
- `<percent-encoded bootstrap URL>@<did>[:port]`：先用 bootstrap URL 通过 tunnel 框架拿到底层 byte stream，再在这条 stream 上建立外层 RTCP tunnel。

`<target-stream-id>` 由 `open_stream()` / `create_datagram_client()` 解释：

- 如果 percent-decode 后是带 scheme 的完整 URL，则按 `dest_port = 0`、`dest_host = <完整 URL>` 发送给对端。
- 否则按 path 第一段解析 `host:port`、`:port` 或 `[ipv6]:port`。

## 3. 线协议总览

RTCP 在线上有两种首部格式。

### 3.1 控制包格式

控制包格式定义在 `package.rs`，头部固定 8 字节：

```text
0               2 3   4               8
+---------------+---+---+---------------+--------------...
| len(u16, BE)  |jp |cmd| seq(u32, BE)  | JSON body
+---------------+---+---+---------------+--------------...
```

字段说明：

- `len`
  - 2 字节，大端。
  - 表示整个包总长度，包含 `len` 字段本身。
  - 当前实现限制 `len <= 65535`。
- `json_pos`
  - 1 字节。
  - 表示 JSON 正文的起始偏移。
  - 当前发送端固定写死为 `8`。
  - 接收端只校验 `json_pos >= 6`，然后按 `json_pos - 2` 在剩余缓冲区中定位 JSON，因此当前实现实际要求它等于 8。
- `cmd`
  - 1 字节，命令字。
- `seq`
  - 4 字节，大端。
  - 用于请求/响应关联，尤其是 `Open/OpenResp`。
- `JSON body`
  - UTF-8 编码 JSON。
  - 不再做额外长度字段，直接由 `len` 推导。

### 3.2 HelloStream 特殊首包

当 `len == 0` 时，这不是控制包，而是一个特殊的 `HelloStream` 首包：

```text
0               2 34
+---------------+----------------------------------------+
| 0x0000        | stream_id(32 bytes raw ascii bytes)    |
+---------------+----------------------------------------+
```

说明：

- `HelloStream` 只能出现在一条新 stream leg 的第一个包；后续再出现会被拒绝。
- 当前实现中 `stream_id` 实际上是 `16` 个随机字节的十六进制字符串，因此线上固定是 `32` 字节 ASCII。
- `HelloStream` 只用来把这条新 stream leg 绑定到某个待建立的业务流；它不是 JSON 包。

## 4. 命令字与包体字段

当前实现支持的 `cmd` 如下：

| cmd | 名称 | 方向 | 用途 |
| --- | --- | --- | --- |
| 1 | `Hello` | tunnel 建立时 | 认证并建立控制通道 |
| 2 | `HelloAck` | tunnel 握手 | §14.2 关键确认首包，承载服务端 challenge |
| 9 | `HelloAckConfirm` | tunnel 握手 | §14.2 发起端 echo challenge，证明持有 AES key |
| 3 | `Ping` | tunnel 内 | 存活探测 |
| 4 | `Pong` | tunnel 内 | `Ping` 的响应 |
| 5 | `ROpen` | tunnel 内 | 请求对端反向建立一条 stream leg |
| 6 | `ROpenResp` | tunnel 内 | `ROpen` 的响应 |
| 7 | `Open` | tunnel 内 | 请求对端准备接收一条由本端主动建立的 stream |
| 8 | `OpenResp` | tunnel 内 | `Open` 的响应 |

### 4.1 Hello

```json
{
  "from_id": "did:...",
  "to_id": "did:...",
  "my_port": 2980,
  "tunnel_token": "<jwt>",
  "device_doc_jwt": "<optional jwt>"
}
```

字段说明：

- `from_id`
  - 发起端声明的逻辑来源设备身份。
  - 可以是 `did:dev:<pkx>`，也可以是 `did:web` / `did:bns` / hostname 这类名字身份。
  - 线协议上应尽量保留这个逻辑语义；从名字身份解析到 `did:dev` 是 RTCP 内部的认证和 key 归一化步骤，不要求调用方预先把名字改写成 `did:dev`。
  - 如果同时携带 `device_doc_jwt`，则要求它能证明 `from_id` 对应的 canonical `did:dev` 设备身份，而不是简单做字符串相等比较。
- `to_id`
  - 发起端声明的逻辑目标设备身份。
  - 同样可以是 `did:dev` 或名字身份。`to_id` 的语义应保留“我要连哪个逻辑设备”，内部再自动解析到 canonical `did:dev` 做验签、keying 和 tunnel 复用判断。
- `my_port`
  - 发起端 RTCP 栈监听端口。
  - 接收端后续会把它当成“回连该设备 RTCP 端口”的目标端口。
- `tunnel_token`
  - 必填。
  - 一个 EdDSA JWT，里面携带本次 tunnel 的临时密钥交换信息。
- `device_doc_jwt`
  - 可选。
  - 跨 zone 首次接入时很重要，允许接收端在还不知道 `from_id` 对应设备公钥时完成名字身份到 canonical `did:dev` 的证明、准入和 token 验签。

### 4.2 tunnel_token 载荷

`tunnel_token` 的 JWT payload 为：

```json
{
  "aud": "buckyos-rtcp-v2-hello",
  "to": "<target logical did hostname>",
  "from": "<source logical did hostname>",
  "xpub": "<hex encoded 32-byte x25519 public key>",
  "exp": 1711111111,
  "nonce": "<hex encoded 16-byte random>"
}
```

字段说明：

- `aud`
  - 必填。固定为 `buckyos-rtcp-v2-hello`。
  - 接收端的 `Validation` 显式 `set_audience(&[RTCP_HELLO_AUD])` 并将 `aud` 列入 `required_spec_claims`；任何不带或不等于该字符串的 token 一律拒绝。
  - 与 `HelloAck` 用的 `buckyos-rtcp-v2-ack` 互不兼容，杜绝“confused deputy”——一条捕获到的 Hello token 不能被重放成 ack，反之亦然。
  - 同时是协议版本号：未来不兼容升级会改 `aud` 后缀，旧实现自然解码失败，无需带外协商版本。
- `to`
  - 发起端认为的目标逻辑设备 host name。
  - 接收端不应只做原始字符串比较；它应把 `to` 自动解析到 canonical `did:dev`，并确认该 DEV DID 等于本机设备身份。这样 `did:web` / `did:bns` 形式仍保留业务语义，同时不会削弱“token 只能给本机使用”的校验。
- `from`
  - 发起端逻辑设备 host name。
  - 接收端会校验它与 `Hello.from_id` 表达的是同一个设备身份；比较时以解析后的 canonical `did:dev` 为准。
- `xpub`
  - 发起端本次握手的**一次性** X25519 公钥，16 进制编码。
  - v2 中该公钥与设备长期身份完全无关——每次 `create_tunnel()` 都现场生成新的 `EphemeralSecret`/`PublicKey`，握手结束后即丢弃。
  - 接收端不再据此推导 AES key；它的作用仅是把发起端的临时公钥送上对端，由对端结合自己的临时私钥完成 ECDH（详见 §5.4）。
- `exp`
  - JWT 过期时间。
  - 当前生成时为“当前时间 + `TUNNEL_TOKEN_EXP_SECS`（60 秒）”；接收端的 `Validation` 显式设 `leeway = JWT_LEEWAY_SECS`（同为 60 秒），所以实际签名接受窗口是 `[exp - leeway, exp + leeway]`。
- `nonce`
  - 必填。16 字节随机数，16 进制编码。
  - 接收端维护 `(source_dev_did, nonce)` 的短期 cache（容量上限 16 KiB）；每条记录的保留期固定为 `exp + JWT_LEEWAY_SECS`，与签名接受窗口的上界对齐，杜绝“签名仍合法但 nonce 已被清理”的重放缝隙。
  - 不再是可选字段；缺失 `nonce` 的 token 在 JWT 解码阶段就会失败。

### 4.3 HelloAck / HelloAckConfirm

`HelloAck`（接收端发起，**明文**）：

```json
{
  "ack_token": "<eddsa jwt signed by responder>",
  "challenge": "<hex encoded 16-byte random>",
  "responder_id": "<responder logical did hostname>"
}
```

`HelloAck.ack_token` 的 JWT payload 为：

```json
{
  "aud": "buckyos-rtcp-v2-ack",
  "to": "<initiator logical did hostname>",
  "from": "<responder logical did hostname>",
  "xpub": "<hex encoded 32-byte responder ephemeral x25519 public key>",
  "peer_xpub": "<echo of Hello.tunnel_token.xpub>",
  "exp": 1711111111,
  "nonce": "<hex encoded 16-byte random>"
}
```

`HelloAckConfirm`（发起端回送，走 AEAD 记录层）：

```json
{
  "challenge_echo": "<same hex string as HelloAck.challenge>"
}
```

说明：

- 三条包共同构成 §14.2 的 v2 3-message handshake：发起端 `Hello`（明文）→ 接收端 `HelloAck`（明文）→ 发起端 `HelloAckConfirm`（AEAD）。
- `HelloAck`
  - **明文**发送，发送时点紧接 `Hello` 校验通过、但**早于**任何一侧把承载流包成 `EncryptedStream`。
  - `ack_token`
    - 接收端用自己长期 Ed25519 私钥签发的 EdDSA JWT，承担 v2 中“证明该临时公钥确实属于这个 responder”的职责（旧版靠静态 X25519 提供这层身份锚定，v2 把它移到这条 JWT 上）。
    - `aud` 必须等于 `buckyos-rtcp-v2-ack`；与 Hello 的 `aud` 隔离。
    - `from` / `to` 仍保留 responder / initiator 的逻辑设备语义；校验时解析到 canonical DEV DID 后比较，避免名字字符串差异影响身份判断。
    - `xpub` 是接收端为本次握手新生成的临时 X25519 公钥；与设备长期 X25519 无关。
    - `peer_xpub` 必须 echo 发起端 Hello 中的 `xpub`，从而把 ack 绑死到这一次握手——即便攻击者拿到同一台 responder 在另一次会话中签出的合法 ack，也无法拼接到本次握手里冒用。
    - `exp`、`nonce` 行为与 Hello token 一致，复用同一个 `TUNNEL_TOKEN_EXP_SECS` / `JWT_LEEWAY_SECS`。
  - `challenge` 是接收端为本次握手随机生成的 16 字节十六进制串，发起端必须在 `HelloAckConfirm` 里原样回写。
  - `responder_id` 用于日志和 sanity check，不是身份认证锚点；如需校验，也应按 canonical DEV DID 比较，而不是要求它与 `create_tunnel()` 的原始目标名字字符串完全一致。
- `HelloAckConfirm`
  - 发起端在收到并通过 `ack_token` 校验后，先用 `(initiator_eph, responder_eph)` 完成 ECDH，HKDF 派生出本次会话的 `(aes_key, iv)`（详见 §5.4），然后才把承载流包成 `EncryptedStream`，并以 AEAD 记录形式发出 `HelloAckConfirm`。
  - 接收端收到此 AEAD 记录后，用自己派生的同一把 `(aes_key, iv)` 解密：解密成功即意味着对端确实持有 `responder_eph` 派生的会话密钥，且 `challenge_echo` 必须与自己发出的 challenge 完全一致，才会真正接纳 tunnel。
- `HelloAck` / `HelloAckConfirm` 的 `seq` 复用 Hello 的 seq（`0`）。`HelloAck` 因为是明文，不参与 AEAD 计数；`HelloAckConfirm` 是该方向 AEAD 序列上的第一条记录。
- 双侧对这两条包都有 15 秒超时（`HELLO_HANDSHAKE_TIMEOUT`）：超时即判定握手失败，释放承载流与 `(aes_key, iv)` 槽位。

### 4.4 Ping / Pong

`Ping`：

```json
{
  "timestamp": 1711111111
}
```

`Pong`：

```json
{
  "timestamp": 0
}
```

说明：

- `Ping` 由 `Tunnel::ping()` 主动发送。
- 收到 `Ping` 后，对端立即回 `Pong`，复用同一个 `seq`。
- 当前实现不会把 `Ping` 的时间戳原样带回，`Pong.timestamp` 固定为 `0`。
- 当前没有自动心跳线程，`ping()` 是按需调用。

### 4.5 Open / ROpen

`Open` 和 `ROpen` 的 JSON 结构完全相同：

```json
{
  "streamid": "<32-char hex string>",
  "purpose": 0,
  "dest_port": 80,
  "dest_host": "127.0.0.1"
}
```

兼容性说明：

- 反序列化时同时兼容 `streamid` 和 `stream_id`。
- 当前发送端写的是 `streamid`。

字段说明：

- `streamid`
  - 一条业务 stream 的会话标识。
  - 当前实现是 `16` 随机字节的十六进制字符串，因此长度固定 `32`。
  - 它还有第二层作用：解码成 16 字节后，直接作为该业务 stream 的 IV/nonce。
- `purpose`
  - 可选。
  - `0` 或缺省表示普通字节流 `Stream`。
  - `1` 表示 `Datagram` 模式。
  - 当前代码只定义了 `Stream = 0` 和 `Datagram = 1`；不存在不加密的 raw stream/raw datagram 协议枚举。
- `dest_port`
  - 目标端口。
- `dest_host`
  - 目标主机。
  - 可选。可以是 IP、域名，也可以在 `dest_port == 0` 时直接塞一个完整 URL。

当前上层实现对目标地址的解释规则是：

- 若 `dest_port != 0`：按普通 `tcp://dest_host:dest_port` 语义处理。
- 若 `dest_port == 0`：要求 `dest_host` 是一个带 scheme 和 port 的完整 URL，例如 `tcp://example.com:443/path`。

### 4.6 OpenResp / ROpenResp

```json
{
  "result": 0
}
```

当前实现中的 `result` 约定：

- `0`：成功。
- `1`：当前仅在 `OpenResp` 使用，表示接收端 pending `Open` 配额已满。
- `2`：当前仅在 `ROpenResp` 使用，表示对端无法建立反向 stream leg。

注意：

- `OpenResp.result` 和 `ROpenResp.result` 都会按 `seq` 投递给等待者。
- 调用方收到非零 `result` 会快速失败，并释放等待 `HelloStream` 的槽位。
- 这些响应码仍不是完整的错误模型；目前只覆盖“成功 / pending Open 配额满 / reconnect 失败”这几类实现内错误。

## 5. 认证、密钥交换与加密

RTCP v2 的认证锚点是双方设备的长期 Ed25519 身份；会话密钥则完全来自双方现场生成的临时 X25519 密钥对，握手结束后即丢弃。这是与 v1 的关键区别——v1 用设备长期 Ed25519 私钥转换出的**静态** X25519 私钥参与 DH，捕获到该长期密钥就能解密所有历史会话；v2 提供前向安全（forward secrecy）。

### 5.1 本地长期密钥

本地 RTCP 栈启动时会加载设备私钥：

- Ed25519 私钥（`this_device_ed25519_sk`）：唯一用途是签发本端发出的 `tunnel_token`（Hello）和 `ack_token`（HelloAck）。
- v2 不再加载或派生静态 X25519 私钥；旧版的 `this_device_x25519_sk` 字段已被移除。会话密钥所需的 X25519 私钥每次握手现场生成（`EphemeralSecret::random()`），永不落盘、永不复用。

### 5.2 发起侧如何生成 Hello tunnel_token

发起侧 `create_tunnel()` 时执行：

1. 解析目标逻辑设备 DID。输入可以是 `did:dev`，也可以是 `did:web` / `did:bns` / hostname。
2. 将目标逻辑 DID 解析到 canonical `did:dev` 设备身份，并取出该设备的长期 Ed25519 验签公钥：
   - 默认走 `resolve_ed25519_exchange_key(remote_did)`。
   - 如果是 `did:web` 且 DID doc 路径失败，当前实现会 fallback 到 web host 的 TXT 记录，依次尝试 `DEV=` JWT 和 `PKX=` 字段提取设备公钥，并据此得到 canonical `did:dev`。
   - `did:bns` / `did:web` 这类名字 DID 的作用是表达逻辑目标；转换成 `did:dev` 是协议栈内部步骤，不改变调用方的 `from` / `to` 语义。
   - 该 Ed25519 公钥会随 `InitiatorHandshakeState` 一起持有到收到 `HelloAck` 时再用——v2 会用它直接验证 `ack_token` 的签名，因此不需要二次解析。
3. 现场生成一次性 X25519 密钥对 `(my_secret, my_public)`（`EphemeralSecret::random()`）；私钥仅在收到 `HelloAck` 后用于一次性的 ECDH，之后被消耗。
4. 生成 16 字节随机 `nonce`。
5. 构造 `TunnelTokenPayload { aud: "buckyos-rtcp-v2-hello", to, from, xpub: hex(my_public), exp: now + 60s, nonce }` 并用本地 Ed25519 私钥签名。
6. 不再在发起阶段计算任何对称密钥——v2 的 AES key / IV 必须等到 `HelloAck` 中拿到 `responder_eph` 才能派生。

### 5.3 接收侧如何确认来源身份

收到 `Hello` 后，接收侧先确定“该用哪个公钥验签 `tunnel_token`”。

有两条路径：

1. `device_doc_jwt` 存在
   - 先不验签解析 JWT，拿到 `owner`。
   - 解析 owner 的 auth key。
   - 用 owner 公钥正式验证 `device_doc_jwt`。
   - 校验 `device_doc_jwt` 证明出的 canonical `did:dev` 与 `hello.from_id` 解析出的 canonical `did:dev` 是同一设备。
   - 从设备文档的默认 key 提取设备 Ed25519 公钥。
   - 用这个设备公钥验证 `tunnel_token`。

2. `device_doc_jwt` 不存在
   - 直接根据 `hello.from_id` 解析 canonical `did:dev` 和设备公钥。
   - 用该设备公钥验证 `tunnel_token`。

无论 `from_id` 使用名字还是 `did:dev`，认证成功后 RTCP 内部都会得到一个 canonical source DEV DID。这个 DEV DID 用于 nonce cache、tunnel key 和会话身份锚定；原始名字身份仍保留其逻辑语义，供日志、策略和上层业务理解。

#### 5.3.1 关于匿名访问：为什么 `did:dev:xxx` 直接放行不是漏洞

第 2 条路径里，接收侧只用 `from_id` 自带的公钥验了一下 `tunnel_token` 就放行进入握手——很多人第一眼会把它当成安全漏洞。这里澄清设计意图：

- **rtcp stack 这一层只做认证（authentication），不做授权（authorization）。** 它要回答的唯一问题是“from 是否真的掌握它所声称身份的私钥”。对 `did:dev:xxx` 这种自描述身份，公钥就内嵌在 DID 里，签名验过即“证明完毕”，没有外部信任根需要查，也没有任何东西可以不一致。
- **“放行”不等于“可访问服务”。** 是否接受这条连接、能访问什么，由上层 `on_new_tunnel_hook_point` 策略决定（见 §11、§12）。认证层只是把“可信的事实”交给策略层，准入是策略层的事。
- **匿名访问是被刻意支持的一等模式，不是疏忽。** BuckyOS 的取向是“默认用正确身份，但要让匿名访问 zone 外 / 非熟人服务很容易打开”：
  - 随手起的客户端（如 `rtcp_get`）用一次性 `did:dev` 即可零成本访问，走路径 2；
  - 严肃 app 访问自己的 app service，用名字 DID + `device_doc_jwt` 的实名身份，走路径 1，让接收侧策略能识别 `owner` / `zone`，同时内部仍锚定到 canonical `did:dev`。
- **两条路径喂给策略层的字段，信任级别不同**，写策略时务必区分：
  - `owner` 是权威的（路径 1 真查名字系统并用 owner 公钥验了签）；
  - `zone_did` / `name` 只随 owner——当 owner 是自证的 `did:dev` 时它们可被任意填写。
  - 因此“只收自己 zone 的设备”这类策略必须锚在 `owner == <我的 zone owner>`，而**不能**只看“带没带 `device_doc_jwt`”或只匹配 `zone_did`。

一句话：认证层对匿名友好（默认放行 = 默认支持匿名），把“要不要实名、要不要熟人”这个价值判断交给策略层去收紧。

### 5.4 tunnel 会话密钥派生

v2 的会话密钥派生过程是双方对称的，完全由现场生成的临时 X25519 密钥对提供，且把整个握手上下文绑进 KDF。

接收侧（responder）在验签 `Hello.tunnel_token` 通过、并通过 §14.2 的 nonce-cache 检查后：

1. 现场生成一次性 X25519 密钥对 `(resp_secret, resp_public)`。
2. 构造 `TunnelAckTokenPayload { aud: "buckyos-rtcp-v2-ack", to: initiator_host, from: this_host, xpub: hex(resp_public), peer_xpub: <Hello.xpub 原文>, exp, nonce }` 并用本端 Ed25519 私钥签名得到 `ack_token`。
3. 随机生成 16 字节 `challenge`。
4. 把 `RTcpHelloAckPackage { ack_token, challenge, responder_id }` 以**明文**写到承载流上。
5. 用 `resp_secret` 与 `Hello.xpub` 解码出的 32 字节做 ECDH，得到 `shared_secret`。
6. 走 §5.4.1 的 HKDF 派生 `(aes_key, iv)`，再把承载流包成 `EncryptedStream`（responder 方向），等待 AEAD 形式的 `HelloAckConfirm`。

发起侧（initiator）在收到明文 `HelloAck` 后：

1. 用 `state.responder_ed25519_pk_der`（即 §5.2 步骤 2 解析到的 responder 长期 Ed25519 公钥）验证 `ack_token` 的 EdDSA 签名。
2. 校验 `ack_token.from / to / aud / nonce / exp`，其中 `from` / `to` 按 canonical DEV DID 比较；并显式校验 `peer_xpub == 自己 Hello 中的 xpub_hex`——这一步杜绝把别的会话里 responder 签出的合法 ack 拼接到本次握手。
3. 用 `state.my_secret` 与 `ack_token.xpub` 解码出的 32 字节做 ECDH，得到与 responder 完全相同的 `shared_secret`。
4. 走 §5.4.1 的 HKDF 派生 `(aes_key, iv)`，把承载流包成 `EncryptedStream`（initiator 方向）。
5. 在该加密流上发出 AEAD 形式的 `HelloAckConfirm { challenge_echo }`，作为对持有同一把 `(aes_key, iv)` 的证明。

#### 5.4.1 HKDF 派生

```
PRK    = HKDF-Extract(salt = None, IKM = shared_secret)             // RFC 5869，HMAC-SHA-256
ctx    = "|" || init_did || "|" || resp_did
       || "|" || init_xpub_hex || "|" || resp_xpub_hex
       || "|" || init_nonce || "|" || resp_nonce
aes_key (32 bytes) = HKDF-Expand(PRK, "buckyos-rtcp-v2 aes256-key" || ctx)
iv      (16 bytes) = HKDF-Expand(PRK, "buckyos-rtcp-v2 iv-salt"   || ctx)
```

要点：

- **协议域分离**：两条 `info` 串都以 `buckyos-rtcp-v2 ...` 开头，确保即使未来出现共享同一对长期 Ed25519 密钥的其它 BuckyOS 协议，也不会派生出与 RTCP 碰撞的密钥。
- **完整握手上下文**：`ctx` 把双方 DID、双方临时 X25519 公钥、双方 nonce 全部塞进 HKDF 的 `info`。任何一处不一致——例如攻击者把不同 ack 拼到本次 Hello——就算碰巧通过签名校验，也会派生出对端无法复现的密钥，下一条 AEAD 记录直接解密失败。
- **AES key 与 IV 独立派生**：v1 把 `xpub` 的前 16 字节直接当 IV，与 AES key 共享同一个一次性公钥来源；一旦 RNG 出现碰撞，相同 `(key, IV)` 会被复用。v2 用两条不同 `info` 串各自展开，IV 与 AES key 在密码学上彼此独立。
- 派生材料消费完毕后，`my_secret`（`EphemeralSecret`）自动 drop——move-only 类型保证它只能被 `diffie_hellman` 消费一次。

业务 stream（`Open` / `ROpen` 后的 `streamid`）仍然复用 tunnel 派生出来的 `aes_key`，但 base IV 换成 `streamid` 解码后的 16 字节；nonce 派生规则与 §5.5 一致。

### 5.5 加密范围

RTCP v2 中明文与加密的分界线是 `HelloAckConfirm`：

- `Hello`、`HelloAck`、`HelloStream` 三类首包都是**明文**。
- `HelloAckConfirm` 是该方向 AEAD 上的第一条记录；之后双方的所有控制包与业务字节都通过 `EncryptedStream` 走 AEAD 记录层。

`EncryptedStream` 使用 `AES-256-GCM` AEAD 记录层，同时提供保密性和完整性。线上记录格式：

```
+--------+---------------------+---------+
| len u16| ciphertext (N)      | tag(16) |
+--------+---------------------+---------+
```

- `len` 为大端序 `u16`，等于 `N + 16`（密文长度加上 GCM tag），不包含自身 2 字节。
- 每条记录的明文长度 `N` 不超过 `16 KiB`。
- tag 是 16 字节 GCM 认证标签；任何篡改都会被接收端识别并使 `poll_read` 报 `InvalidData`。

IV/nonce 选择规则：

- tunnel 控制通道
  - base IV 是 §5.4.1 HKDF 用 `info = "buckyos-rtcp-v2 iv-salt" || ctx` 展开的 16 字节；与 AES key 在 KDF 层独立，且把双方 DID/xpub/nonce 全部绑入。
- 业务 stream
  - 使用 `streamid` 解码后的 16 字节作为 base IV（仍由 `streamid` 直接派生）。
- 每条记录的 96-bit GCM nonce 由以下步骤派生：
  1. 以 base IV 和方向标签（`"rtcp-aead-nonce/A"` 或 `"rtcp-aead-nonce/B"`）做 `SHA-256`，取前 12 字节作为该方向的 `nonce_base`。
  2. 将当前方向的 64-bit 记录序号以大端序 XOR 到 `nonce_base` 的低 8 字节，得到每条记录的唯一 nonce。
- tunnel 的两端根据角色（initiator/responder）选择不同方向的 `nonce_base`，保证两端写方向的 (key, nonce) 空间互不重叠。

业务 stream 复用的是“所属 tunnel 的同一把 AES key”，只是 base IV 改成 `streamid` 对应的值，nonce 派生规则相同。

## 6. Tunnel 建立流程

下面描述的是当前协议语义和实现目标，而不是早期设计。

### 6.1 发起端 A

1. 解析目标 `rtcp://<did>[:port]`，其中 `<did>` 是调用方表达的逻辑目标，可以是名字 DID 或 `did:dev`。
2. 调用 `name_client::resolve_ips(remote_did)` 得到候选 IP 列表。候选名展开（stack id host、`to_host_name()`、`to_raw_host_name()`、`to_string()`）、DID info 文档的 `ip`/`ips`/`all_ip` 字段、以及地址排序（scope / 家族偏好 / 历史 RTT）全部由 name-client 负责，RTCP 不再自行组装或排序。
3. 对候选 IP 采用 **Happy Eyeballs 风格的并发竞速**（详见 §10），而非串行尝试：
   - 先对首个地址发起 attempt；
   - 每 `250ms` 起一条新的 attempt，直到耗尽候选；
   - 单个 TCP connect 超过 `10s` 即视为失败，让位给后续 attempt。
4. 每条 attempt 各自独立：TCP connect 成功后，该 attempt 单独生成 `tunnel_token`、一次性 X25519 密钥对（`InitiatorHandshakeState`）、随机 `nonce`；握手材料不跨 attempt 复用。AES key/IV **不在此时派生**，要等到收到对应的 `HelloAck`。
5. 在该 TCP 连接上发送明文 `Hello`。
6. 在仍未加密的承载流上读取明文 `HelloAck`，验证 `ack_token`（含 `peer_xpub` 必须 echo 自己 Hello 的 `xpub`）；通过后用 `(my_secret, ack_token.xpub)` 完成 ECDH，走 §5.4.1 的 HKDF 派生 `(aes_key, iv)`，把承载流包成 `EncryptedStream`（initiator 方向），并以 AEAD 形式发出 `HelloAckConfirm`。
7. **首个** 走完 `Hello` → `HelloAck` 验证 → `HelloAckConfirm` 写出的 attempt 获胜：以解析后的 canonical local DEV DID + canonical remote DEV DID 注册成 tunnel，标记 `can_direct = true`，加入 `tunnel_map`；其余 in-flight attempt 随 `FuturesUnordered` 被 drop 而取消。
8. 获胜 attempt 的 Hello RTT 通过 `name_client::record_connection_outcome`（`MeasurementLayer::Application`）回写给 name-client，作为下次排序依据；失败 attempt 则按失败原因记录 `Unreachable` 或 `Timeout`。
9. 启动 tunnel 读循环。

### 6.2 接收端 B

1. `accept()` 新 TCP。
2. 读取首包。
3. 若首包是 `Hello`，进入 tunnel 建立流程。
4. 校验来源身份和 `tunnel_token`（`aud == "buckyos-rtcp-v2-hello"`、签名、`from`），并执行 §14.2 的 anti-replay 检查：
   - token payload 里的 `to` 必须解析到本机 canonical DEV DID。
   - `(source_dev_did, nonce)` 必须尚未出现过。
5. 从 `Hello.my_port` 提取对端后续回连所需的 RTCP 监听端口。
6. 现场生成一次性 X25519 密钥对 `(resp_secret, resp_public)` 和随机 `challenge`，签发 `ack_token`（`aud == "buckyos-rtcp-v2-ack"`，`peer_xpub == Hello.xpub`），并以**明文**形式把 `HelloAck { ack_token, challenge, responder_id }` 发到承载流上。
7. 用 `(resp_secret, Hello.xpub)` 做 ECDH，走 §5.4.1 的 HKDF 派生 `(aes_key, iv)`；把承载流包成 `EncryptedStream`（responder 方向），等待 AEAD 形式的 `HelloAckConfirm` 并校验 `challenge_echo`。
8. 只有 key-confirmation 成功后，才调用 `listener.on_new_tunnel(...)` 做准入控制。
9. 准入通过后，才把这条连接包装成 tunnel，标记 `can_direct = false`，并按 canonical DEV DID 注册到 `tunnel_map`。
10. 启动 tunnel 读循环。

### 6.3 当前实现上的重要事实

- `Hello` 之后还有一次 `HelloAck`（明文）/ `HelloAckConfirm`（AEAD）的往返，必须成功才算 tunnel 建立；详见 §14.2。
- **TCP 三次握手成功不等于 tunnel 建立成功**。当前实现的建链完成点是“协议层 key-confirmation 成功”，不是 `TcpStream::connect()` 返回。
- `can_direct` 的设置时机也在 key-confirmation 之后，而不是刚拿到一条 TCP 连接时。
- `Hello.from_id` / `Hello.to_id` 承载逻辑来源和逻辑目标语义；真正的身份校验会把它们解析到 canonical `did:dev` 后再比较。名字到 DEV 的转换是内部动作，不应要求调用方在协议语义上放弃 `did:web` / `did:bns`。
- 对端后续回连端口来自 `Hello.my_port`，不是当前 TCP 连接的源端口。
- v2 的 AES key/IV 完全派生自双方临时 X25519 密钥对，与设备长期密钥无关——即便长期 Ed25519 私钥之后被泄露，也无法解密任何已经结束的会话。

### 6.4 Tunnel Key 与设备唯一性

RTCP 的 tunnel key 只用于协议栈内部复用和去重，不是对外 URL 语义。它必须基于 canonical DEV DID，而不是用户传入的名字：

- direct tunnel key: `<local_dev_did>_<remote_dev_did>`
- bootstrap-backed tunnel key: `<local_dev_did>_<remote_dev_did>|bootstrap=<bootstrap_url>`

这个规则保证“从当前 stack 到另一个真实设备 stack 有且仅有一条 tunnel”。名字 DID 的公钥发生变化时，解析出的 remote DEV DID 也会变化，旧 tunnel 不应继续被复用；协议栈应建立新 tunnel，并让旧 tunnel 自然断开或被清理。

反过来，如果用户把同一个设备公钥绑定到多个名字，这些名字会解析到同一个 canonical DEV DID，并共享同一条 tunnel。对 RTCP 来说这是同一个设备，不是多个逻辑设备。用同一把设备公钥表达多个逻辑设备会导致 tunnel 复用、keep_tunnel 状态、准入策略和日志语义混淆；这违反“每个逻辑设备必须有不同设备公钥”的原则，不应通过 name-based tunnel key 兼容。

## 7. Open 流程

`Open` 用在“当前这一侧是 tunnel 主动发起者，`can_direct = true`”的场景。

设 A 是主动建 tunnel 的一侧，B 是被动接受的一侧。A 希望访问 B 的服务。

### 7.1 时序

1. A 生成 `streamid = hex(random[16])`。
2. A 生成新的 `seq`，向 tunnel 发送 `Open(streamid, purpose, dest_host, dest_port)`。
3. B 收到 `Open` 后，先检查 pending inbound `Open` 配额；配额可用时登记一个等待项，键为 `<B.this_device_id>_<streamid>`。
4. B 回 `OpenResp(seq, result=0)`；如果配额已满则回 `OpenResp(seq, result=1)` 并结束本次 Open。
5. A 收到 `OpenResp(result=0)` 后，通过 `build_reconnect_stream()` 建立一条新的 stream leg。
6. A 在这条新 stream leg 上发送 `HelloStream(streamid)`。
7. B 的 RTCP listener 收到该新 stream leg，读到 `HelloStream(streamid)`，查找刚才登记的等待项。
8. A 和 B 两边都把这条新 stream leg 包装成 `EncryptedStream`，AES key 复用 tunnel 的会话 AES key，IV 使用 `streamid` 解出的 16 字节。
9. B 把 stream 交给上层 `on_new_stream()` 或 `on_new_datagram()`。

### 7.2 关键点

- B 会先尝试占用一个 pending inbound `Open` 配额；每个 tunnel 最多 `64` 个等待 `HelloStream` 的 inbound `Open`。
- 如果配额满，B 返回 `OpenResp(result=1)`，A 立即失败，不再建立 `HelloStream`。
- `OpenResp(result=0)` 表示 B 已经登记等待项，A 可以开始建立新的 stream leg。
- 新 stream 不复用 tunnel 控制连接；direct tunnel 会重新建 TCP 连接，bootstrap-backed tunnel 会复用同一份 bootstrap URL 通过 tunnel 框架再拉一条底层 stream。
- direct tunnel 的新 stream 目标地址必须进入 §10 的直连地址选择逻辑：优先尝试上一次成功 IP，但每次 `Open` 都有机会在 250ms 后启动下一个候选 IP，并在成功后更新 RTT / 历史成功记录。
- B 等待 `HelloStream` 的上限是 `30s`；超时后等待项会被清理，迟到或未知的 `HelloStream` 会被关闭。

## 8. ROpen 流程

`ROpen` 用在“当前这一侧是 tunnel 被动接受者，`can_direct = false`”的场景。

设 B 是被动接受 tunnel 的一侧，A 是主动建 tunnel 的一侧。B 希望访问 A 的服务。

### 8.1 时序

1. B 生成 `streamid = hex(random[16])`。
2. B 在本地登记等待项，键为 `<B.this_device_id>_<streamid>`。
3. B 向 tunnel 发送 `ROpen(streamid, purpose, dest_host, dest_port)`。
4. A 收到 `ROpen` 后，通过 `build_reconnect_stream()` 建立一条新的 stream leg：
   - direct tunnel：进入 §10 的直连地址选择逻辑，优先“上一次成功 IP + `Hello.my_port`”，必要时在 250ms 后并发尝试下一个候选 IP。
   - bootstrap-backed tunnel：复用同一份 bootstrap URL，通过 tunnel 框架建立新的底层 stream。
5. 若回连失败，A 回 `ROpenResp(seq, result=2)`。
6. 若回连成功，A 先回 `ROpenResp(seq, result=0)`。
7. A 在新 stream leg 上发送 `HelloStream(streamid)`。
8. B 的 listener 收到新 stream leg 并匹配等待项。
9. A 和 B 两边都把这条新 stream leg 包装成 `EncryptedStream`，AES key 复用 tunnel 的会话 AES key，IV 使用 `streamid`。
10. A 把 stream 交给本地上层，去连接自己这一侧的真实服务。

### 8.2 和 Open 的本质区别

两者的业务目标相同，区别只在“谁来主动建立新的 stream leg”：

- `Open`：由请求方自己去连对端 RTCP 端口。
- `ROpen`：由对端反向连回来。
- `ROpenResp` 会与本地 `HelloStream` 等待并发竞争：如果先收到非零响应，本地立即失败并清理等待项；如果先收到 `HelloStream`，则按成功路径继续。
- 等待 `HelloStream` 的上限同样是 `30s`。

## 9. Datagram 模式

Datagram 并没有单独的 UDP tunnel。当前实现只是把 datagram 封装进一条加密 stream 里。

触发方式：

- `Open/ROpen.purpose = Datagram`

上层字节格式：

```text
+-------------------+-------------------+
| datagram_len u32  | datagram payload  |
+-------------------+-------------------+
```

字段说明：

- `datagram_len`
  - 4 字节，大端。
- `datagram payload`
  - 原始 datagram 内容。

所以 Datagram 模式的真实语义是：

- 建立一条新的 RTCP 加密 stream。
- 在该 stream 上用 `u32 length + payload` 复用多个 datagram。

## 10. 地址解析与连接选择

RTCP 的 tunnel 建立和 direct stream reconnect 都应采用“**排序 + 并发竞速 + 首个可用连接获胜**”的模型，思路参考 RFC 8305（Happy Eyeballs v2）、RFC 6724（地址选择）和 WebRTC ICE（RFC 8445）。

每次 `Open` / `ROpen` 需要建立 direct stream leg 时，都是一次直连链路选择机会。实现不能只因为 tunnel 控制连接仍然可用，就长期固定使用第一次建 tunnel 时选中的 IP。

### 10.1 职责分工

RTCP 自身只负责**连接竞速**；候选展开、地址排序、历史 RTT 缓存统一委托给 `name-client`：

- `name_client::resolve_ips(remote_did)` 负责：
  - 展开候选名（含 `to_host_name()` / `to_raw_host_name()` / `to_string()` 等写法）；
  - 合并 DID info 文档中的 `ip`、`ips`、`all_ip` 字段；
  - 按 scope、地址族偏好、历史 Hello RTT 等因子排序；
  - 必要时走 did-info HTTP fallback。
- `name_client::record_connection_outcome(local_ip, remote_addr, outcome)` 负责沉淀每条 attempt 的结果（成功 RTT / `Unreachable` / `Timeout`），作为下一次 `resolve_ips` 排序的依据。

RTCP 不再在 `rtcp.rs` 里维护候选名拼接、DID info 字段解析或 HTTP fallback 代码。

注意：这里说的是“地址解析”。目标设备 exchange key 的解析仍在 `rtcp.rs` 中有一条 `did:web` TXT fallback 路径，详见 §5.2。

### 10.2 建链与建流的并发竞速策略

`create_tunnel()` 和 direct `build_reconnect_stream()` 的连接阶段遵循下述约束：

- 候选 IP 顺序来自 `resolve_ips`，只决定 attempt 的**启动顺序**，不等于“必须等前一个失败”。
- `create_tunnel()` 的候选地址来自 `resolve_ips(remote_did)`，端口使用目标 RTCP stack port。
- direct stream reconnect 的候选地址优先包含上一次成功的 peer IP，端口使用对端 `Hello.my_port` / RTCP stack port；随后合并 `resolve_ips(remote_did)` 返回的其他 IP，并去重。
- Staggered parallel attempts：首条 attempt 立刻启动；如果 250ms 内没有建立可用连接，则每 `DIRECT_CONNECT_ATTEMPT_DELAY = 250ms` 起一条新 attempt，直到候选耗尽。
- 单条 attempt 的 TCP connect 超时 `DIRECT_TCP_CONNECT_TIMEOUT = 10s`；超时后让位给下一条，而不是阻塞整体。
- `create_tunnel()` 的每条 attempt 独立生成 `tunnel_token`、AES key、一次性 `xpub`，握手材料不跨 attempt 复用。
- `create_tunnel()` 的**获胜判定发生在协议层**，而不是 TCP 层：
  1. TCP connect 成功
  2. 明文 `Hello` 已发送
  3. `HelloAck` 收到且可解密
  4. `HelloAckConfirm` 已回送并通过 §14.2 的 key-confirmation 校验
- direct stream reconnect 的获胜判定是 TCP 连接建立成功，并且后续 `HelloStream(streamid)` 发送成功；失败 attempt 需要继续让其他候选有机会完成。
- 首条满足对应条件的 attempt 获胜：`create_tunnel()` 注册进 `tunnel_map`，direct stream reconnect 返回新 stream leg；其余 in-flight attempt 随之取消。
- 所有 attempt 都失败时才回退到 `TunnelError::ConnectError`，错误消息包含每条 attempt 的失败原因。
- bootstrap-backed tunnel 不在 RTCP direct IP 列表内竞速；它通过 `TunnelManager::open_stream_by_url(bootstrap_url)` 复用同一份 bootstrap URL。若 bootstrap URL 对应的底层 tunnel 自身支持多 IP 或多链路选择，由底层 tunnel 负责。

### 10.3 RTT 统计口径

RTT 统计口径分两类：

- tunnel 建立使用 **Hello 往返时间**（应用层），而不是 TCP SYN/SYN-ACK：在 `Hello` 发出前用 `Instant::now()` 打点，key-confirmation 完成后取 `elapsed()`。
- direct stream reconnect 使用“TCP connect + `HelloStream` 发送完成”的耗时作为本次 stream leg 的成功耗时。
- 成功路径以 `ConnectionOutcome::Success { rtt, layer: MeasurementLayer::Application }` 回写给 name-client；
- 失败路径按错误类型分别记录 `Timeout { elapsed }` 或 `Unreachable`。

这种口径要求只有端到端 connectivity check 通过的路径才计入 RTT：tunnel 建立以 §14.2 的 key-confirmation 为准，direct stream reconnect 以新 stream leg 能成功发送 `HelloStream` 为准。这保证了"能完成 RTCP 协议动作"的路径优先，而不仅仅是"TCP 可达"的路径。

### 10.4 长生命周期 tunnel 的可选优化

如果 tunnel 是长生命周期连接，后续还可以考虑增加后台重评估能力，但这属于优化项，不是当前协议的组成部分：

- 定期对备选 IP 做轻量探测
- 发现明显更优的路径时，先建立新 tunnel
- 迁移上层流量后再关闭旧 tunnel

这和 ICE 的 renomination 思路接近，但 RTCP 目前还没有实现这套机制。

## 11. on_new_tunnel_hook_point 可见字段

这不是线协议字段，但它决定了“隧道建立后，业务栈能看到哪些来源信息”。

`device_doc_jwt` 校验成功时，`on_new_tunnel_hook_point` 当前能拿到：

- `source_addr`
- `source_device_id`
- `source_device_name`
- `source_device_owner`
- `source_zone_did`
- `source_device_doc_jwt`

如果未携带 `device_doc_jwt`，则只保证拿到：

- `source_addr`
- `source_device_id`

## 12. 本地配置与 device_doc_jwt

RTCP stack 的 `device_config_path` 当前支持两类文件内容：

- 设备文档 JSON
- owner 已签名的设备文档 JWT

行为差异：

- 如果本地加载的是 JSON 且设备 DID 是 `did:dev:<pkx>`，RTCP 仍能工作，但发起 `Hello` 时不会自动携带 `device_doc_jwt`。
- 如果本地加载的是 JWT，发起 `Hello` 时会自动把它塞进 `device_doc_jwt` 字段。
- 如果 stack 的设备 DID 是逻辑名字（非 `did:dev:<pkx>`），初始化时必须提供 `device_doc_jwt`，并且发起 `Hello` 时必定携带该 JWT。

因此，跨 zone 首次接入若希望让对端在“尚未知晓本设备公钥”的前提下完成准入，应该配置 JWT 形式的设备文档。

### 12.1 通过 DID 加载本地身份

RTCP stack 支持像 TLS stack 一样只声明一个本端 DID，由 identity manager 自动加载必要的设备身份文件和 Ed25519 私钥，替代显式配置 `key_path` / `device_config_path` / `name` 的方式。

示例：

```yaml
identity_manager:
  public_root_path: /opt/buckyos/local/identity
  security_root_path: /opt/buckyos/security

stacks:
  rtcp:
    protocol: rtcp
    bind: 0.0.0.0:2980
    identity: did:web:device.example.com
    hook_point: {}
```

文件布局沿用 identity manager 的目录规则：

- 设备文档 JWT：`<public_root>/<encoded-did>/device.doc.jwt`
- 设备文档 JSON：`<public_root>/<encoded-did>/did.json`
- 设备认证私钥：`<security_root>/<encoded-did>/authentication.private.pem`

如果同时存在 `device.doc.jwt` 和 `did.json`，RTCP 优先使用 `device.doc.jwt`。这样发起 `Hello` 时可以继续携带 `device_doc_jwt`，便于对端在尚未缓存本设备公钥时完成身份校验。若 `identity` 是逻辑名字（非 `did:dev:<pkx>`），`device.doc.jwt` 是必需的；只有 `did.json` 会被拒绝。

落地约束：

- 一个 RTCP stack 只允许配置一个本端 DID；多 RTCP stack 暂不支持。当前 RTCP 设备身份语义仍是单设备身份、单 stack。
- 加载出的私钥公钥必须与设备文档 default/authentication key 一致；加载出的设备文档 ID 必须与配置 DID 一致。
- 逻辑名字 DID 必须能加载出 `device_doc_jwt`；该 JWT 会随每个新建 tunnel 的 `Hello` 包发送。
- 热更新时不允许静默切换 DID 或私钥；这类变更会被拒绝，要求重启 RTCP stack。

## 13. 当前实现与文义设计的差异

为了避免文档误导，下面这些点要特别说明：

- `HelloAck` 是 v2 3-message handshake 的核心包：携带 responder 签名的 `ack_token`，明文发送，先于密钥派生；`HelloAckConfirm` 才是首条 AEAD 记录。
- `Hello.from_id` / `Hello.to_id` 保留逻辑设备语义；token payload 中的 `from` / `to` + `aud` 会被严格校验，但比较基准是解析后的 canonical DEV DID，而不是原始名字字符串。
- tunnel key 语义以 §6.4 为准：内部复用和去重必须基于 canonical DEV DID。如果实现仍使用原始名字 DID / `remote_stack.did.to_string()` 作为 key，需要修正到 DEV-based key。
- 设备的 X25519 私钥**已被废弃**：v2 中 ECDH 双方都用一次性 `EphemeralSecret`，长期 Ed25519 私钥仅用于签发 Hello/HelloAck JWT。
- 会话密钥不再是 `SHA256(shared_secret)`，而是 HKDF（详见 §5.4.1），且把双方 DID/xpub/nonce 全部绑进 `info`。
- `OpenResp.result` / `ROpenResp.result` 已经会被等待者读取并触发快速失败，但错误码集合仍然很小，不是完整错误模型。
- `Pong.timestamp` 当前固定为 `0`，不是对 `Ping.timestamp` 的镜像。
- tunnel 的首包 `Hello`、`HelloAck` 以及业务 stream 的 `HelloStream` 都是明文；真正加密从 `HelloAckConfirm` / 业务流首条 AEAD 记录开始。
- Datagram 不是 UDP 打洞，而是“在加密 TCP stream 里封装 datagram”。
- `purpose` 当前只支持 `Stream = 0` 和 `Datagram = 1`，没有 raw/no-encryption 模式。

## 14. 安全注意事项与协议 TODO

本节记录的是“当前实现已经确认存在，但暂未完成修订”的协议问题。它们不是建议级优化，而是后续协议升级时必须正式文档化并落地的 TODO。

### 14.1 tunnel 与 stream 完整性保护（已落地）

历史问题：

- 早期实现使用 `AES-256-CTR` 做字节流加密，没有 MAC，也没有 AEAD tag，只提供保密性。
- 链路上的攻击者即使无法解密，也可以对密文做按位篡改，`Open` / `ROpen` / `Ping` / 业务字节都有被静默篡改的风险。
- 两端还使用了相同的 `(key, iv)` 和独立递增的 CTR 计数器，存在 keystream 复用的隐患。

当前实现：

- tunnel 与业务 stream 已升级为 `AES-256-GCM` AEAD 记录层，同时提供保密性与完整性。详情见 §5.5。
- 每条记录的 96-bit nonce 由 `SHA-256(iv || direction)` 派生的 `nonce_base` 与 64-bit 记录序号 XOR 得到；initiator / responder 使用不同方向的 `nonce_base`，两端写方向的 `(key, nonce)` 空间不会碰撞。
- 任何一次解密失败都会立即把读端返回 `InvalidData`，不再向上层回吐可疑明文。
- 读端在收到第一条被认证的 AEAD 记录之前遇到 FIN / `Ok(0)`，一律按 `UnexpectedEof` 上报；避免在没有任何认证证据的情况下把“对端悄悄断开”当作正常结束。
- `RTcpTunnel::close()` 现在真正会关闭写半边并设置关闭标记，`run()` 循环会在下一个读边界退出；`on_new_tunnel` 不再静默替换已存在的 tunnel，而是直接拒绝重复的 `Hello`——否则新旧两条 tunnel 在同一把 `(aes_key, iv)` 上各自从序号 0 开始递增，会把 `(key, nonce)` 空间重新打开。

这是一次 **不兼容的协议升级**：新实现不能与旧的 `AES-256-CTR` 实现互通。部署升级时两端必须一起换到 AEAD 版本。

仍然建议跟进：

- 和 §14.2 的握手重构一起，把记录序号的初始值、方向标签都纳入正式握手确认，避免中途静默切换。

### 14.2 v2 握手：抗重放、密钥确认与前向安全（已落地）

历史问题（v0/v1 阶段）：

- 最早期的 `Hello` 依赖签名过的 `tunnel_token` 建立 tunnel，接收端验完签就直接发布 tunnel：没有 challenge-response，也没有显式 key confirmation。
- v1 引入了 AEAD 加密的 `HelloAck` / `HelloAckConfirm`，关闭了重放替换 tunnel 的窗口；但 ECDH 仍由发起端 ephemeral X25519 ↔ **responder 长期 X25519** 完成，长期密钥泄露后所有历史会话可被解密（无前向安全）。
- v1 的会话密钥是 `SHA256(shared_secret)`，IV 直接取 `xpub` 前 16 字节——AES key 与 IV 共享同一个一次性公钥来源，对 RNG 碰撞没有缓冲。

v2 3-message handshake 语义：

1. **Hello（明文，initiator → responder）**
   - `tunnel_token` payload 形如 §4.2，必填 `aud = "buckyos-rtcp-v2-hello"`、`nonce` 与 `exp = now + 60s`。
   - `xpub` 是发起端**当场生成**的一次性 X25519 公钥；与设备长期身份解耦。
   - 接收端依次校验：
     - JWT EdDSA 签名合法。
     - `aud` 严格等于 `RTCP_HELLO_AUD`（`set_audience` + `required_spec_claims = ["exp", "aud"]`）。
     - `from` 与 `Hello.from_id` 解析到同一个 canonical source DEV DID。
     - `to` 解析到本机 canonical DEV DID——防止把针对 A 的 token 重放到 B。
     - `(source_dev_did, nonce)` 不在短期 cache 中（容量 16 KiB，按 `exp + JWT_LEEWAY_SECS` 自动过期）；命中即立刻拒绝。
2. **HelloAck（明文，responder → initiator）**
   - 接收端通过 §14.2 的 anti-replay 检查后，现场生成新的临时 X25519 密钥对 `(resp_secret, resp_public)` 和随机 16 字节 `challenge`。
   - 用本端 Ed25519 私钥签发 `ack_token`（payload 见 §4.3），关键字段：
     - `aud = "buckyos-rtcp-v2-ack"`，与 Hello 的 audience 严格隔离。
     - `from` / `to` 分别表达 responder / initiator 的逻辑身份，校验时按 canonical DEV DID 比较。
     - `xpub = hex(resp_public)`，公开本端临时公钥。
     - `peer_xpub = Hello.xpub`，把这条 ack 绑到本次握手——攻击者即便拿到同一个 responder 在别的会话里签过的合法 ack，也因为 `peer_xpub` 不匹配而无法拼接到当前会话上。
   - 把 `RTcpHelloAckPackage { ack_token, challenge, responder_id }` 以**明文**形式写到承载流上。
   - 然后用 `(resp_secret, Hello.xpub)` 完成 ECDH，走 §5.4.1 的 HKDF 派生 `(aes_key, iv)`，把承载流包成 `EncryptedStream`（responder 方向），等待 AEAD 形式的 `HelloAckConfirm`。
3. **HelloAckConfirm（AEAD，initiator → responder）**
   - 发起端在仍未加密的承载流上读到明文 `HelloAck`，立即用 §5.2 步骤 2 缓存的 responder 长期 Ed25519 公钥验证 `ack_token`，并校验 `aud` / `from` / `to` / `peer_xpub == 自己 Hello.xpub`；其中 `from` / `to` 按 canonical DEV DID 比较。
   - 任意一项不通过即终止握手，`peer_xpub` 不匹配是 v2 防 ack-splicing 的关键护栏。
   - 通过后用 `(my_secret, ack_token.xpub)` 完成 ECDH，与 responder 派生出**同一把** `(aes_key, iv)`；把承载流包成 `EncryptedStream`（initiator 方向）。
   - 在加密流上发出 `HelloAckConfirm { challenge_echo = ack.challenge }`。
   - 接收端只有在该 AEAD 记录解密成功，且 `challenge_echo` 与本端发出的 `challenge` 完全一致时，才把 tunnel 注册进 `tunnel_map` 并触发 `on_new_tunnel` 回调；否则直接丢弃。

落地后的性质：

- **前向安全（v2 新增）**：会话密钥派生于双方临时 X25519 密钥对的 ECDH，握手结束后 `EphemeralSecret` 立即被消耗丢弃；事后即便长期 Ed25519 私钥被泄露，攻击者也无法解密任何已经结束的 RTCP 会话。
- **Challenge-response + Key-confirmation**：`HelloAck.challenge` 是 responder 每次新生成的随机因子；发起端必须先用派生出的 AES key 把它原样加密回写，才能让接收端接纳 tunnel——这等价于“发起端对 challenge 和会话密钥的持有证明”。
- **Anti-replay**：三层防护——
  1. nonce cache：同一个 Hello token 在 `exp + JWT_LEEWAY_SECS` 窗口内不会二次被接纳；
  2. ack 绑定：即便攻击者同时控制本次承载流并重放 Hello，他也产出不了与 `Hello.xpub` 匹配的 `ack_token`（需要 responder 长期 Ed25519 私钥）；
  3. AEAD key 持有证明：拿到对方临时公钥也无法绕过 ECDH，因此攻击者无法派生 `(aes_key, iv)`，自然无法构造合法的 `HelloAckConfirm`。
- **Audience / 协议域隔离**：Hello 与 HelloAck 的 `aud` 各自固定（`buckyos-rtcp-v2-hello` / `buckyos-rtcp-v2-ack`），同一把 Ed25519 私钥就算被复用到将来其它 BuckyOS 协议，也不能产生交叉认可的 token——这是 confused-deputy 的常见缓解。HKDF 的 `info` 串以 `buckyos-rtcp-v2 ...` 开头，提供进一步的密钥域分离。
- **Ack-splicing 防护**：`ack_token.peer_xpub` 必须 echo 发起端 `Hello.xpub`，把 ack 物理地绑到**这一次**握手；与 `aud = "...-ack"` 配合后，已签出的 ack token 不可能被回收复用到任何其它会话。
- **超时与清理**：`HelloAck` / `HelloAckConfirm` 各自 15 秒超时；一旦超时或包体不合法，接收端立刻关闭承载流并释放占用的 `(aes_key, iv)` 槽位。
- **listener 回调时机**：`listener.on_new_tunnel(...)` 的触发被推迟到 key-confirmation 通过之后；重放者无法让 `on_new_tunnel` 观察到虚假事件。
- **兼容性**：v2 是一次 **不兼容的协议升级**。`tunnel_token` 必须带 `aud` 与 `nonce`；`HelloAck` 改为明文且必须带 `ack_token`；HKDF 派生与 v1 的 `SHA256(shared_secret)` + IV-from-xpub 不同。任何只改一端的部署都会握手失败——`aud` 校验在 JWT 解码阶段就会拒绝旧版 token；新 responder 也不会再用静态 X25519 私钥解 v1 token。两端必须同步升级，且与 §14.1 的 AEAD 切换是同一波协议升级的一部分。

注意事项：

- `nonce_cache` 只在本进程内存里维护；如果一台设备水平扩展成多个 RTCP stack 实例（例如多机负载均衡），需要额外的跨实例抗重放手段。当前实现不提供。
- 60s 的 `TUNNEL_TOKEN_EXP_SECS` + 60s 的显式 `JWT_LEEWAY_SECS`，意味着两端时钟最多允许约 2 分钟偏差；如果部署环境时钟漂移更大，需要在上层配置 NTP 或显式调整 `JWT_LEEWAY_SECS`（同时记得 nonce-cache 的保留期也会随之放大，这是期望的，不要只改签名验证侧）。
- `HelloAck.responder_id` 当前是明文字段，对初始化 tunnel 的身份认证并非必需——真正的身份锚点是 `ack_token` 的 EdDSA 签名（用 §5.2 解析到的 responder 长期 Ed25519 公钥验证），它把 responder 临时 X25519 公钥与设备身份强绑定。保留 `responder_id` 便于日志排查和多身份部署下的 sanity check。
- `EphemeralSecret`（来自 `x25519-dalek`）是 move-only 类型，DH 后即被消费；这是密码学上保证“一次性”的语言级护栏，不要尝试绕过它做密钥复用。

### 14.3 stream 建立超时、配额与清理语义（已落地）

历史问题：

- `Open` / `ROpen` 发出后，等待 `HelloStream` 的槽位如果没有被对端完成，可能长时间占用。
- 早期 `OpenResp` / `ROpenResp` 更接近同步点，调用侧没有可靠消费非零结果码。
- 对端如果持续发送 `Open` 但不完成新连接，会拖住 tunnel 读循环或积累等待项。

当前实现：

- `RTcpStreamBuildHelper::wait_ropen_stream()` 使用固定 `STREAM_WAIT_TIMEOUT = 30s`。
- 等待超时会删除等待项；迟到或未知的 `HelloStream` 会被 `notify_ropen_stream()` 关闭。
- `Open` 的接收侧不在 tunnel 读循环里阻塞等待 `HelloStream`，而是在登记等待项并返回 `OpenResp(result=0)` 后，用后台 task 完成后续接管。
- 每个 tunnel 最多允许 `MAX_PENDING_INBOUND_OPENS = 64` 个并发 inbound `Open` 等待项；超过时直接返回 `OpenResp(result=1)`。
- `OpenResp.result` / `ROpenResp.result` 都会通过 oneshot waiter 交给发起侧：
  - `OpenResp(non-zero)`：发起侧立即失败，不再建立 `HelloStream`。
  - `ROpenResp(non-zero)`：发起侧立即失败并清理等待项。
  - `ROpenResp(0)`：表示对端已接受并正在发送 `HelloStream`，发起侧继续等待。
- 发送 `Open` / `ROpen` 失败时，本地会主动移除对应 waiter，避免依赖 30 秒超时回收。


### 14.4 支持 remote 嵌套的 bootstrap stream URL (已落地)

`tunnel框架.md` 里已经给出了 RTCP 更完整的 URL 设计方向：不仅 target 可以嵌套，remote 的建立过程本身也可以嵌套。例如：

```text
rtcp://socks%3A%2F%2Faaa%3Abbb%40pub.proxy.com%2Fremote.com@remote.com:2981/google.com:443/
```

它表达的是：

1. 先按 `socks://aaa:bbb@pub.proxy.com/remote.com` 拿到底层 byte stream。
2. 再在这条底层 stream 上建立外层 RTCP tunnel。
3. 外层 RTCP 的真实 remote 身份仍然是 `remote.com:2981`。
4. tunnel 建好后，再让 remote 侧继续访问 `google.com:443`。

RTCP authority 的语法：

- `rtcp://<remote>[/...]`：不带 bootstrap，当前直连语义。
- `rtcp://<params>@<remote>[/...]`：带 bootstrap，`<params>` 必须整体 percent-encoding，解码后是一条完整的 stream URL（scheme、authority、path 全部在 `<params>` 里）。
- `<remote>` 始终是 `did[:port]`，代表外层 RTCP 的真实身份；它不受 `<params>` 的影响。

当前实现行为：

- `parse_rtcp_stack_id()` 按最后一个裸 `@` 拆分 authority：左侧 percent-decode 得到 bootstrap URL，右侧按 `<did>[:port]` 解析为 remote。
- `create_tunnel()` 在检测到 bootstrap URL 时，走 `TunnelManager::open_stream_by_url()` 拿到 byte stream 作为 tunnel 承载连接，而不是 `TcpStream::connect(remote_ip:port)`；然后在这条 stream 上正常发送 `Hello`。
- 不带 `params` 时，仍然走“解析 DID → 解析 IP → 直连 RTCP 端口”的旧路径，保持兼容。
- `RTcpTunnel` 的承载流从 `EncryptedStream<TcpStream>` 统一改成 `EncryptedStream<Box<dyn AsyncStream>>`，兼容裸 TCP 和由 tunnel 框架产生的任意 stream；但 `Hello` / `HelloStream` 的线协议格式不变。
- Bootstrap 建立的 tunnel 不再持有直连的 `peer_addr`；后续 `Open` / `ROpen` 通过 §14.5 的 `bootstrap` 上下文复用同一份 bootstrap URL 建立新的 stream leg。

### 14.5 为 remote 嵌套后的建流流程重新绑定 transport 语义

remote 嵌套场景下，`Open` / `ROpen` 的建流动作必须与 tunnel 承载保持一致，否则 tunnel 即便能建立，后续 stream 仍然会退回“直接连 peer IP + RTCP port”的旧模型。

历史问题：

- `Open` 路径下，请求方收到 `OpenResp` 后，会以“当前 tunnel 对端 IP + 对端 RTCP 端口”建立新的 TCP 连接。
- `ROpen` 路径下，对端会根据 `Hello.my_port` 回连新的 TCP 连接。
- 这套流程默认假设两端之间始终存在可直接互连的 RTCP TCP 端口；一旦 tunnel 是经 SOCKS、上层 tunnel 或其他 bootstrap stream 建出来的（14.4 场景），这个假设就不再成立。
- 早期实现对这类 bootstrap-backed tunnel 的处理方式是：`Open` 路径直接返回 `Unsupported` 错误；`ROpen` 路径直接回 `ROpenResp(result=2)`。行为上是拒绝，不是正式可用的 stream 建立机制。

设计要求：

- `RTcpTunnel` 在建立时额外持有一个 `bootstrap` 上下文（bootstrap URL + `TunnelManager`），direct tunnel 为 `None`，bootstrap-backed tunnel 为 `Some(...)`。
- 引入统一的 `build_reconnect_stream` 入口：
  - direct tunnel：按 §10 的 direct stream reconnect 策略建立新 TCP 连接；首选上一次成功 IP，但每次 `Open` / `ROpen` 都要能在 250ms 后尝试后续候选 IP。
  - bootstrap-backed tunnel：调用 `tunnel_manager.open_stream_by_url(bootstrap_url)`，复用与 tunnel 承载流同一份 bootstrap 机制来拉出新的底层 stream。
- `Open` / `ROpen` 的后续建流都改走这个入口：不再假设“peer 必然可直连”，也不再静默退回直连。
- 对这条新 stream 的加密处理保持不变：AES key 复用 tunnel 的会话 AES key，IV 使用 `streamid` 解出的 16 字节，方向仍按“谁 connect+发 HelloStream 谁是 initiator”区分。
- `send_hello_stream` 由接收 `&mut TcpStream` 改为接收任意 `AsyncWrite + Unpin`，以便直接在 bootstrap-backed stream 上发送 HelloStream。
- tunnel 复用键按 §6.4 基于 canonical DEV DID 生成，并在 bootstrap-backed tunnel 上加入 `|bootstrap=<url>` 后缀；direct tunnel 与 bootstrap-backed tunnel、以及不同 bootstrap 路径之间不会互相复用。

遗留语义：

- bootstrap-backed stream 的 `peer_addr` / `local_addr` 不对应任何真实 TCP 端点，当前用 `0.0.0.0:0` 占位上报给 `on_new_stream` / `on_new_datagram`，这些字段在 bootstrap 场景下仅供日志辨认，不可直接作为路由依据。
- 外层 RTCP remote 身份仍然是 `<did>[:port]`；bootstrap URL 仅用于承载传输，不参与对端身份认证——身份仍由 `Hello + tunnel_token` 确认。
- 对方如果也需要走嵌套出站，需要在自己那一侧单独配置，bootstrap URL 不会随协议自动传递。

## 15. 最小实现心智模型

如果只记住 RTCP 的核心机制，可以简化成下面四句话：

1. 先用 `Hello + tunnel_token` 在一个 TCP 连接上建立加密 tunnel。
2. tunnel 只传控制消息，不直接承载业务流。
3. 每次业务访问都要再新建一条 stream leg：direct tunnel 是新的 TCP 连接，bootstrap-backed tunnel 是通过同一 bootstrap URL 拉出的新底层 stream；随后用 `HelloStream(streamid)` 绑定到 tunnel 中的某个 `Open/ROpen` 请求。
4. tunnel 和所有业务 stream 都复用同一把 AES key，但每条业务 stream 用自己的 `streamid` 作为 IV。
