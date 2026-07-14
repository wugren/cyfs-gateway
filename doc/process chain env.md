# cyfs_gateway中process chain执行环境变量说明

cyfs_gateway中各个process chain执行位置都可以通过环境变量获取到当前请求的相关数据，以下为各个process chain能获取到的环境变量说明

## REQ 来源变量命名约定

不同 stack/server 的 `REQ` 字段应尽量使用同一套来源命名，方便 process chain 在 HTTP、TCP、TLS、UDP、RTCP 等入口之间复用规则。

来源类字段按“来源层级前缀 + 来源属性”命名：

| 前缀 | 语义 | 示例 |
| --- | --- | --- |
| `source_` | 当前 hook point 看到的有效来源。没有更精确来源时，通常就是直接连接来源；存在可信还原来源时，可以等同于 `real_source_` | `source_addr`、`source_ip`、`source_port`、`source_did` |
| `conn_source_` | 连接层直接上一跳来源，不穿透 PROXY protocol、RTCP、可信 upstream 等多跳信息 | `conn_source_addr`、`conn_source_ip`、`conn_source_port` |
| `real_source_` | 经过可信机制还原后的原始请求来源，表示跨 upstream/tunnel/proxy 之后仍希望保留的真实来源 | `real_source_addr`、`real_source_ip`、`real_source_port`、`real_source_did` |

来源属性的后缀约定：

| 后缀 | 语义 |
| --- | --- |
| `_addr` | Socket 地址，格式通常为 `IP:PORT` |
| `_ip` | IP 地址 |
| `_port` | 端口 |
| `_did` | 可信身份 DID，例如 RTCP 握手验证出的来源 DID |
| `_device_id` | 设备 ID。已有实现中可能表示 DID 或设备标识；新增字段优先使用更明确的 `_did` |
| `_hostname` | 来源主机名 |
| `_mac` | 来源 MAC |
| `_app_id` | 来源应用 ID |
| `_user_id` | 来源用户 ID |

`real_` 前缀只用于可信来源：例如 PROXY protocol、RTCP 已认证身份、受信任 upstream 写入并经过网关信任边界确认的信息。普通 HTTP 请求头里的 `X-Forwarded-For`、`X-Real-IP` 属于输入数据，只有在明确配置该上一跳可信后，才应转换成 `real_source_ip` / `real_source_addr`。

兼容说明：

- HTTP server 当前已有 `REQ_remote_ip`、`REQ_conn_remote_ip`、`REQ_real_remote_ip` 等变量，语义分别对应当前有效来源、连接层来源、可信还原来源。
- 新增跨协议字段时，推荐在 `REQ` Map 内使用 `source_*` / `conn_source_*` / `real_source_*`，其中 RTCP 身份信息使用 `real_source_did` 表达可信原始来源 DID。
- HTTP 转发链路仍应保留标准头名 `X-Forwarded-For`、`X-Real-IP`、`X-Forwarded-Host`、`X-Forwarded-Proto`；这些是协议兼容头，不作为 process chain 通用字段命名前缀。

## 来源变量统一 TODO

- [x] HTTP server 在 `REQ` Map 中补齐 `source_addr` / `source_ip` / `source_port`、`conn_source_addr` / `conn_source_ip` / `conn_source_port`、`real_source_addr` / `real_source_ip` / `real_source_port`。继续保留现有 `REQ_remote_*`、`REQ_conn_remote_*`、`REQ_real_remote_*` 顶层变量作为兼容别名。
- [x] TCP、TLS、QUIC、UDP、RTCP 等入口统一提供能够可靠获得的 `conn_source_*` 和 `real_source_*` 字段。当前已有的 `source_addr` / `source_ip` / `source_port` 保持兼容；没有可信还原来源时，不构造或伪造 `real_source_*`。
- [x] RTCP 将握手认证得到的来源 DID 暴露为 `REQ.real_source_did`，并保留现有 `REQ.source_device_id`。需要当前有效身份别名时，可同时提供 `REQ.source_did`。
- [x] `forward ip_hash` 获取来源 IP 时，按 `REQ.real_source_ip`、`REQ.source_ip`、HTTP 兼容变量 `REQ_remote_ip` 的顺序回退，确保 HTTP 和非 HTTP process chain 无需手工补字段即可使用同一配置。
- [x] 明确 HTTP `X-Forwarded-For` / `X-Real-IP` 的可信 upstream 配置和解析规则。默认不信任普通客户端传入的转发头；只有直接上一跳属于可信 upstream 时，才允许将其转换为 `real_source_*`。
- [x] 为上述字段增加跨入口测试，至少覆盖直连、PROXY protocol、RTCP 已认证身份、可信 HTTP upstream 和伪造转发头，并验证旧变量在兼容期内保持原有语义。

实现说明（2026-07）：

- HTTP server（`type: http`）的 `REQ` Map 现在提供 9 个保留来源键（见下文表格）。这些键只从连接信息解析，同名 HTTP 头永远不会透出到这些键（读取、遍历、dump 一致），也不可通过 `map-add` / `map-set` / `map-remove` 修改。
- HTTP server 新增可选配置 `trusted_upstreams`（IP 或 CIDR 列表，如 `["127.0.0.1", "10.0.0.0/8"]`）。仅当直接上一跳 IP 命中该列表、且更强机制（PROXY protocol、RTCP 等，即 `StreamInfo.real_src_addr`）未提供可信来源时，才解析转发头：`X-Forwarded-For` 从右向左跳过可信 IP，第一个不可信条目即客户端（全部可信时取最左）；条目非法则整个头作废，回退到 `X-Real-IP`（可配合 `X-Real-Port`）。解析结果写入 `real_source_*` 并成为有效来源 `source_*`（同时反映到 `REQ_remote_*` / `REQ_real_remote_*`）。默认（空列表）不信任任何转发头。
- 从转发头还原的来源可能没有端口，此时只有 `*_addr`（裸 IP）与 `*_ip` 存在，`*_port` 缺失，相应的 `REQ_*_port` 顶层变量也不会创建。
- TCP / TLS / TUN(TCP) 入口通过 `StreamRequest` 新增 `conn_source_addr` / `real_source_addr` 字段派生 `conn_source_*`、`real_source_*`；QUIC / UDP / TUN(UDP) 提供 `conn_source_*`；RTCP stream 入口在 PROXY protocol 存在时提供 `real_source_*`。`real_source_*` 仅在可信还原来源存在时出现。
- `forward ip_hash` 的来源 IP 读取顺序：`REQ.real_source_ip` → `REQ.source_ip` → `REQ_remote_ip`。

## HTTP Request 环境变量


| 变量                       | 类型                            | 说明                                       |
| ------------------------ | ----------------------------- | ---------------------------------------- |
| `REQ_host`               | `Visitor(String, read-only)`  | HTTP `host` 头                            |
| `REQ_method`             | `Visitor(String, read-only)`  | HTTP method，映射到 `REQ.method`             |
| `REQ_content_length`     | `Visitor(String, read-only)`  | HTTP `content-length` 头                  |
| `REQ_content_type`       | `Visitor(String, read-only)`  | HTTP `content-type` 头                    |
| `REQ_user_agent`         | `Visitor(String, read-only)`  | HTTP `user-agent` 头                      |
| `REQ_url`                | `Visitor(String, read/write)` | 请求 URI（path + query，即 `request.uri()`），与 `REQ.uri` 相同；不含 scheme 和 host；设置会更新请求 URI |
| `REQ_remote_ip`          | `String`                      | 当前请求源地址 IP（当前有效来源，与 `REQ.source_ip` 相同；无可信还原来源时即 `StreamInfo.src_addr`） |
| `REQ_remote_port`        | `String`                      | 当前请求源地址端口（与 `REQ.source_port` 相同；来源为转发头还原的裸 IP 时不创建） |
| `REQ_conn_remote_ip`     | `String`                      | 连接层源地址 IP（来自 `StreamInfo.conn_src_addr`，与 `REQ.conn_source_ip` 相同） |
| `REQ_conn_remote_port`   | `String`                      | 连接层源地址端口（来自 `StreamInfo.conn_src_addr`）  |
| `REQ_real_remote_ip`     | `String`                      | 真实源地址 IP（来自 `StreamInfo.real_src_addr` 或可信 upstream 转发头还原，与 `REQ.real_source_ip` 相同；无可信来源时不创建） |
| `REQ_real_remote_port`   | `String`                      | 真实源地址端口（同上，端口未知时不创建）           |
| `REQ_target_ip`          | `String`                      | 当前请求目标地址 IP（来自 `StreamInfo.dst_addr`，可选） |
| `REQ_target_port`        | `String`                      | 当前请求目标地址端口（来自 `StreamInfo.dst_addr`，可选）  |
| `REQ_source_mac`         | `String`                      | 源设备 MAC（可选）                              |
| `REQ_source_hostname`    | `String`                      | 源设备主机名（可选）                               |
| `REQ_source_online_secs` | `String`                      | 源设备当日在线秒数（可选）                            |
| `REQ`                    | `Map`                         | HTTP 请求 Map（见下表）                         |


`REQ` Map 字段（值均为 `CollectionValue::String`）：


| 字段              | 类型       | 说明                         |
| --------------- | -------- | -------------------------- |
| `path`          | `String` | URI path                   |
| `method`        | `String` | HTTP method                |
| `uri`           | `String` | 请求 URI（path + query），与 `REQ_url` 相同；不含 scheme 和 host |
| `version`       | `String` | HTTP version（如 `HTTP/1.1`） |
| `source_addr`   | `String` | 当前有效来源地址（保留键，只读；可信还原来源存在时等于 `real_source_addr`，否则为连接来源） |
| `source_ip`     | `String` | 当前有效来源 IP（保留键，只读）           |
| `source_port`   | `String` | 当前有效来源端口（保留键，只读；来源为转发头还原的裸 IP 时缺失） |
| `conn_source_addr` | `String` | 连接层直接上一跳地址（保留键，只读，来自 `StreamInfo.conn_src_addr`） |
| `conn_source_ip`   | `String` | 连接层直接上一跳 IP（保留键，只读）        |
| `conn_source_port` | `String` | 连接层直接上一跳端口（保留键，只读）        |
| `real_source_addr` | `String` | 可信还原来源地址（保留键，只读；来自 PROXY protocol/RTCP 等机制或可信 upstream 转发头，无可信来源时缺失） |
| `real_source_ip`   | `String` | 可信还原来源 IP（保留键，只读）          |
| `real_source_port` | `String` | 可信还原来源端口（保留键，只读，可能缺失）      |
| `<header-name>` | `String` | 任意请求头名称，对应头值               |


备注：

- 非 UTF-8 的 header 值会被转换为空字符串。
- 上表 9 个 `source_*` / `conn_source_*` / `real_source_*` 为保留键：始终从连接信息解析，客户端发送的同名 HTTP 头不会透出到这些键，也不能通过 `map-add` / `map-set` / `map-remove` 修改。
- `X-Forwarded-For` / `X-Real-IP` 默认只是普通请求头；仅当 server 配置了 `trusted_upstreams` 且直接上一跳命中时，才会按可信规则转换为 `real_source_*`（见"来源变量统一 TODO"一节的实现说明）。

如需完整 HTTP URL（scheme + host + path + query），可自行拼接：`${scheme}://${REQ_host}${REQ_url}`，其中 scheme 需根据实际部署推断（如 TLS 终止则用 `https`，否则用 `http`；若前端有 `X-Forwarded-Proto` 头，可从 `REQ.X-Forwarded-Proto` 获取）。

## HTTP Response 环境变量

`RESP` 主要用于 HTTP `post_hook_point`，表示当前响应头的 Map。


| 变量     | 类型    | 说明                |
| ------ | ----- | ----------------- |
| `RESP` | `Map` | HTTP 响应头 Map（见下表） |


`RESP` Map 字段：


| 字段              | 类型       | 说明           |
| --------------- | -------- | ------------ |
| `<header-name>` | `String` | 任意响应头名称，对应头值 |


说明：

- `RESP` 当前只包含响应 header，不包含 status code 和 HTTP version
- `post_hook_point` 可以通过 `map-add` / `map-set` / `map-remove` 修改 `RESP`
- `RESP` 的修改发生在响应真正写回客户端之前
- 它不是“响应已经开始发送后”的 hook

更完整的配置和限制见 [http_post_hook_point.md](/Users/liuzhicong/project/cyfs-gateway/doc/http_post_hook_point.md)。

## Tcp Stack、TlsStack、TunStack Tcp环境变量


| 变量    | 类型    | 说明          |
| ----- | ----- | ----------- |
| `REQ` | `Map` | 请求 Map（见下表） |


`REQ` Map 字段：


| 字段                   | 类型       | 说明                                                |
| -------------------- | -------- | ------------------------------------------------- |
| `dest_port`          | `String` | 目标端口（u16 字符串化）                                    |
| `dest_host`          | `String` | 目标主机名（可选）                                         |
| `dest_addr`          | `String` | 目标 SocketAddr（可选）                                 |
| `dest_ip`            | `String` | 目标 IP（由 `dest_addr` 派生，可选）                        |
| `app_protocol`       | `String` | 应用层协议标识（可选）                                       |
| `dest_url`           | `String` | 目标 URL（可选）                                        |
| `source_addr`        | `String` | 源 SocketAddr（可选；PROXY protocol 存在时为还原后的来源）        |
| `source_ip`          | `String` | 源 IP（由 `source_addr` 派生，可选）                       |
| `source_port`        | `String` | 源端口（由 `source_addr` 派生，可选）                        |
| `conn_source_addr`   | `String` | 连接层直接上一跳 SocketAddr（可选；TUN 场景为发起端地址）              |
| `conn_source_ip`     | `String` | 连接层直接上一跳 IP（由 `conn_source_addr` 派生，可选）           |
| `conn_source_port`   | `String` | 连接层直接上一跳端口（由 `conn_source_addr` 派生，可选）            |
| `real_source_addr`   | `String` | 可信还原来源 SocketAddr（可选；目前来自 PROXY protocol，无可信来源时缺失） |
| `real_source_ip`     | `String` | 可信还原来源 IP（由 `real_source_addr` 派生，可选）             |
| `real_source_port`   | `String` | 可信还原来源端口（由 `real_source_addr` 派生，可选）              |
| `source_mac`         | `String` | 源 MAC（可选）                                         |
| `source_hostname`    | `String` | 源主机名（可选）                                          |
| `source_online_secs` | `String` | 源设备当日在线秒数（可选）                                     |
| `source_device_id`   | `String` | 源设备 ID（可选）                                        |
| `source_app_id`      | `String` | 源应用 ID（可选）                                        |
| `source_user_id`     | `String` | 源用户 ID（可选）                                        |
| `ext`                | `Map`    | 扩展 Map（可选）                                        |
| `incoming_stream`    | `Any`    | `Arc<Mutex<Option<Box<dyn AsyncStream>>>>` handle |


### Socks Server环境变量


| 变量    | 类型    | 说明          |
| ----- | ----- | ----------- |
| `REQ` | `Map` | 请求 Map（见下表） |


`REQ` Map 字段：


| 字段            | 类型       | 说明                                         |
| ------------- | -------- | ------------------------------------------ |
| `inbound`     | `String` | 入站地址字符串（来自 `StreamInfo.src_addr`，缺失时为空字符串） |
| `target`      | `Map`    | 目标地址 Map（见下表）                              |
| `source_ip`   | `String` | 从 `inbound` 解析出的源 IP（不可解析或缺失时为空字符串）        |
| `source_port` | `String` | 从 `inbound` 解析出的源端口（不可解析或缺失时为空字符串）         |


`REQ.target` Map 字段：


| 字段     | 类型       | 说明                                                           |
| ------ | -------- | ------------------------------------------------------------ |
| `type` | `String` | 目标地址类型：`ip` 或 `domain`                                       |
| `addr` | `String` | 目标地址字符串；`type=ip` 时为 SocketAddr，`type=domain` 时为 `host:port` |
| `port` | `String` | 目标端口                                                         |
| `ip`   | `String` | 目标 IP（仅 `type=ip` 时存在）                                       |
| `host` | `String` | 目标主机名（仅 `type=domain` 时存在）                                   |


备注：Socks 请求环境变量为只读，不支持在 process chain 中写入或删除。

### DNS  Server环境变量


| 变量    | 类型    | 说明          |
| ----- | ----- | ----------- |
| `REQ` | `Map` | 请求 Map（见下表） |


`REQ` Map 字段：


| 字段            | 类型       | 说明                |
| ------------- | -------- | ----------------- |
| `name`        | `String` | 查询的域名             |
| `record_type` | `String` | DNS 记录类型          |
| `source_addr` | `String` | 客户端 IP            |
| `source_port` | `String` | 客户端端口             |
| `dest_addr`   | `String` | 目标 SocketAddr（可选） |
| `dest_ip`     | `String` | 目标 IP（可选）         |
| `dest_port`   | `String` | 目标端口（可选）          |


### SOCKS Server 环境变量


| 变量    | 类型    | 说明                |
| ----- | ----- | ----------------- |
| `REQ` | `Map` | SOCKS 请求 Map（见下表） |


`REQ` Map 字段：


| 字段        | 类型       | 说明                           |
| --------- | -------- | ---------------------------- |
| `inbound` | `String` | 客户端源地址；当前实现里是一个字符串形式的地址，可能为空 |
| `target`  | `Map`    | SOCKS CONNECT 的目标（见下表）       |


`REQ.target` Map 字段：


| 字段     | 类型       | 说明                                 |
| ------ | -------- | ---------------------------------- |
| `type` | `String` | 目标类型，`domain` 或 `ip`               |
| `host` | `String` | 目标域名，仅当 `type=domain` 时存在          |
| `ip`   | `String` | 目标 IP，仅当 `type=ip` 时存在             |
| `port` | `String` | 目标端口                               |
| `addr` | `String` | 目标地址字符串，形如 `host:port` 或 `ip:port` |


示例：

- `${REQ.target.type}`
- `${REQ.target.host}`
- `${REQ.target.port}`

### TUN  Stack Udp 环境变量：


| 变量    | 类型  | 说明          |
| ----- | --- | ----------- |
| `REQ` | Map | 请求 Map（见下表） |


`REQ` Map 字段：


| 字段                 | 类型       | 说明               |
| ------------------ | -------- | ---------------- |
| `dest_addr`        | `String` | 目标 SocketAddr    |
| `dest_ip`          | `String` | 目标 IP            |
| `dest_port`        | `String` | 目标端口             |
| `source_addr`      | `String` | 源 SocketAddr     |
| `source_ip`        | `String` | 源 IP             |
| `source_port`      | `String` | 源端口              |
| `conn_source_addr` | `String` | 连接层直接上一跳 SocketAddr（与 `source_addr` 相同） |
| `conn_source_ip`   | `String` | 连接层直接上一跳 IP      |
| `conn_source_port` | `String` | 连接层直接上一跳端口       |
| `app_protocol`     | `String` | 应用层协议（固定为 `udp`） |


### QUIC  Stack环境变量：


| 变量    | 类型    | 说明          |
| ----- | ----- | ----------- |
| `REQ` | `Map` | 请求 Map（见下表） |


`REQ` Map 字段：


| 字段                   | 类型       | 说明                      |
| -------------------- | -------- | ----------------------- |
| `dest_host`          | `String` | QUIC 握手 SNI server_name |
| `dest_addr`          | `String` | 目标 SocketAddr           |
| `dest_ip`            | `String` | 目标 IP                   |
| `dest_port`          | `String` | 目标端口                    |
| `source_addr`        | `String` | 客户端 SocketAddr          |
| `source_ip`          | `String` | 客户端 IP                  |
| `source_port`        | `String` | 客户端端口                   |
| `conn_source_addr`   | `String` | 连接层直接上一跳 SocketAddr（与 `source_addr` 相同） |
| `conn_source_ip`     | `String` | 连接层直接上一跳 IP            |
| `conn_source_port`   | `String` | 连接层直接上一跳端口             |
| `source_mac`         | `String` | 源 MAC（可选）               |
| `source_hostname`    | `String` | 源主机名（可选）                |
| `source_online_secs` | `String` | 源设备当日在线秒数（可选）           |


### RTCP  Stack TCP环境变量：


| 变量    | 类型    | 说明          |
| ----- | ----- | ----------- |
| `REQ` | `Map` | 请求 Map（见下表） |


`REQ` Map 字段：


| 字段                   | 类型       | 说明              |
| -------------------- | -------- | --------------- |
| `dest_port`          | `String` | 目标端口            |
| `dest_host`          | `String` | 目标主机名（可能为空）     |
| `dest_addr`          | `String` | 目标 SocketAddr   |
| `dest_ip`            | `String` | 目标 IP           |
| `protocol`           | `String` | 传输协议（固定为 `tcp`） |
| `path`               | `String` | 路径信息（可能为空）      |
| `source_device_id`   | `String` | 源设备 ID（握手认证得到的对端 DID，兼容保留） |
| `real_source_did`    | `String` | 握手认证得到的可信来源 DID（与 `source_device_id` 相同） |
| `source_did`         | `String` | 当前有效身份 DID 别名（与 `real_source_did` 相同） |
| `source_addr`        | `String` | 源 SocketAddr（PROXY protocol 存在时为还原后的来源） |
| `source_ip`          | `String` | 源 IP            |
| `source_port`        | `String` | 源端口             |
| `conn_source_addr`   | `String` | 连接层直接上一跳 SocketAddr（隧道对端地址） |
| `conn_source_ip`     | `String` | 连接层直接上一跳 IP    |
| `conn_source_port`   | `String` | 连接层直接上一跳端口     |
| `real_source_addr`   | `String` | 可信还原来源 SocketAddr（仅 PROXY protocol 存在时提供） |
| `real_source_ip`     | `String` | 可信还原来源 IP（可选）  |
| `real_source_port`   | `String` | 可信还原来源端口（可选）   |
| `source_mac`         | `String` | 源 MAC（可选）       |
| `source_hostname`    | `String` | 源主机名（可选）        |
| `source_online_secs` | `String` | 源设备当日在线秒数（可选）   |


### RTCP  Stack UDP环境变量：


| 变量    | 类型    | 说明          |
| ----- | ----- | ----------- |
| `REQ` | `Map` | 请求 Map（见下表） |


`REQ` Map 字段：


| 字段                   | 类型       | 说明              |
| -------------------- | -------- | --------------- |
| `dest_port`          | `String` | 目标端口            |
| `dest_host`          | `String` | 目标主机名（可能为空）     |
| `dest_addr`          | `String` | 目标 SocketAddr   |
| `dest_ip`            | `String` | 目标 IP           |
| `protocol`           | `String` | 传输协议（固定为 `udp`） |
| `path`               | `String` | 路径信息（可能为空）      |
| `source_device_id`   | `String` | 源设备 ID（握手认证得到的对端 DID，兼容保留） |
| `real_source_did`    | `String` | 握手认证得到的可信来源 DID（与 `source_device_id` 相同） |
| `source_did`         | `String` | 当前有效身份 DID 别名（与 `real_source_did` 相同） |
| `source_addr`        | `String` | 源 SocketAddr    |
| `source_ip`          | `String` | 源 IP            |
| `source_port`        | `String` | 源端口             |
| `conn_source_addr`   | `String` | 连接层直接上一跳 SocketAddr（隧道对端地址，与 `source_addr` 相同） |
| `conn_source_ip`     | `String` | 连接层直接上一跳 IP    |
| `conn_source_port`   | `String` | 连接层直接上一跳端口     |
| `source_mac`         | `String` | 源 MAC（可选）       |
| `source_hostname`    | `String` | 源主机名（可选）        |
| `source_online_secs` | `String` | 源设备当日在线秒数（可选）   |


### RTCP Stack on_new_tunnel 环境变量：

`on_new_tunnel_hook_point` 在新隧道握手完成后执行，`reject`/`drop` 会拒绝该隧道。


| 字段                       | 类型       | 说明                                    |
| ------------------------ | -------- | ------------------------------------- |
| `protocol`               | `String` | 固定为 `rtcp`                            |
| `source_addr`            | `String` | 隧道对端 SocketAddr                       |
| `conn_source_addr`       | `String` | 连接层直接上一跳 SocketAddr（与 `source_addr` 相同） |
| `conn_source_ip`         | `String` | 连接层直接上一跳 IP                           |
| `conn_source_port`       | `String` | 连接层直接上一跳端口                            |
| `source_device_id`       | `String` | 源设备 ID（握手认证得到的对端 DID，兼容保留）            |
| `real_source_did`        | `String` | 握手认证得到的可信来源 DID（与 `source_device_id` 相同） |
| `source_did`             | `String` | 当前有效身份 DID 别名（与 `real_source_did` 相同） |
| `source_device_name`     | `String` | 对端设备名（可选，来自 device document）          |
| `source_device_owner`    | `String` | 对端设备 owner（可选）                        |
| `source_zone_did`        | `String` | 对端 zone DID（可选）                       |
| `source_device_doc_jwt`  | `String` | 对端 device document JWT（可选）            |
