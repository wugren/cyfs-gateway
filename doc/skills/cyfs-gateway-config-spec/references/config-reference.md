# 配置参考

这是 cyfs-gateway 配置规范的发布版参考文件。

它整合了配置装载、合并、路径归一化、顶层结构、类型支持范围和关键字段规则，可直接单独使用。

## 1. 配置装载链

运行时有三个关键概念：

- `user_config`
- `effective_config`
- 内置控制面默认配置 `gateway_control_server.yaml`

行为规则：

1. 先读取主配置文件及其 `includes`
2. 再把 `gateway_control_server.yaml` 作为基础配置合入
3. 这份结果视为 `user_config`
4. 若存在保存过的 patch，则在 `user_config` 基础上叠加得到 `effective_config`
5. 实际运行使用的是 `effective_config`

因此：

- `user_config` 不是“纯用户原文”
- `effective_config` 才是最终生效配置

## 2. includes 与 merge

根对象只识别：

```yaml
includes:
  - path: other.yaml
```

支持：

- 本地文件
- 本地目录
- `http://` / `https://` 远程文件

相对 include 解析规则：

- 本地 include：相对当前 include 文件所在目录
- 远程 include：相对当前 URL 的父目录

merge 语义：

- object 对 object：递归 merge
- array 对 array：去重追加
- array 对单值：若不存在则追加
- 其他类型：后者覆盖前者

结论：

- 当前文件优先级高于它 include 的文件
- 不能把它理解成“简单整段覆盖”

## 3. 路径归一化

配置值中以下字段会被识别为路径：

- `path`
- 所有以 `_path` 结尾的字段

规则：

- 相对路径统一按“主配置文件目录”解释
- 不是按 include 文件所在目录解释
- `a.json#fragment` 这类值会只归一化路径部分，保留 `#fragment`

所以必须区分两件事：

- include 路径相对当前 include 文件
- 配置字段里的 `path` / `*_path` 相对主配置文件

## 4. 顶层 section

常见顶层字段：

- `includes`
- `user_name`
- `password`
- `js_externals`
- `timers`
- `device_manager`
- `acme`
- `tls_ca`
- `tunnel_client_certs`
- `limiters`
- `collections`
- `global_process_chains`
- `stacks`
- `servers`

真正会被解析并构造成运行时对象的主要 section：

- `stacks`
- `servers`
- `global_process_chains`
- `collections`
- `timers`
- `limiters`
- `device_manager`
- `acme`
- `tls_ca`
- `tunnel_client_certs`

## 5. map key 注入规则

这些 section 的 map key 会变成运行时主标识：

| section | 注入字段 |
| --- | --- |
| `stacks.<key>` | `id = <key>` |
| `servers.<key>` | `id = <key>` |
| `timers.<key>` | `id = <key>` |
| `limiters.<key>` | `id = <key>` |
| `collections.<key>` | `name = <key>` |
| `global_process_chains.<key>` | `id = <key>` |
| `blocks.<key>` | `id = <key>` |

因此：

- `id` / `name` 通常不需要在 YAML 里手写
- map key 才是配置定义源

## 6. hook_point 结构

常见写法：

```yaml
hook_point:
  main:
    priority: 1
    blocks:
      default:
        priority: 1
        block: |
          call-server welcome;
```

规则：

- `hook_point` 是 chain map
- `blocks` 是 block map
- 解析时会转成数组
- chain 与 block 都按 `priority` 排序执行

当前会做 map-to-vector 转换的区域：

- stack 的 `hook_point`
- HTTP server 的 `hook_point`
- HTTP server 的 `post_hook_point`
- RTCP stack 的 `on_new_tunnel_hook_point`
- `global_process_chains`

## 7. 已支持的 stack 协议

当前 cyfs-gateway 应用层正式支持：

- `tcp`
- `udp`
- `tls`
- `quic`
- `rtcp`
- `tun`

### `tcp`

字段：

- `bind`
- `transparent?`
- `io_dump_file?`
- `io_dump_rotate_size?`
- `io_dump_rotate_max_files?`
- `io_dump_max_upload_bytes_per_conn?`
- `io_dump_max_download_bytes_per_conn?`
- `reuse_address?`
- `hook_point`

默认：

- `transparent = false`
- `reuse_address = false`

### `udp`

字段：

- `bind`
- `concurrency?`
- `session_idle_time?`
- `transparent?`
- `io_dump_*`
- `reuse_address?`
- `hook_point`

常用默认值：

- `concurrency = 200`
- `session_idle_time = 120`

### `tls`

字段：

- `bind`
- `hook_point`
- `certs`
- `concurrency?`
- `alpn_protocols?`
- `io_dump_*`
- `client_auth?`
- `reuse_address?`

`certs` 元素字段：

- `domain`
- `acme_type?`
- `acme_issuer?`
- `cert_path?`
- `key_path?`
- `data?`

### `quic`

字段：

- `bind`
- `concurrency?`
- `hook_point`
- `certs`
- `alpn_protocols?`
- `io_dump_*`
- `reuse_address?`

### `rtcp`

字段：

- `bind`
- `hook_point`
- `keep_tunnel?`
- `keep-tunnel?`，是 `keep_tunnel` 的别名
- `on_new_tunnel_hook_point?`
- `key_path`
- `device_config_path?`
- `device_doc_jwt?`
- `name?`
- `io_dump_*`
- `reuse_address?`

约束：

- 未配置 `device_config_path` 和 `device_doc_jwt` 时，`name` 必填
- 当 stack 的 DID 是逻辑名字（非 `did:dev:<pkx>`）时，必须通过 `device_config_path` 指向 JWT、配置 `device_doc_jwt`，或在 identity manager 中提供 `device.doc.jwt`

### `tun`

必填字段：

- `bind`
- `hook_point`

可选字段：

- `mask?`
- `mtu?`
- `tcp_timeout?`
- `udp_timeout?`
- `io_dump_*`

默认：

- `mask = 255.255.255.0`
- `mtu = 1500`
- `tcp_timeout = 60`
- `udp_timeout = 60`

运行时语义：

- `tun` 当前应按带 IP 参数的 stack 配置理解，不是普通监听 socket，也不能直接等价成二层 bridge / TAP
- `bind` 是传给 `TunStack` builder 的本地 IP 参数
- `mask` 是传给 `TunStack` builder 的掩码参数
- `mtu` 是传给 `TunStack` builder 的 MTU 参数；当前默认值为 `1500`
- `tcp_timeout`、`udp_timeout` 是当前 `tun` stack 暴露出来的超时类参数；当前默认值都为 `60`
- `hook_point` 不只是一个可挂载 DSL 的入口，而是 `tun` 流量处理路径的必需部分
- `tun` 的 TCP / UDP 连接处理会先执行 `hook_point`
- `hook_point` 需要返回当前宿主可消费的转发动作；当前应按 `forward ...` 或 `server ...` 理解
- 若 `hook_point` 没有返回可消费动作，则不会形成有效业务转发路径

使用约束：

- `bind` 与 `mask` 只定义 `tun` stack 的 IP 参数，不自动证明 underlay 联通、静态路由、IP 转发或防火墙已经满足
- 仅有 `bind` / `mask` / `mtu` 这类地址参数不足以形成可用业务路径，还必须说明 `hook_point` 的转发逻辑
- 若用户继续讨论跨机互通，必须把 underlay、静态路由、防火墙、MTU、是否需要 NAT 单列为外部前提
- 若目标是多节点或站点互联，不能把它表述成“当前应用原生内建能力”；只能写成外部组网方案，并要求补验证步骤
- app 是否访问 `tun` 地址、物理地址或代理入口，属于部署与接入设计，不属于 `tun` 字段自身语义
- 如果用户需求依赖广播、ARP、mDNS、NetBIOS 或零配置发现，不能把 `tun` 方案表述成“天然等价于原生局域网”
- 不能给出缺少 `hook_point` 的 `tun` 配置示例

回答 `tun` 使用问题时至少写出：

- 已确认字段：`bind`、`mask`、`mtu`、`tcp_timeout`、`udp_timeout`、`hook_point`
- 已确认默认值：`mask = 255.255.255.0`、`mtu = 1500`、`tcp_timeout = 60`、`udp_timeout = 60`
- `hook_point` 的转发目标是 `call-server` 还是 `forward`
- 外部前提：underlay、静态路由、防火墙、MTU、是否需要 NAT
- 接入方式：应用访问哪个地址或是否应改走代理
- 无证据部分：哪些组网效果当前不能直接承诺

推荐写法：

- 把 `tun` 和宿主机动作拆开描述：
  `cyfs-gateway` 负责 `tun` stack 配置
  宿主机负责路由、转发、防火墙和 MTU
- 把 `tun` 和 `socks` 区分描述：
  `tun` 负责 IP 级参数配置
  `socks` 适合支持代理的单个应用接入
- 把 `tun` 和 `forward` / `call-server` 区分描述：
  `tun` 解决的是 `tun` stack 的 IP 级入口配置
  `forward` / `call-server` 解决的是流量命中后交给哪个 server 或 upstream

## 8. 已支持的 server 类型

当前 cyfs-gateway 应用层正式支持：

- `http`
- `socks`
- `dns`
- `dir`
- `control_server`
- `local_dns`
- `sn`
- `acme_response`

### `http`

字段：

- `version?`
- `h3_port?`
- `hook_point`
- `post_hook_point?`
- `gzip`
- `gzip_types`
- `gzip_min_length`
- `gzip_comp_level`
- `gzip_http_version`
- `gzip_vary`
- `gzip_disable?`
- `gzip_request`
- `brotli`
- `brotli_types`
- `brotli_min_length`
- `brotli_comp_level`

### `dir`

字段：

- `version?`
- `root_path`
- `index_file?`
- `fallback_file?`
- `autoindex`
- `etag`
- `if_modified_since?`

默认：

- `etag = true`

### `dns`

字段：

- `hook_point`

### `local_dns`

字段：

- `file_path`

### `socks`

字段：

- `username?`
- `password?`
- `target`
- `enable_tunnel?`
- `rule_config?`
- `hook_point`

### `sn`

字段：

- `host`
- `ip`
- `boot_jwt`
- `owner_pkx`
- `device_jwt`
- `aliases`
- `db_type?`
- `db_params?`

### `control_server`

字段：

- 只有 `type`
- `id` 由 map key 注入

### `acme_response`

字段：

- 只有 `type`
- `id` 由 map key 注入

## 9. 顶层对象规则

### `timers`

规则：

- key 注入成 `id`
- `timeout` 必须大于 0
- `process-chain` 和 `process_chain` 两种写法都支持

### `limiters`

字段：

- `upper_limiter`
- `download_speed`
- `upload_speed`
- `concurrent`

规则：

- `download_speed` / `upload_speed` 使用字符串速率
- `upper_limiter` 形成依赖关系，解析时会做拓扑排序

### `collections`

当前支持：

- `memory_set`
- `json_set`
- `sqlite_set`
- `text_set`
- `memory_map`
- `json_map`
- `sqlite_map`
- `ip_region_map`

通用字段：

- `type`
- `file_path`
- `only_read_file`
- `data`

补充：

- `json_map` 支持 `file_path: ./all_info.json#app_info`
- `ip_region_map` 解析阶段会自动注入 `cache_path`

### `device_manager`

字段：

- `enabled`
- `offline_timeout_seconds`
- `cleanup_interval_seconds`

默认：

- `enabled = false`
- `offline_timeout_seconds = 600`
- `cleanup_interval_seconds = 60`

### `acme`

字段：

- `account?`
- `issuer?`
- `dns_providers?`
- `check_interval?`
- `renew_before_expiry?`
- `issuers`

### `tls_ca`

字段：

- `cert_path`
- `key_path`

### `tunnel_client_certs`

这是一个 map，值支持两类：

- `type: local`
  - `cert_path`
  - `key_path`
- `type: acme`
  - `domain`
  - `acme_type`
  - `dns_provider?`

## 10. 控制面默认配置

`gateway_control_server.yaml` 会在用户配置前作为基础配置注入，默认带入：

- `stacks.__control_server__`
- `servers.__control_server__`
- `servers.acme_response`

因此：

- 用户不必显式声明 control server
- 规范里不能把它写成“必须手工配置”

## 11. 当前不要宣称为正式支持的类型

实现层虽然存在 `NdnServerConfig`，但当前应用没有注册对应 parser/factory。

因此：

- 可以注明“库内存在”
- 不能写成“当前可直接在 servers 中使用”
