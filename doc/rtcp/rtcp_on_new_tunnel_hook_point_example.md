# RTCP on_new_tunnel_hook_point 配置示例

`on_new_tunnel_hook_point` 用于在 RTCP tunnel 建立完成前执行 process_chain。

它和现有的 `hook_point` 不同：

- `on_new_tunnel_hook_point` 控制“这个来源是否允许建立 tunnel”
- `hook_point` 控制“tunnel 建好以后，stream/datagram 如何转发”

`on_new_tunnel_hook_point` 当前可用的环境变量见 [process chain env.md](/Users/liuzhicong/project/cyfs-gateway/doc/process%20chain%20env.md)，最常用的是：

- `REQ.source_device_id`
- `REQ.source_addr`
- `REQ.source_device_owner`
- `REQ.source_zone_did`
- `REQ.source_device_name`
- `REQ.protocol`

注意：

- `REQ.source_device_id` 来自 RTCP 握手包里的 `hello.body.from_id`
- 它是对端设备的 `device_config.id` 字符串
- `REQ.source_device_owner` / `REQ.source_zone_did` / `REQ.source_device_name` 只有在对端 `Hello` 里携带并通过校验 `device_doc_jwt` 时才存在
- 如果你希望 `on_new_tunnel_hook_point` 使用这些语义字段，发起方的 `device_config_path` 应该指向 owner 已签名的 `device.doc.jwt`
- 示例里的 `<真实device_id>` 需要替换成你实际设备配置里的 `id`

## 示例 1：只允许指定 device 建立 tunnel

下面的配置表示：

- 允许 `<真实device_id_1>` 建立 RTCP tunnel
- 允许 `<真实device_id_2>` 建立 RTCP tunnel
- 其他来源全部拒绝

```yaml
stacks:
  main_rtcp:
    protocol: rtcp
    bind: 0.0.0.0:2980
    key_path: /opt/app/device_private_key.pem
    device_config_path: /opt/app/device.doc.jwt

    on_new_tunnel_hook_point:
      main:
        priority: 1
        blocks:
          allow_list:
            priority: 1
            block: |
              eq ${REQ.source_device_id} "<真实device_id_1>" && return "ok";
              eq ${REQ.source_device_id} "<真实device_id_2>" && return "ok";
              reject;

    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "server my_tcp_server";
```

说明：

- 如果命中白名单，`return "ok"` 会结束当前 process_chain，tunnel 继续建立
- 如果没有命中，最后的 `reject;` 会拒绝本次 tunnel

## 示例 2：同时限制 device_id 和来源地址

下面的配置表示：

- 只有 `<真实office_gateway_device_id>` 能连
- 并且它的来源地址必须在 `192.168.100.0/24` 网段内
- 否则拒绝

```yaml
stacks:
  main_rtcp:
    protocol: rtcp
    bind: 0.0.0.0:2980
    key_path: /opt/app/device_private_key.pem
    device_config_path: /opt/app/device.doc.jwt

    on_new_tunnel_hook_point:
      main:
        priority: 1
        blocks:
          check_source:
            priority: 1
            block: |
              neq ${REQ.source_device_id} "<真实office_gateway_device_id>" && reject;
              not match ${REQ.source_addr} "^192\\.168\\.100\\.[0-9]+:[0-9]+$" && reject;
              return "ok";

    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "forward tcp://127.0.0.1:8080";
```

说明：

- `REQ.source_addr` 的格式是 `IP:PORT`
- 如果只想限制 IP，建议正则里把端口一起匹配掉

## 示例 3：默认允许，只拒绝某些来源

```yaml
stacks:
  main_rtcp:
    protocol: rtcp
    bind: 0.0.0.0:2980
    key_path: /opt/app/device_private_key.pem
    device_config_path: /opt/app/device.doc.jwt

    on_new_tunnel_hook_point:
      main:
        priority: 1
        blocks:
          blacklist:
            priority: 1
            block: |
              eq ${REQ.source_device_id} "<被拉黑device_id>" && reject;
              match ${REQ.source_addr} "^10\\.10\\.10\\." && reject;
              return "ok";
```

这个模式适合“默认放行，只有少量来源要拦截”的场景。

## 建议

- 如果你要做强身份控制，优先使用 `REQ.source_device_id`
- 如果你要按 owner / zone 做准入，确保对端实际发送的是 `device.doc.jwt`
- 如果你要做临时封禁或局域网限制，再叠加 `REQ.source_addr`
- `on_new_tunnel_hook_point` 里只做准入控制，不要把 stream 转发逻辑写进来
- 真正的 `forward` / `server` 分发逻辑仍然放在普通 `hook_point`
