# RTCP SOCKS Proxy 配置示例

这个例子对应下面的目标：

- `cyfs-gateway` 在固定端口提供一个 SOCKS5 服务
- 客户端把 SOCKS `CONNECT` 的目标写成 `remote_device:port`
- gateway 在 SOCKS process chain 中把 `remote_device` 解释为 **RTCP 对端 stack id**
- gateway 再通过 `rtcp://remote_device/` 建立 tunnel
- tunnel 建好后，把原始 SOCKS 请求里的 `port` 作为远端最终访问端口

整体路径如下：

```text
Client
  -> SOCKS5 127.0.0.1:21080
  -> cyfs-gateway socks server
  -> process chain return "PROXY rtcp://remote_device/"
  -> RTCP tunnel
  -> remote RTCP stack
  -> process chain forward tcp:///127.0.0.1:${REQ.dest_port}
  -> remote local service
```

## 1. Service Gateway 上的 SOCKS 入口

下面这段配置让 gateway 在 `127.0.0.1:21080` 暴露一个固定的 SOCKS5 端口。

关键点是：

- `REQ.target.host` 被当成远端 RTCP stack id
- `REQ.target.port` 保留为远端最终访问端口
- 只接受 `domain` 类型目标，避免把 IP 字面量误当成 RTCP 设备 ID
- `target` 字段是 socks server 的必填兜底值；真正生效的是 `hook_point` 返回的 `PROXY rtcp://...`

```yaml
stacks:
  rtcp_socks_tcp:
    bind: 127.0.0.1:21080
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server rtcp_socks_proxy;

  main_rtcp:
    bind: 0.0.0.0:2980
    protocol: rtcp
    key_path: ./gateway_private_key.pem
    device_config_path: ./gateway_device.doc.jwt
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              eq ${REQ.protocol} "tcp" || reject;
              return "forward tcp:///127.0.0.1:${REQ.dest_port}";

servers:
  rtcp_socks_proxy:
    type: socks
    target: rtcp://fallback.invalid/
    username: rtcp_user
    password: change_me
    hook_point:
      main:
        priority: 1
        blocks:
          check_target:
            priority: 1
            block: |
              eq ${REQ.target.type} "domain" || reject;
              eq ${REQ.target.host} "" && reject;
              eq ${REQ.target.port} "" && reject;

          forward_rtcp:
            priority: 10
            block: |
              
              return "forward rtcp://${REQ.target.host}/:${REQ.target.port}";
```

## 2. 客户端如何使用

客户端连到 SOCKS 端口：

```text
127.0.0.1:21080
```

SOCKS `CONNECT` 里的目标写成：

```text
remote_device:3389
```

这里的 `remote_device` 应该是 **RTCP 可识别的 stack id / DID hostname**，而不是普通出口代理里常见的“最终目标域名”。

这个例子下，gateway 的行为是：

1. SOCKS server 收到 `remote_device:3389`
2. process chain 返回 `PROXY rtcp://remote_device/`
3. gateway 通过 RTCP 连接 `remote_device`
4. RTCP 对端收到 `REQ.dest_port=3389`
5. 对端 `main_rtcp` 把它转发到本机 `127.0.0.1:3389`

## 3. 更安全的常见变体

如果不想开放“任意端口都能通过 SOCKS 访问”，建议在远端 RTCP stack 再加一层端口白名单。例如只允许 80 和 443：

```yaml
stacks:
  main_rtcp:
    bind: 0.0.0.0:2980
    protocol: rtcp
    key_path: ./gateway_private_key.pem
    device_config_path: ./gateway_device.doc.jwt
    hook_point:
      main:
        priority: 1
        blocks:
          allow_80:
            priority: 1
            block: |
              eq ${REQ.protocol} "tcp" && eq ${REQ.dest_port} "80" && return "forward tcp:///127.0.0.1:80";

          allow_443:
            priority: 2
            block: |
              eq ${REQ.protocol} "tcp" && eq ${REQ.dest_port} "443" && return "forward tcp:///127.0.0.1:443";

          default:
            priority: 100
            block: |
              reject;
```

## 4. 这个例子的语义边界

这个例子实现的是：

```text
SOCKS target host = RTCP 对端设备
SOCKS target port = 对端设备上最终访问的本地端口
```

也就是：

```text
remote_device:port
```

被解释成：

```text
通过 RTCP 连到 remote_device，再访问 remote_device 本机的 :port
```

如果你希望 SOCKS target 的 host 不是 `remote_device`，而是“远端再帮你连接一个第三方域名”，那就不是这个例子了。那种场景通常要在 SOCKS process chain 里先做一层名字映射，再单独拼出 RTCP 对端和最终目标。
