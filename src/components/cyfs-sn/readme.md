# cyfs-sn 的主要功能

1. 提供基于 HTTP JSON-RPC 的 SN 账号会话与设备在线态管理能力
2. 在 `/kapi` 下拆分 SN 入口：`/kapi/sn` 仅作命名空间根，`/kapi/sn/auth` 承载账号/session/user_domain，`/kapi/sn/deviceinfo` 承载设备在线态与 OOD 连接信息
3. BNS 写入和文档管理由独立 `/kapi/bns` 组件承担，不再挂在 SN 下
4. DID/域名解析走标准 W3C DID Resolver 和 DNS NameServer，不再通过 kRPC `query.resolve_*`
5. 提供带 `active_code` 的 `auth.register`、`auth.login` 和服务端 JWT
6. 用户名校验接入 `buckyos-kit::is_valid_name`，并支持服务端保留名单文件

## 文档

- JSON-RPC 接口文档：[`doc/SN/SN-API.md`](/home/aa/app/base/cyfs-gateway/doc/SN/SN-API.md)
