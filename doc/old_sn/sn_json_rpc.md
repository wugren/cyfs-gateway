# SN JSON-RPC API

本文档描述当前 SN 的 JSON-RPC 管理接口。

## 总体原则

- HTTP 入口按路由需求拆成三类：
  - `POST /kapi/sn`
  - `POST /kapi/sn/auth`
  - `POST /kapi/sn/bns`
- 请求包体格式不变，继续使用现有 JSON-RPC 封装
- path 先决定路由类别，`method` 再决定具体能力
- `update` 继续保留原名原语义

## 请求格式

所有接口继续使用 JSON-RPC body：

```json
{
  "method": "auth.login",
  "params": {
    "name": "alice",
    "pwd_hash": "<base64-sha256-hash>",
    "active_code": "<activation-code>"
  },
  "sys": [
    1,
    "optional-token"
  ]
}
```

说明：

- `method` 负责能力分发
- `params` 结构保持既有 client 协议，不因为 namespaced `method` 而变化
- `pwd_hash` 表示前端预处理后的密码摘要值，不是明文密码，也不是可逆加密结果
- `sys[1]` 用于携带 token；公开查询、注册、登录等接口可不带
- namespaced 管理接口的稳定错误继续通过 `RPCResult::Failed(string)` 返回

### `pwd_hash` 说明

当前前端主流程 `active_lib / node_active` 提交的 `pwd_hash` 规则是：

```text
Base64(SHA256(password + username + ".buckyos"))
```

说明：

- 这里的 `username` 指前端归一化后的用户名
- `pwd_hash` 是哈希摘要，不是可逆“加密密码”
- 服务端接口文档约定的是最终提交值；当前前端实现来源于 `buckyos.hashPassword(...)`

## 入口

- 通用 SN / 边缘查询：`/kapi/sn`
- 用户 auth 相关：`/kapi/sn/auth`
- 用户中心 / BNS 管理相关：`/kapi/sn/bns`
- 内部直连测试也兼容根路径 `/`
- 为兼容历史调用，`/kapi/sn` 当前仍可兜底处理 auth/bns method，但新接入应按上面三类 path 发送
- `/kapi/sn/v2/<module>` 和 `/v2/<module>` 已废弃，不应再使用

## Method 命名

推荐调用以下 namespaced `method`：

- `auth.*`
- `user.*`
- `zone.*`
- `device.*`
- `query.*`
- `dns.*`
- `did.*`
- `admin.*`

旧方法名仍然兼容，但服务端内部会先归一化为新的 namespaced `method` 再分发。

## 旧方法别名

当前保留的主要 alias 如下：

- `check_active_code` -> `auth.check_active_code`
- `clear_state_by_active_code` -> `admin.clear_state_by_active_code`
- `check_username` -> `auth.check_username`
- `register_user` -> `user.register_by_public_key`
- `bind_zone_config` -> `zone.bind_config`
- `set_user_self_cert` -> `user.set_self_cert`
- `set_user_did_document` -> `did.set_document`
- `register` -> `device.register`
- `get` -> `device.get`
- `get_by_pk` -> `device.get_by_pk`
- `query_by_hostname` -> `query.by_hostname`
- `query_by_did` -> `query.by_did`
- `add_dns_record` -> `dns.add_record`
- `remove_dns_record` -> `dns.remove_record`
- `device.query_by_hostname` -> `query.by_hostname`
- `device.query_by_did` -> `query.by_did`

`update` 不做 alias，仍是独立旧接口。

## Token 说明

- `auth.register` 和 `auth.login` 都会返回 `access_token` 与 `refresh_token`
- `access_token` 用于 auth/bns 管理接口，当前有效期为 1 小时
- `refresh_token` 仅用于 `auth.refresh`，当前有效期为 1 天
- token 由服务端签发，不复用旧版 user/device 自签 token
- 部分兼容接口会同时接受旧 token 语义和新的 access token 语义，服务端按 `params` 和 token 类型自动选择处理逻辑

## 错误码

稳定错误码通过 `RPCResult::Failed(string)` 暴露，字符串格式为：

```text
[SNV2:1005:invalid_password] invalid password
```

建议调用方优先解析中括号内的 `code` 和 `name`，不要依赖后面的自由文本。

当前保留的错误码如下：

- `1000 invalid_params`
- `1001 invalid_username`
- `1002 username_already_exists`
- `1003 invalid_active_code`
- `1004 user_auth_not_found`
- `1005 invalid_password`
- `1006 auth_required`
- `1007 invalid_token`
- `1008 user_not_found`
- `1009 owner_key_required`
- `1010 invalid_public_key`
- `1011 invalid_zone_config`
- `1012 device_not_found`
- `1013 device_permission_denied`
- `1014 invalid_device_did`
- `1015 invalid_domain`
- `1016 did_document_not_found`
- `1017 hostname_not_found`
- `1018 cross_user_access_denied`
- `1019 unsupported_password_algo`
- `1020 invalid_password_storage`
- `1021 invalid_did`
- `1022 user_not_activated`
- `1099 internal_error`

## auth

推荐 path：`/kapi/sn/auth`

推荐 method 前缀：`auth.*`

- `auth.check_username`
  - params: `{ "name": "alice" }`
  - 兼容旧 `check_username` 的参数风格
  - 服务端按 `buckyos-kit::is_valid_name(name, NameType::User)` 校验用户名
  - 额外拦截服务端保留名单文件，默认路径：`$BUCKYOS_ROOT/data/var/sn/reserved_user_names.txt`
  - 如果设置了环境变量 `BUCKYOS_SN_RESERVED_NAMES_FILE`，则优先读取该文件
  - result:
    - 可用：`{ "valid": true, "reason": "ok", "message": "", "normalized_name": "alice" }`
    - 不可用：`{ "valid": false, "reason": "invalid_username" | "already_exists", "message": "...", "normalized_name": "alice" }`
- `auth.check_active_code`
  - params: `{ "active_code": "..." }`
  - result: `{ "code": 0, "valid": true }`
- `auth.register`
  - params: `{ "name": "alice", "pwd_hash": "...", "active_code": "..." }`
  - `pwd_hash` 当前约定为 `Base64(SHA256(password + username + ".buckyos"))`
  - `name` 需要通过和 `auth.check_username` 相同的服务端校验
  - 成功后直接完成注册并返回 token
  - result: `{ "code": 0, "access_token": "...", "refresh_token": "...", "need_bind_owner_key": true }`
- `auth.login`
  - params: `{ "name": "alice", "pwd_hash": "...", "active_code": "..." }`
  - `pwd_hash` 当前约定为 `Base64(SHA256(password + username + ".buckyos"))`
  - 对外 RPC 登录当前要求同时携带 `active_code`
  - 前置条件：用户已完成 `auth.register`
  - result: `{ "code": 0, "access_token": "...", "refresh_token": "..." }`
- `auth.refresh`
  - params: `{ "refresh_token": "..." }`
  - result: `{ "code": 0, "access_token": "..." }`
- `auth.logout`
  - params: `{}`
  - result: `{ "code": 0 }`
- `auth.me`
  - params: `{}`
  - result: `{ "code": 0, "name": "alice", "owner_key_bound": false, ... }`

## user

推荐 path：`/kapi/sn/bns`

推荐 method 前缀：`user.*`

- `user.register_by_public_key`
  - 对应旧 `register_user`
  - params 沿用旧接口格式
  - `user_name` 需要通过和 `auth.check_username` 相同的服务端校验
- `user.bind_owner_key`
  - params: `{ "public_key": <jwk-object-or-string> }`
  - 作用：把 owner 公钥写回 `users.public_key`
- `user.get_owner_key`
  - params: `{}`
- `user.set_self_cert`
  - 兼容旧接口和 access token 模式
  - params 取决于调用场景，保持现有 client 协议
- `user.get_profile`
  - params: `{}`

## zone

推荐 path：`/kapi/sn/bns`

推荐 method 前缀：`zone.*`

- `zone.get`
  - params: `{ "name": "optional-self-name" }`
- `zone.bind_config`
  - params: `{ "zone_config": "<jwt>", "user_domain": "optional-domain" }`
  - 兼容旧 `bind_zone_config` 的参数与 token 语义
  - `zone_config` 仍由客户端按旧规则生成签名 JWT
- `zone.unbind_config`
  - params: `{ "user_name": "alice" }`
  - 只支持 owner key 签名 token，不支持 access token
  - 语义是清空当前用户的 `zone_config`；接口保持幂等，未绑定时也返回成功

## device

推荐 path：

- `device.register`、`device.update`、`device.list` -> `/kapi/sn/bns`
- `device.get`、`device.get_by_pk` -> `/kapi/sn`

推荐 method 前缀：`device.*`

- `device.register`
  - 兼容旧 `register` 与新的账号 access token 模式
  - 旧参数和新参数都保持兼容
- `device.update`
  - params: `{ "device_name": "ood1", "device_ip": "127.0.0.1", "device_info": "...", "device_did": "optional", "mini_config_jwt": "optional" }`
  - 这是 namespaced 管理接口
- `device.get`
  - 兼容旧 `{ owner_id, device_id }` 和新的 `{ name, device_name }` 风格
- `device.list`
  - params: `{ "name": "optional-self-name" }`
- `device.get_by_pk`
  - params: `{ "public_key": "<jwk-string>" }`

## query

推荐 path：`/kapi/sn`

推荐 method 前缀：`query.*`

- `query.by_hostname`
  - 对应旧 `query_by_hostname`
  - params: `{ "dest_host": "home.alice.web3.example.com" }`
- `query.by_did`
  - 对应旧 `query_by_did`
  - params: `{ "source_device_id": "did:dev:xxx" }`
- `query.resolve_did`
  - params: `{ "did": "did:bns:alice", "type": "zone|boot|doc|info" }`
- `query.resolve_hostname`
  - params: `{ "host": "home.alice.web3.example.com" }`
- `query.resolve_device`
  - params: `{ "name": "alice", "device_name": "ood1" }`

## dns

推荐 path：`/kapi/sn`

推荐 method 前缀：`dns.*`

- `dns.add_record`
  - 兼容旧 `add_dns_record` 和新的 access token 模式
  - params: `{ "device_did": "did:dev:xxx", "domain": "home.alice.web3.example.com", "record_type": "A", "record": "127.0.0.1", "ttl": 600, "has_cert": true }`
- `dns.remove_record`
  - 兼容旧 `remove_dns_record` 和新的 access token 模式
  - params: `{ "device_did": "did:dev:xxx", "domain": "home.alice.web3.example.com", "record_type": "A", "has_cert": false }`
- `dns.list_records`
  - params: `{ "name": "optional-self-name" }`

## did

推荐 path：`/kapi/sn`

推荐 method 前缀：`did.*`

- `did.set_document`
  - 兼容旧 `set_user_did_document` 和新的 access token 模式
  - params: `{ "obj_name": "profile", "did_document": { ... }, "doc_type": "optional" }`
- `did.get_document`
  - params: `{ "name": "optional-self-name", "obj_name": "profile", "doc_type": "optional" }`

## admin

推荐 path：`/kapi/sn/bns`

- `admin.clear_state_by_active_code`
  - 对应旧 `clear_state_by_active_code`
  - 用于测试或运维清理，不属于正式产品接口

## 特例接口

- `update`
  - 固定入口仍然是 `/kapi/sn`
  - method 仍然直接写 `update`
  - 这是旧设备上报/心跳接口，不等同于 `device.update`
  - 不参与 namespaced alias 迁移

## 与实现的对应关系

- path 路由与 method 归一化：`src/components/cyfs-sn/src/sn_server.rs`
- namespaced handler：`src/components/cyfs-sn/src/v2/mod.rs`
- 账号鉴权与 JWT 管理：`src/components/cyfs-sn/src/v2/auth.rs`、`src/components/cyfs-sn/src/v2/common.rs`
- 数据库存储：`src/components/cyfs-sn/src/sn_db.rs`、`src/components/cyfs-sn/src/sqlite_db.rs`

## 覆盖与兼容说明

下面这些接口存在覆盖兼容关系：

- `auth.check_username`
  - 旧逻辑使用 `check_username`
  - 新逻辑使用 `auth.check_username`
  - 当请求里使用旧参数风格时，仍走旧校验逻辑；使用新参数风格时，走新的账号逻辑
- `user.set_self_cert`
  - 覆盖旧 `set_user_self_cert`
  - 同时兼容旧 token 语义和新的 access token 语义
- `zone.bind_config`
  - 覆盖旧 `bind_zone_config`
  - 同时兼容旧参数风格和新的 access token 模式
- `device.register`
  - 覆盖旧 `register`
  - 旧设备注册参数和新的管理面参数都兼容
- `device.get`
  - 覆盖旧 `get`
  - 同时兼容旧 `{ owner_id, device_id }` 和新的 `{ name, device_name }` 风格
- `query.by_hostname`
  - 覆盖旧 `query_by_hostname`
  - 也兼容历史上的 `device.query_by_hostname`
- `query.by_did`
  - 覆盖旧 `query_by_did`
  - 也兼容历史上的 `device.query_by_did`
- `dns.add_record`
  - 覆盖旧 `add_dns_record`
  - 同时兼容旧 token 语义和新的 access token 模式
- `dns.remove_record`
  - 覆盖旧 `remove_dns_record`
  - 同时兼容旧 token 语义和新的 access token 模式
- `did.set_document`
  - 覆盖旧 `set_user_did_document`
  - 同时兼容旧参数风格和新的 access token 模式

下面这些接口没有发生“新版覆盖旧版同名逻辑”的收敛，只是新增的 namespaced method 或单独保留的旧接口：

- `auth.register`
- `auth.login`
- `auth.refresh`
- `auth.logout`
- `auth.me`
- `user.register_by_public_key`
- `user.bind_owner_key`
- `user.get_owner_key`
- `user.get_profile`
- `zone.get`
- `zone.unbind_config`
- `device.update`
- `device.list`
- `device.get_by_pk`
- `query.resolve_did`
- `query.resolve_hostname`
- `query.resolve_device`
- `dns.list_records`
- `did.get_document`
- `admin.clear_state_by_active_code`
- `update`
