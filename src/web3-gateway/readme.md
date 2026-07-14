为什么web3-gateway不是buckyos的一个应用？
比如用户可以在应用商店里安装web3-gateway,然后自己的zone就变成了一个web3 bridge,可以给其它需要sn的zone提供服务。

答:目前web3_gateway的整体逻辑与基于zone的基础逻辑相差太大，一定是需要有运维的情况下才能做到和原有的buckyos逻辑共存。
让web3_gateway与buckyos强耦合，还会带来潜在的循环以来问题。

因此在这个阶段，web3-gateway是基于cyfs-gatway开发的应用，而不是基于buckyos开发的应用，是一个为了防止混乱的刻意设计。web3-gateway的妥善运行是需要有运维支持的。 

## web3-gatway的核心配置文件

- web3_gateway.yaml 核心配置文件，可以看成是代码的一部分。单机 all-in-one 部署用它
- web3_dns.yaml / web3_relay.yaml / web3_sn_api.yaml 是 web3_gateway.yaml 的独立部署拆分，行为逐条对齐合并版：
  - web3_dns.yaml 只做 53 端口权威 DNS（local_dns + web3_sn 兜底解析）
  - web3_relay.yaml 是对外 TCP 入口（443 SNI / 80 / 2980 rtcp / 3443 *.web3 TLS 终止），设备流量走 rtcp 隧道转发，sn./bns./web3. 流量原样转给 api 实例（params 的 sn_api_addr / api_tls_port / api_http_port，默认 127.0.0.1 同机直连）
  - web3_sn_api.yaml 提供 SN RPC / DID resolver / BNS 网关，只绑高位端口（api_http_bind / api_tls_bind，默认 3080/3444），C 类种子只在这个实例导入
  - 三个实例各自内嵌 web3_sn server（qa/resolve 只支持进程内引用），设备/账号数据必须共享：同机部署共享 sn.sqlite3（make_sn_config.ts 会给存在的拆分文件打同样的 db 补丁）；跨机部署需给各 web3_sn 配 db: {type: postgres, provider_base_url: ...} 指向共享 provider，且 api 实例要移除 seed_path
  - 启动方式与合并版相同：web3_gateway --config_file <拆分文件>；建议先起 web3_sn_api（导种子）再起 dns/relay
- website.yaml 被web3_gatweay引用，提供https://sn.$sn_base 的常规网页需求。这个根据运维手工填写。默认为 {}
- fullchain.cert,fullchain.pem 包含 sn.$sn_base、bns.$sn_base、web3.$sn_base、*.web3.$sn_base 的证书和对应的密钥。如果做全自拥有证书的逻辑就没有 *.web3的证书
- ca/ca_cert,ca_cert.pem 如果是测试环境，fullchain.cert是自签名的。这里保存用于于自签名的CA证书
- local_dns.toml 是 DNS 本地记录源；make_sn_config.ts 会在部署副本中写入 bns.$sn_base -> sn_ip，使用 SN 作为 DNS 服务器的客户端可直接解析 BNS 域名
- zone_zone 自动生成的，包含有buckyos定制的DNS TXT记录的DNS Zone文件
- device.doc.jwt, device_private_key.pem rtcp协议栈用到的 DeviceConfig和对应的密钥文件
- node_idenity.json （包含device.doc.jwt)，兼容buckyos的设备identity文件，目前暂没用到

## web3-gatway的核心数据文件
- sn.db sqlite数据库文件，需要定期备份

## 日志文件
- /opt/buckyos
