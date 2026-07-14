
# doc/rtcp.md 设计 Review

**总评**:v2 协议设计本身是扎实的——前向安全的临时密钥交换、key-confirmation、aud 域隔离、绑定完整握手上下文的 HKDF、方向分离的 AEAD 记录层、认证/授权分层(§5.3.1),这套推理链完整且大部分与代码一致。文档质量在项目内也是高的(有历史演进、有兼容性声明、有威胁分析)。但有两类问题:**①一个设计决策(拒绝重复 Hello)的安全理由在 v2 下已失效,且与"无保活"叠加会造成真实的重连锁死;②文档停在 7-01 13:04,其后代码改了 1100+ 行,认证一节(§5.3)已与实现漂移,另有多处把"应然"写成了"已然"。**

## 一、设计层面的问题(按优先级)

**1.【高】"拒绝重复 Hello"的理由在 v2 失效,并造成僵尸 tunnel 锁死。** §14.1 的理由是"新旧 tunnel 在同一把 (aes_key, iv) 上各自从 0 计数"——这是 v1(responder 静态 X25519)的事实。v2 每次握手双方都现场生成 ephemeral,重复 Hello 必然派生全新 (key, iv),该风险已不存在,但 [rtcp.rs:1635-1641](src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs:1635) 的注释和行为仍沿用旧理由。叠加三个事实——`run()` 读循环无 idle 超时、全 rtcp 未设 TCP keepalive、`remove_tunnel` 只在 `run()` 退出后执行——后果是:NAT 半开或对端崩溃后,接受侧 tunnel 永久僵死在 map 里;对端重连的新 Hello 完整走完 v2 握手后被当 duplicate 拒掉,keep_tunnel 每 15s 重试、每次都被拒,恢复遥遥无期。**建议:v2 语义下改为"key-confirmation 通过后新替旧、close 旧 tunnel"(自愈且无密码学代价),并补 TCP keepalive 或读 idle 探测。**

**2.【中高】inbound ROpen 没有配额。** Open 有 64 槽 semaphore([rtcp.rs:2276](src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs:2276)),但每条 inbound ROpen 都会触发一次出站 TCP 竞速拨号 + HelloStream,无并发上限、无速率限制,`on_ropen` 也不检查方向(接受侧收到 ROpen 同样会拨号)。恶意对端可把本端当出站连接放大器。§14.3 记录的"对端持续发送请求"问题只修了 Open 一半。

**3.【中】未认证阶段的健壮性/资源面,文档未讨论。**
- [package.rs](src/components/cyfs-gateway-lib/src/rtcp/package.rs) 解析畸形包会 panic:`len` 在 3..8 时 `&buf[pos..pos+4]` 越界、`json_pos > len` 时切片越界——未认证远程可触发(panic=unwind 只杀 task,但应改为错误返回)。且接收端对 `json_pos` 只查下界 `>=6`,文档 §3.1"实际要求它等于 8"不成立(6/7 在 seq 字节恰为 JSON 空白字符时会被偶然接受)。
- 带 `device_doc_jwt` 的 Hello 在准入前就触发 name-system 权威查询(网络 I/O),攻击者可用随机 owner 的 doc_jwt 让 responder 对外打查询、占 15s 握手槽。需要负缓存/并发上限这类缓解,至少文档要记录这个面。
- nonce cache 满 16Ki 条目时逐出"最早到期"项——可被自造 did:dev 灌爆挤出真实条目。好在 v2 下重放 Hello 反正过不了 key-confirmation,所以 nonce cache 实质是 **DoS 缓解而非安全边界**;§14.2"三层防护"的表述建议摆正它的定位。

**4.【中】`my_port` 是纯明文、无完整性保护**([package.rs:123](src/components/cyfs-gateway-lib/src/rtcp/package.rs:123),不在 tunnel_token 内)。on-path 攻击者可篡改,把接受侧后续回连引到 initiator 同 IP 的任意端口(最终 AEAD 失败,危害限于 DoS/端口触碰),但修复很便宜:把 `my_port` 收进 tunnel_token payload。建议列入 §14 TODO。

**5.【中】单 key 终身使用、无 rekey。** tunnel 和所有业务 stream 共用一把 AES key(stream 只换 IV),网关场景单 tunnel 累计流量可能非常大,而 TLS 1.3 的工程实践是 ~2^24.5 条记录就 KeyUpdate;当前 u64 seq 溢出只报错。低成本改进:**per-stream key = HKDF(tunnel_key, streamid)**——顺带消除"对端选的 streamid 直接当 base IV"的耦合。

**6.【低】值得一句话记录的取舍:** AEAD 层无认证关闭(记录边界的 FIN 截断会被当正常 EOF);HelloStream 不含持钥证明,知道 streamid 者可抢占 waiter(仅 DoS);Datagram 线上 u32 长度但无协议级上限约定(现有 forwarder 用 5KiB 缓冲,对端发大包流直接死——互通隐患);Hello/HelloAck 明文暴露 from/to/owner/zone 的身份隐私未声明是接受的 trade-off;`len` u16 意味着 Hello+device_doc_jwt 上限 ~64KB,大 DID doc 会撞墙。

## 二、文档与代码的实质偏差(需要改文档)

1. **§4.5 `purpose` 线上取值是错的**——serde derive 忽略判别值,实际序列化为字符串 `"Stream"`/`"Datagram"`,`{"purpose":0}` 反序列化直接报错。这是互通级文档错误。
2. **§5.3 路径 2 已过时**:具名 from_id(did:web/did:bns/hostname)不带 doc_jwt 现在被直接拒绝([rtcp.rs:1183-1188](src/components/cyfs-gateway-lib/src/rtcp/rtcp.rs:1183),7-01 下午落地,晚于文档更新)。路径 2 只对 `did:dev` 成立,§4.1 的"可选"要加限定。
3. **§5.3 路径 1 描述的是回落路径**:主路径是 name-client `verify_device_document_jwt` 权威锚定(5 个错误码硬拒、其余含 NotCurrentActive 回落——权威明确吊销也会回落是代码自认的已知取舍,吊销留给授权层)。文档写的 owner 自验流程只是第 2 级。且两级校验都是 doc.id 与 from_id **字符串相等**,不是文档说的"解析到 canonical did:dev 比较"。
4. **§4.2/§14.2 的 from/to 校验写过头了**:实际是 host-name 字符串比较;`to` 只对 did:web 别名做解析到 dev did,其他名字别名直接拒;HKDF ctx 里的 DID 也是逻辑 host-name 形式而非 canonical dev did。这些是文档把目标语义当现状写了。
5. **§8.1/§10.2 重连端口语义错误**:标准流程里重连全发生在 tunnel 发起侧,端口取 URL stack port;`Hello.my_port` 只在接受侧被消费。§8.1 步骤 4 的"上一次成功 IP + Hello.my_port"对 A 侧不成立。
6. **§10.2/§10.3 重连竞速与 RTT 口径不符**:实际获胜判定只是 TCP connect 成功(HelloStream 失败不复赛);RTT 记 `MeasurementLayer::Tcp`、仅 connect 耗时;失败 attempt 不回写 name-client。文档写的三点(connect+HelloStream、Application 层、失败回写)都与代码不符——这里我倾向认为**该修的是代码**(文档的口径更合理,符合"端到端 connectivity check 才计入"的原则)。
7. **nonce cache "容量上限 16 KiB" 单位错**:实际是 16Ki **条目**(≈1.6 MiB)。建议顺带写明淘汰策略(满时逐出最早到期项)。
8. **§5.2 did:web 的 TXT 顺序反了**:代码里 TXT 是优先路径,DID doc 解析才是其后手段。
9. **§12.1 JWT 文件名不存在**:实际探测顺序 `device.jwt` → `device_doc.jwt` → `did.json`,没有 `device.doc.jwt`。
10. **§13 的 tunnel key 对冲说法过时**:DEV-based key 已落地(含 bootstrap 后缀、回归测试),该条应改为陈述已完成。
11. 小项:§5.5 nonce 派生哈希顺序建议写死(实际 label 在前:`SHA-256(label || base_iv)`);文首"实现入口"清单漏了真正的记录层实现 [aes_stream.rs](src/components/cyfs-gateway-lib/src/aes_stream.rs) 和 [stream_helper.rs](src/components/cyfs-gateway-lib/src/rtcp/stream_helper.rs);第 14/16 行的链接是机器本地绝对路径,换环境即断;§4.2 exp 窗口"[exp-leeway, exp+leeway]"的左边界其实来自签发时刻(恰好数值相等,概念误导);§6.4"有且仅有一条 tunnel"与 bootstrap 后缀语义矛盾(应为"每〈设备对,承载路径〉唯一")。

## 三、结构建议

- **§14 名实不符**:标题是"协议 TODO",但 14.1–14.5 全部标着"已落地",真正的 open item(多实例 nonce cache、时钟偏差、后台路径重评估)反而散在注意事项里。建议已落地内容并入正文对应章节,§14 只留 open TODO——上面第一部分的 6 条正好可以填进去。
- **应然/已然混写**是本文档最大的可读性风险:§4.2、§5.3、§10 多处用"应/不应该"描述尚未实现或与实现不符的语义(from/to canonical 比较、RTT 口径)。建议明确标注哪些是"当前实现"、哪些是"目标语义,实现待跟进",否则读者(和未来的你)无法用它当协议真值。
- **补一节 per-stream 授权**:代码里每条新 stream 都会 fork hook_point 链、能看到 `dest_host/dest_port` 并可拒绝([rtcp_stack.rs:264-361](src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs:264))——这是 proxy 节点最关键的安全控制点,但 rtcp.md 只写了 tunnel 级的 §11。

**一句话结论**:协议内核(v2 握手 + AEAD 记录层)可以放心继续演进;优先处理"重复 Hello 拒绝 + 无保活"的锁死问题和 ROpen 配额,然后把 §5.3/§4.5/§10 三处漂移的文档修正回真值。需要的话我可以按上面的结论直接修订 rtcp.md,或先把设计问题(第一部分 1、2 两条)落成代码修复。