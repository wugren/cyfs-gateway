#!/usr/bin/env -S deno run --allow-all
// make_sn_config.ts - standalone minimal SN (Super Node) deployment tool.
//
// Design intent:
// This script is the SN-side companion to buckyos' make_config.ts. It pre-seeds
// the local state that a dev Super Node owns before web3-gateway starts, using
// only the public Web SDK provision surface. That keeps dev setup close to what
// a third-party tool or agent would do when it registers users, devices, and
// zone data through the data-plane API instead of relying on process-private
// setup code.
//
// The user/zone/device cases come from devenv_config.ts. That file is the shared
// user-data seed description; this script materializes the SN-owned view of that
// seed, while make_config.ts materializes the OOD/rootfs-owned view. The boundary
// is intentional: do not duplicate another module's derived config here just to
// make boot pass. If web3-gateway can reconstruct indexes, caches, or dependent
// state from its seed database and protocol data, it should do so lazily at boot.
//
// Iteration direction:
// Keep this script short and owned by the SN/web3-gateway boundary. It may write
// minimal SN service parameters, SN identity material, and component seed config
// files. Runtime-derived data, compatibility shims, caches, and state that
// belongs to OOD-side services should live in the owning module's lazy/seed
// initialization path. When a version cannot start from the current seed data,
// treat that as a data-format compatibility signal to review before release.
//
// Runtime: Deno >= 2.2. websdk import mapped in src/deno.json.
//
// Usage: deno run --allow-all src/make_sn_config.ts
//          [--rootfs <dir>] [--ca <dir>] [--sn_ip <ip>]
//          [--sn_base_host <host>] [--env_root <dir>] [--dev-local|--dev-vm]
//          [--seed-v2]   (seed-v2 已是唯一行为，flag 保留为 no-op)
//
// Output layout:
//   <rootfs>/sn_device_config.json    SN server device config
//   <rootfs>/sn_private_key.pem       device private key (rtcp stack)
//   <rootfs>/params.json              SN service parameters (incl. sn_ip)
//   <rootfs>/sn.sqlite3               SN sqlite database runtime path (created by cyfs-sn)
//   <rootfs>/sn_token_key/            server JWT signing key directory
//   <rootfs>/fullchain.cert/.pem      TLS cert+key for sn.$base, bns.$base,
//                                    web3.$base, *.web3.$base
//   <rootfs>/ca/                      dev CA cert+key (client trust install)
//   <rootfs>/sn_server/.buckycli/     sn admin owner config
//   <rootfs>/web3_gateway.yaml        patched when present to load sn.sqlite3
//   <rootfs>/web3_dns.yaml            独立部署拆分（DNS/relay/SN API），存在时
//   <rootfs>/web3_relay.yaml          与 web3_gateway.yaml 打同样的 web3_sn
//   <rootfs>/web3_sn_api.yaml         文本补丁（db 路径、dev bns_proxy 注入）
// Still created manually/by app template: website.yaml, local_dns.toml.
//
// Seed users: alice.ood1 / bob.ood1 / charlie.ood1 / dave.ood1 dev zones are
// materialized as bns_dv_seed.yaml and sn_seed.yaml. Their user envs are reused
// from <env_root> when present (so JWTs match rootfs built by make_config.ts)
// and generated there otherwise (DEV_TEST_KEYS are deterministic, so devices
// still verify). cyfs-sn imports sn_seed.yaml at startup; this script no longer
// writes SN-private user/device tables.

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { parseArgs } from "node:util";
import {
  assertProvisionRuntime,
  createCertFromCa,
  createSnConfigs,
  ensureCa,
} from "buckyos/provision";
import { createNodeConfigs, createUserEnv } from "buckyos/provision";
import {
  ENV_ROOT_DIR,
  getParamsFromGroupName,
  type OODGroupParams,
} from "./devenv_config.ts";

// ---------------------------------------------------------------------------
// local helpers（原从 buckyos make_config.ts 导入；本仓库不携带该脚本，
// 这里保留同语义的薄实现。machine.json 由 writeMachineConfig 生成：旧
// "web3_gateway 进程不消费 machine.json" 的断言已被证伪——cyfs_gateway
// 启动时用它初始化 name-client 的 web3_bridge（gateway.rs Gateway::start），
// RTCP keep-tunnel 对来源设备的权威验证依赖 bns 权威指向本 SN。
// ---------------------------------------------------------------------------

export function ensureDir(dirPath: string): string {
  fs.mkdirSync(dirPath, { recursive: true });
  return dirPath;
}

interface DevEd25519KeyPair {
  privateKeyPem: string;
  publicKeyX: string;
}

// websdk DEV_TEST_KEYS 之外的种子用户（如纯 Web3 位 dave）没有预置密钥，
// createNodeConfigs 查不到 `<user>.<device>` 会直接 throw。这里用固定标签
// sha256 出 32 字节种子做 ed25519 私钥（PKCS8 头 + seed），公钥 x 由
// node:crypto 导出——确定性与 DEV_TEST_KEYS 预置键等价，仅限 devtest。
function deriveDevEd25519KeyPair(label: string): DevEd25519KeyPair {
  const seed = createHash("sha256")
    .update(`buckyos-devtest-ed25519:${label}`)
    .digest();
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${
    pkcs8.toString("base64")
  }\n-----END PRIVATE KEY-----`;
  const jwk = createPublicKey(createPrivateKey(privateKeyPem)).export({
    format: "jwk",
  }) as { x?: string };
  if (!jwk.x) {
    throw new Error(`derive ed25519 key pair failed for ${label}`);
  }
  return { privateKeyPem, publicKeyX: jwk.x };
}

// 需要本地派生密钥的种子用户（不在 buckyos websdk DEV_TEST_KEYS 预置表里）。
const DERIVED_KEY_SEED_USERS = new Set(["dave"]);

function seedKeyOverrides(
  username: string,
  deviceName: string,
): { ownerKeyPair?: DevEd25519KeyPair; deviceKeyPair?: DevEd25519KeyPair } {
  if (!DERIVED_KEY_SEED_USERS.has(username)) {
    return {};
  }
  return {
    ownerKeyPair: deriveDevEd25519KeyPair(`${username}.owner`),
    deviceKeyPair: deriveDevEd25519KeyPair(`${username}.${deviceName}`),
  };
}

// Build (or rebuild) the user env dir <envRoot>/<zone_id> with provision.
// websdk createUserEnv + createNodeConfigs 的组合薄封装（与 buckyos
// make_config.ts 的 buildUserEnv 同语义），另支持 DEV_TEST_KEYS 之外用户的
// 确定性派生密钥。
export async function buildUserEnv(
  params: OODGroupParams,
  envRoot: string,
): Promise<string> {
  const userDir = ensureDir(path.join(envRoot, params.zone_id));
  const oodNameForZone = params.netid !== "lan"
    ? `${params.node_name}@${params.netid}`
    : params.node_name;
  const keyOverrides = seedKeyOverrides(params.username, params.node_name);

  await createUserEnv({
    username: params.username,
    hostname: params.zone_id,
    oodName: oodNameForZone,
    snBaseHost: params.sn_base_host,
    rtcpPort: params.rtcp_port,
    outputDir: userDir,
    ...keyOverrides,
  });
  await createNodeConfigs({
    deviceName: params.node_name,
    netId: params.netid,
    envDir: userDir,
    ...keyOverrides,
  });
  return userDir;
}

const DEFAULT_SN_BASE_HOST = "devtests.org";
const DEFAULT_CA_NAME = "buckyos_test_ca";
const PROVISION_SN_DB_FILE = "sn_db.sqlite3";
const SN_DB_FILE = "sn.sqlite3";
const SN_AUTH_DATA_DIR = "sn_token_key";
const WEB3_GATEWAY_CONFIG_FILE = "web3_gateway.yaml";
// web3_gateway.yaml 的独立部署拆分（DNS / 流量转发 / SN API）。每个文件都有
// 自己的 web3_sn server 块，provision 阶段的文本补丁（sn.sqlite3 db 路径、
// dev profile 的 bns_proxy controller 注入）必须对存在的文件同步应用，否则
// 拆分实例会各自落到不同的数据库/凭据来源。
const WEB3_GATEWAY_ALL_CONFIG_FILES = [
  WEB3_GATEWAY_CONFIG_FILE,
  "web3_dns.yaml",
  "web3_relay.yaml",
  "web3_sn_api.yaml",
];
const LOCAL_DNS_CONFIG_FILE = "local_dns.toml";
const BNS_LOCAL_DNS_BEGIN = "# BEGIN make_sn_config:bns";
const BNS_LOCAL_DNS_END = "# END make_sn_config:bns";

function printUsage(log: (message?: unknown) => void = console.error): void {
  log(
    "usage: make_sn_config.ts [--rootfs <dir>] [--ca <dir>] [--sn_ip <ip>] [--sn_base_host <host>] [--env_root <dir>] [--dev-local|--dev-vm] [--seed-v2]",
  );
}

function defaultTargetRoot(): string {
  if (os.platform() === "win32") {
    const appData = Deno.env.get("APPDATA") ?? Deno.env.get("USERPROFILE") ??
      ".";
    return path.join(appData, "web3-gateway");
  }
  return "/opt/web3-gateway";
}

function getLocalIp(): string {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const item of list ?? []) {
      if (!item.internal && item.family === "IPv4") {
        return item.address;
      }
    }
  }
  return "127.0.0.1";
}

function writeJson(file: string, data: unknown): void {
  fs.writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);
  console.log(`# Write file: ${file}`);
}

function readJson(file: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

// SN 进程内 name-client 的 bns method 权威必须指向本 SN 自己：不写这份
// machine.json 时 cyfs_gateway 落到内置默认 web3.buckyos.ai（生产环境），
// devtest 的 zone 在那边不存在，RTCP keep-tunnel 会在 SN 侧被拒绝
// （rtcp.rs resolve_source_device_info 的两级验证全部失败）。
// 值必须是纯 host（不能带 scheme）：bns bridge 根域同时承担
// did:bns:<name> ↔ <name>.<bridge> 的 hostname 映射（bns_provider.rs），
// 带 scheme 会让 RTCP DID hostname 校验失败。https 信任由部署侧安装
// dev CA 解决（web3-gateway/start.py install_dev_ca）。
// 部署侧由 web3-gateway/start.py 装载到 {BUCKYOS_ROOT}/etc/machine.json。
function writeMachineConfig(targetDir: string, snBaseHost: string): void {
  const machineConfigPath = path.join(targetDir, "machine.json");
  writeJson(machineConfigPath, {
    web3_bridge: { bns: `web3.${snBaseHost}` },
    force_https: false,
    trust_did: [
      "did:web:buckyos.org",
      "did:web:buckyos.ai",
      "did:web:buckyos.io",
    ],
  });
  console.log(`  machine.json bns bridge -> web3.${snBaseHost}`);
}

function isProvisionSnDbFile(name: string): boolean {
  return name === PROVISION_SN_DB_FILE ||
    name === `${PROVISION_SN_DB_FILE}-shm` ||
    name === `${PROVISION_SN_DB_FILE}-wal`;
}

function discardProvisionSnDb(targetDir: string): void {
  for (const suffix of ["", "-shm", "-wal"]) {
    fs.rmSync(path.join(targetDir, `${PROVISION_SN_DB_FILE}${suffix}`), {
      force: true,
    });
  }
  console.log(`SN database runtime path: ${SN_DB_FILE} (deployment-relative)`);
}

function readStagedParams(targetDir: string): Record<string, unknown> {
  const paramsPath = path.join(targetDir, "params.json");
  if (!fs.existsSync(paramsPath)) {
    return {};
  }
  try {
    const json = readJson(paramsPath);
    return (json.params && typeof json.params === "object")
      ? json.params as Record<string, unknown>
      : {};
  } catch (err) {
    console.warn(`read staged params.json failed, ignore: ${err}`);
    return {};
  }
}

function updateParamsJson(
  targetDir: string,
  snDbPath: string,
  authDataDir: string,
  stagedParams: Record<string, unknown>,
): void {
  const paramsPath = path.join(targetDir, "params.json");
  const json = readJson(paramsPath);
  const params = (json.params && typeof json.params === "object")
    ? json.params as Record<string, unknown>
    : {};
  // createSnConfigs 重写 params.json 时会丢掉仓库模板新增的参数
  // (例如 bns_server_url),这里把 staged(仓库)里有而生成结果缺失的
  // key 补回来;身份类参数以生成结果为准。
  for (const [key, value] of Object.entries(stagedParams)) {
    if (!(key in params)) {
      console.log(`# params.json: restore staged param ${key}`);
      params[key] = value;
    }
  }
  params.sn_db_path = snDbPath;
  delete params.sn_v2_auth_data_dir;
  params.sn_auth_data_dir = authDataDir;
  json.params = params;
  writeJson(paramsPath, json);
}

function leadingSpaces(line: string): number {
  const match = line.match(/^ */);
  return match ? match[0].length : 0;
}

function patchWeb3GatewayConfigText(text: string): string | null {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim() === "web3_sn:");
  if (start < 0) {
    return null;
  }

  const indent = leadingSpaces(lines[start]);
  let end = start + 1;
  while (end < lines.length) {
    const line = lines[end];
    if (
      line.trim() !== "" &&
      !line.trimStart().startsWith("#") &&
      leadingSpaces(line) <= indent
    ) {
      break;
    }
    end++;
  }

  const childIndent = indent + 2;
  const nestedIndent = childIndent + 2;
  const block = lines.slice(start + 1, end);
  const filtered: string[] = [];
  for (let i = 0; i < block.length; i++) {
    const line = block[i];
    const trim = line.trim();
    const lineIndent = leadingSpaces(line);
    if (
      lineIndent === childIndent &&
      (trim.startsWith("v2_auth_data_dir:") ||
        trim.startsWith("auth_data_dir:") ||
        trim.startsWith("db_type:") ||
        trim.startsWith("db_path:"))
    ) {
      continue;
    }
    if (lineIndent === childIndent && trim === "db_params:") {
      i++;
      while (i < block.length && leadingSpaces(block[i]) > childIndent) {
        i++;
      }
      i--;
      continue;
    }
    filtered.push(line);
  }

  const insertLines = [
    `${" ".repeat(childIndent)}auth_data_dir: "{{sn_auth_data_dir}}"`,
    `${" ".repeat(childIndent)}db_type: sqlite`,
    `${" ".repeat(childIndent)}db_params:`,
    `${" ".repeat(nestedIndent)}db_path: "{{sn_db_path}}"`,
  ];
  const ipLine = filtered.findIndex((line) =>
    leadingSpaces(line) === childIndent && line.trim().startsWith("ip:")
  );
  const insertAt = ipLine >= 0 ? ipLine + 1 : filtered.length;
  const patchedBlock = [
    ...filtered.slice(0, insertAt),
    ...insertLines,
    ...filtered.slice(insertAt),
  ];

  const patchedLines = [
    ...lines.slice(0, start + 1),
    ...patchedBlock,
    ...lines.slice(end),
  ];
  return patchedLines.join("\n");
}

function patchWeb3GatewayConfig(targetDir: string): void {
  for (const configFile of WEB3_GATEWAY_ALL_CONFIG_FILES) {
    const configPath = path.join(targetDir, configFile);
    if (!fs.existsSync(configPath)) {
      console.log(
        `skip ${configFile} patch: file not found in ${targetDir}`,
      );
      continue;
    }

    const original = fs.readFileSync(configPath, "utf8");
    const patched = patchWeb3GatewayConfigText(original);
    if (patched === null) {
      console.log(
        `skip ${configFile} patch: web3_sn server block not found`,
      );
      continue;
    }
    if (patched !== original) {
      fs.writeFileSync(configPath, patched);
      console.log(`Patched ${configPath} to use ${SN_DB_FILE}`);
    } else {
      console.log(`${configPath} already uses ${SN_DB_FILE}`);
    }
  }
}

/**
 * local_dns.toml is loaded directly by LocalConfigDnsProvider and therefore is
 * not rendered through params.json. Keep the staged template portable and
 * materialize the deployment-specific bns.<sn_host> -> sn_ip record here.
 */
export function patchLocalDnsBnsRecord(
  targetDir: string,
  snBaseHost: string,
  snIp: string,
): void {
  const configPath = path.join(targetDir, LOCAL_DNS_CONFIG_FILE);
  if (!fs.existsSync(configPath)) {
    console.log(
      `skip ${LOCAL_DNS_CONFIG_FILE} BNS record: file not found in ${targetDir}`,
    );
    return;
  }

  const bnsHostname = `bns.${snBaseHost}`;
  const original = fs.readFileSync(configPath, "utf8");
  const lines = original.split(/\r?\n/);
  let start = lines.findIndex((line) => line.trim() === BNS_LOCAL_DNS_BEGIN);
  let end: number;

  if (start >= 0) {
    end = lines.findIndex(
      (line, index) => index > start && line.trim() === BNS_LOCAL_DNS_END,
    );
    if (end < 0) {
      throw new Error(
        `${LOCAL_DNS_CONFIG_FILE}: missing ${BNS_LOCAL_DNS_END}`,
      );
    }
    end += 1;
  } else {
    // Adopt a pre-existing exact record so rerunning the generator does not
    // leave duplicate TOML tables behind.
    const tableHeader = `[${JSON.stringify(bnsHostname)}]`;
    start = lines.findIndex((line) => line.trim() === tableHeader);
    if (start >= 0) {
      end = start + 1;
      while (end < lines.length && !/^\s*\[.*\]\s*$/.test(lines[end])) {
        end += 1;
      }
    } else {
      start = lines.length;
      end = lines.length;
    }
  }

  const managedBlock = [
    BNS_LOCAL_DNS_BEGIN,
    `[${JSON.stringify(bnsHostname)}]`,
    "ttl = 60",
    `address = [${JSON.stringify(snIp)}]`,
    BNS_LOCAL_DNS_END,
  ];
  lines.splice(start, end - start, ...managedBlock);
  while (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  fs.writeFileSync(configPath, `${lines.join("\n")}\n`);
  console.log(
    `Patched ${configPath}: ${bnsHostname} -> ${snIp}`,
  );
}

async function makeSnConfigs(
  targetDir: string,
  snBaseHost: string,
  snIp: string,
  caDir: string,
  caName: string,
): Promise<void> {
  console.log(`Generating SN configuration files to ${targetDir} ...`);
  console.log(`  SN base domain: ${snBaseHost}`);
  console.log(`  SN IP address: ${snIp}`);
  ensureDir(targetDir);

  // createSnConfigs 会生成新的 params.json 并覆盖 buckyos-install 从仓库
  // staged 过来的那份;先快照 staged 参数,稍后在 updateParamsJson 里补回。
  const stagedParams = readStagedParams(targetDir);

  // 1. SN device identity configuration (written under <targetDir>/sn_server)
  console.log("# Step 1: Create SN device identity configuration...");
  await createSnConfigs({ outputDir: targetDir, snIp, snBaseHost });

  // move generated files up to targetDir; .buckycli stays in sn_server
  const snServerDir = path.join(targetDir, "sn_server");
  if (fs.existsSync(snServerDir)) {
    for (const name of fs.readdirSync(snServerDir)) {
      const src = path.join(snServerDir, name);
      if (fs.statSync(src).isFile()) {
        if (isProvisionSnDbFile(name)) {
          fs.rmSync(src, { force: true });
          console.log(`Discard provision database: ${name}`);
          continue;
        }
        fs.renameSync(src, path.join(targetDir, name));
        console.log(`Move file: ${name} -> ${targetDir}/`);
      }
    }
    if (fs.readdirSync(snServerDir).length === 0) {
      fs.rmdirSync(snServerDir);
    }
  }

  discardProvisionSnDb(targetDir);
  ensureDir(path.join(targetDir, SN_AUTH_DATA_DIR));
  // params.json 会随部署目录整体复制到另一台机器，运行态路径必须相对于
  // web3_gateway 的工作目录，不能泄漏 provision 时的宿主机输出路径。
  updateParamsJson(
    targetDir,
    SN_DB_FILE,
    SN_AUTH_DATA_DIR,
    stagedParams,
  );
  patchWeb3GatewayConfig(targetDir);
  patchLocalDnsBnsRecord(targetDir, snBaseHost, snIp);
  writeMachineConfig(targetDir, snBaseHost);

  // 2. TLS certificates for the SN, BNS, and web3 gateway public hosts
  console.log("# Step 2: Generate TLS certificates...");
  await ensureCa(caDir, caName);
  const snHostname = `sn.${snBaseHost}`;
  const { certPath, keyPath } = await createCertFromCa(
    caDir,
    snHostname,
    targetDir,
    [
      snHostname,
      `bns.${snBaseHost}`,
      `web3.${snBaseHost}`,
      `*.web3.${snBaseHost}`,
    ],
  );
  fs.renameSync(certPath, path.join(targetDir, "fullchain.cert"));
  fs.renameSync(keyPath, path.join(targetDir, "fullchain.pem"));

  // keep dev CA cert+key next to the SN config for client trust install
  const caOutputDir = ensureDir(path.join(targetDir, "ca"));
  for (const name of [`${caName}_ca_cert.pem`, `${caName}_ca_key.pem`]) {
    fs.copyFileSync(path.join(caDir, name), path.join(caOutputDir, name));
  }
  console.log("TLS certificates generated:");
  console.log(`  - ${path.join(targetDir, "fullchain.cert")}`);
  console.log(`  - ${path.join(targetDir, "fullchain.pem")}`);
  console.log(`  - ${path.join(caOutputDir, `${caName}_ca_cert.pem`)}`);
}

// ===========================================================================
// seed-v2：cyfs-sn 新架构下的种子构造
// ===========================================================================
//
// 需求来源：
// - cyfs-gateway/doc/SN/新SN核心流程整理.md：BNS 是权威状态系统，SN 只从
//   bns-indexer 读最终状态；SN 本地只保留账号/登录态等无默认值的数据。
// - cyfs-gateway/doc/SN/SN运行态lazy-init改造TODO.md：A 类（BNS 派生缓存）与
//   B 类（纯运行态）不由 provision 预置，只有 C 类（sn_user 账号）必须显式创建。
// - buckyos/doc/CI/基于VM的开发环境构造.md：hosts、DNS 指向、CA 信任、VM 生命
//   周期由 buckyos-devtest 环境脚本负责；本脚本专注 seed config 的构造。
//
// 核心模式：本脚本不直写各组件的私有存储，而是为每个组件产出一份
// "初始化种子配置"，组件自己实现"从配置初始化"（幂等）。组件侧配套：
//
// 1. bns_dv【已实现】`serve --config/--seed-config <yaml>`：seed（签名 key、
//    幂等策略）+ on_init_txs（type=register_name + initial_documents，
//    if_exists=apply_mutations 幂等重放；inline_json*/inline_text* 两类文档
//    载体）。真值见 src/components/bns-server/src/bin/bns_dv.rs 的
//    BnsDvInitConfig。【待扩展】controller policy / owner 变更类 tx type
//    （P1，托管代发需要）。
// 2. web3-gateway/start.py【已实现】部署目录存在 bns_dv_seed.yaml 时给
//    bns_dv 追加 `--seed-config <path>`。
// 3. cyfs-sn web3_sn server【已实现】启动时从 sn_seed.yaml 幂等导入 C 类
//    种子（激活码、sn_user 账号、user_domain 绑定），格式真值
//    cyfs-sn/src/sn_seed.rs；schema 完全归 SN 所有。
// 4. web3_gateway.yaml【已实现】bns_rpc_url 参数化为 {{bns_rpc_url}}，
//    由 params.json 提供（alignBnsRuntimeParams 与 dv-env.json 对齐）。
//
// 验证入口：scripts/sn-dev-up.sh + sn-dev-smoke.sh（本机三件套）与
// `cargo test -p cyfs_gateway --test e2e_sn_seed -- --ignored`（T1-T6）。

/** 种子用户的 SN 侧视图描述（真值仍来自 devenv_config.ts 的组定义）。 */
export interface SnSeedUserSpec {
  /** devenv_config.ts OOD_GROUPS 的 key，如 "alice.ood1"。 */
  groupName: string;
  username: string;
  /** SN 账号邮箱；devtest 统一使用 <username>@buckyos.org。 */
  email: string;
  /** alice.bns.did（did:bns 型）或 charlie.me（自有域名型）。 */
  zoneId: string;
  /** true = Web2 注册用户（建 sn_user 账号）；false = 纯 Web3 用户（只上链）。 */
  snAccount: boolean;
  /** 自有域名 zone 时给出，ZoneDocument 走 SN user_domain 机制而非 BNS。 */
  userDomain?: string;
}

/** bns_dv 种子文件的 TS 镜像（真值：bns_dv.rs BnsDvInitConfig，勿漂移）。 */
export interface BnsDvSeedDocument {
  /** owner / zone / boot / device_mini_doc / dns_txt ... */
  doc_type: string;
  /** 相对 seed yaml 所在目录的文档 JSON 路径。 */
  inline_json_file?: string;
  inline_json?: unknown;
  /** 原样上链的文本文档（如 owner key 签名的 boot JWT，不做 JSON 包装）。 */
  inline_text_file?: string;
  inline_text?: string;
}

export interface BnsDvSeedTx {
  type: "register_name";
  name: string;
  /** 用户 EVM 地址（固定助记词确定性派生）。owner 权威必须锚在用户地址上，
   * 即使注册 tx 由 dev key 代发。 */
  asset_owner: string;
  if_exists: "apply_mutations" | "fail";
  initial_documents: BnsDvSeedDocument[];
}

export interface BnsDvSeedConfig {
  seed: {
    /** 缺省 anvil account[0]；显式写出，避免依赖 bns_dv 的隐式缺省。 */
    private_key?: string;
    private_key_env?: string;
    if_exists?: "apply_mutations" | "fail";
  };
  on_init_txs: BnsDvSeedTx[];
}

/** sn_seed.yaml 的 TS 镜像（真值：cyfs-sn/src/sn_seed.rs SnSeedConfig，勿漂移）。 */
export interface SnSeedConfigMirror {
  activation_codes: string[];
  users: {
    username: string;
    email: string;
    password: string;
    /** ed25519 owner 公钥（JWK x 分量）。 */
    owner_public_key: string;
    bns_name?: string;
    /** devtest 预置证书可用；测试环境不依赖 ACME 回写。 */
    self_cert?: boolean;
  }[];
  user_domains: {
    domain: string;
    owner: string;
    pkx: string;
    zone_document_jwt: string;
  }[];
}

/** 与 sn_seed.yaml 对齐的确定性 dev 测试密码/激活码（仅限 devtest）。 */
export const DEV_TEST_PASSWORD = "devtest-pwd";
export const SEED_ACTIVATION_CODE_COUNT = 16;
export const SEED_ACTIVATION_CODES = Array.from(
  { length: SEED_ACTIVATION_CODE_COUNT },
  (_, index) => `dev-code-${index + 1}`,
);

// anvil 固定助记词 "test test ... junk"（路径 m/44'/60'/0'/0/i）的标准账户
// 表，预展开硬编码——与 websdk DEV_TEST_KEYS 预置 ed25519 键、bns_dv 硬编码
// account[0] 托管 key 是同一做法：固定助记词确定性派生，公开知识，仅限
// devtest。account[0] 留给 bns_dv 托管代发（等价 Web2 代注册），用户位从
// account[1] 起。
const ANVIL_DEV_ACCOUNTS: { address: string; privateKey: string }[] = [
  {
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    privateKey:
      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  },
  {
    address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    privateKey:
      "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  },
  {
    address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    privateKey:
      "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  },
  {
    address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    privateKey:
      "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  },
  {
    address: "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
    privateKey:
      "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  },
  {
    address: "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
    privateKey:
      "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  },
];

/** bns_dv 托管代发 key（anvil account[0]），显式写进 seed.private_key。 */
const BNS_DV_SEED_SENDER = ANVIL_DEV_ACCOUNTS[0];

// SN BNS proxy dev-local controller keys（anvil account[2]/[4]）。仅写入
// --dev-local 生成的临时 rootfs，用来覆盖 auth.register -> bns_proxy 的
// 用户无手续费真实写链路径。
const SN_DEV_BNS_PROXY_CONTROLLERS = [
  { id: "controller-a", account: ANVIL_DEV_ACCOUNTS[2] },
  { id: "controller-b", account: ANVIL_DEV_ACCOUNTS[4] },
];

// 用户名 -> anvil 账户索引的固定映射（新种子用户在此登记，保持确定性）。
const SEED_USER_EVM_INDEX: Record<string, number> = {
  alice: 1,
  bob: 2,
  charlie: 3,
  dave: 4,
};

/** 参与 seed-v2 的 devenv 组（真值：devenv_config.ts OOD_GROUPS）。 */
const SEED_GROUP_NAMES = [
  "alice.ood1",
  "bob.ood1",
  "charlie.ood1",
  "dave.ood1",
];

/**
 * 种子用户清单：从 devenv_config.ts 推导 alice/bob/charlie（snAccount=true，
 * charlie 带 userDomain=charlie.me）+ dave（snAccount=false 纯 Web3 位——
 * devenv 注释"did:bns:alice 可以不是 SN 注册用户"的测试实例，验证 lazy-init
 * 的"解除 sn_user 前提"：纯钱包用户不建 sn_user 也能被 SN 解析）。
 */
export function getSeedUserSpecs(): SnSeedUserSpec[] {
  return SEED_GROUP_NAMES.map((groupName) => {
    const params = getParamsFromGroupName(groupName);
    const isBnsZone = params.zone_id.endsWith(".bns.did");
    return {
      groupName,
      username: params.username,
      email: `${params.username}@buckyos.org`,
      zoneId: params.zone_id,
      snAccount: params.sn_account !== false,
      userDomain: isBnsZone ? undefined : params.zone_id,
    };
  });
}

/**
 * 确定性派生用户 EVM 账户（devenv 注释：用户密钥对使用固定助记词构造，
 * 非随机；与 ed25519 owner key 同源不同用途）。地址用作 BNS name 的
 * asset_owner；私钥供用例层测试"用户直发已签 raw tx"的纯 Web3 路径。
 */
export function deriveUserEvmAccount(
  username: string,
): { address: string; privateKey: string } {
  const index = SEED_USER_EVM_INDEX[username];
  const account = index === undefined ? undefined : ANVIL_DEV_ACCOUNTS[index];
  if (!account) {
    throw new Error(
      `no deterministic EVM account for seed user ${username}; register it in SEED_USER_EVM_INDEX`,
    );
  }
  return account;
}

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("invalid JWT: expected 3 segments");
  }
  const payload = Buffer.from(
    parts[1].replaceAll("-", "+").replaceAll("_", "/"),
    "base64",
  ).toString("utf8");
  return JSON.parse(payload);
}

interface SeedUserEnvView {
  bootConfigJwt: string;
  deviceMiniDocJwt: string;
  pkx: string;
  zoneBootJson: Record<string, unknown>;
}

// 读取（缺失则先构建）用户 env，取出种子需要的签名 JWT 与公钥。
async function loadSeedUserEnv(
  envRoot: string,
  user: SnSeedUserSpec,
): Promise<SeedUserEnvView> {
  const params = getParamsFromGroupName(user.groupName);
  const userDir = path.join(envRoot, params.zone_id);
  if (
    !fs.existsSync(path.join(userDir, params.node_name, "node_identity.json"))
  ) {
    console.log(`user env missing, generate: ${userDir}`);
    await buildUserEnv(params, envRoot);
  }
  const zoneRecord = readJson(path.join(userDir, "zone_txt_record.json"));
  const bootConfigJwt = String(zoneRecord.boot_config_jwt ?? "");
  const deviceMiniDocJwt = String(zoneRecord.device_mini_doc_jwt ?? "");
  const pkx = String(zoneRecord.pkx ?? "");
  if (!bootConfigJwt || !deviceMiniDocJwt || !pkx) {
    throw new Error(
      `user env ${userDir} zone_txt_record.json misses boot_config_jwt/device_mini_doc_jwt/pkx`,
    );
  }
  const zoneBootJson = readJson(
    path.join(userDir, `${params.zone_id}.zone.json`),
  );
  return { bootConfigJwt, deviceMiniDocJwt, pkx, zoneBootJson };
}

function yamlQuote(value: string): string {
  return JSON.stringify(value);
}

// 链上 zone 文档必须满足 name-lib ZoneDocument 的 schema（id /
// verificationMethod / authentication / iat 必填）：SN 对 RTCP keep-tunnel
// 来源设备验证的回落路径用 resolve_auth_key(owner) 解析 owner DID，name-lib
// 按 oods 字段识别为 ZoneDocument 后从 verificationMethod[0] 取 owner 公钥
// 验 device_doc_jwt 签名。env 的 <zone>.zone.json 只有 oods/sn/exp（BuckyOS
// boot 面形状），直接上链会让 SN 侧 parse 失败并拒绝 keep-tunnel。BuckyOS
// 侧 boot/zone 消费面对新增字段宽容，补全无影响。
const SEED_ZONE_DOC_IAT = 1735689600; // 2025-01-01T00:00:00Z，devtest 确定性时间戳

function toZoneDocumentJson(
  username: string,
  env: SeedUserEnvView,
): Record<string, unknown> {
  const zone: Record<string, unknown> = { ...env.zoneBootJson };
  const zoneDid = `did:bns:${username}`;
  zone.id = zoneDid;
  zone.owner = zoneDid;
  zone.verificationMethod = [
    {
      type: "Ed25519VerificationKey2020",
      id: "#owner",
      controller: zoneDid,
      publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: env.pkx },
    },
  ];
  zone.authentication = ["#owner"];
  zone.boot_jwt = env.bootConfigJwt;
  if (zone.hostname === undefined) {
    // devtest zone 的 web 主机名：sn 字段形如 sn.<base>，zone host 挂在
    // <user>.web3.<base>；没有 sn 字段时退回 DID 规范 host。
    const sn = typeof zone.sn === "string" ? zone.sn : "";
    zone.hostname = sn.startsWith("sn.")
      ? `${username}.web3.${sn.slice("sn.".length)}`
      : `${username}.bns.did`;
  }
  if (zone.iat === undefined) {
    zone.iat = SEED_ZONE_DOC_IAT;
  }
  return zone;
}

/**
 * 产出 bns_dv 的启动种子配置，让种子用户的 BNS 权威文档真正上链：
 *   <targetDir>/bns_dv_seed.yaml             BnsDvSeedConfig
 *   <targetDir>/bns_seed_docs/<user>/*       每用户 owner/zone/boot/device_mini_doc
 * 文档内容取自 <envRoot> 用户 env（owner key 已签好的 JWT），多文档随
 * register_name 一次提交（多文档原子写优先用合约批量接口）。种子经 bns_dv
 * 托管 key 代发（等价 Web2 代注册），asset_owner 锚定用户 EVM 地址。
 * 这是 resolver A 类路径（indexer lazy 解析）在测试环境有数据可测的前提，
 * 补 SN-测试计划 §7 的端到端缺口。消费方：start.py（组件侧需求 2）。
 *
 * 文档形状与 resolver 消费面对齐（test_sn_bns_integration 同款）：
 *   owner            {"id":"did:bns:<u>","x":<pkx>}          PKX TXT / resolve_owner
 *   zone             env zone.json 补全 ZoneDocument 必填字段  见 toZoneDocumentJson
 *   boot             签名 boot JWT 原文（inline_text_file）    原子文档；BOOT= TXT 取 jwt
 *   device_mini_doc  {"devices":{"<ood>":{payload+jwt}}}      设备解析 + DEV= TXT
 * did:web 用户（userDomain）只上链 owner——其 ZoneDocument 权威在 SN 的
 * user_domain 机制（见 makeSnAuthSeedConfig），不在 BNS。
 */
export async function makeBnsDvSeedConfig(
  targetDir: string,
  envRoot: string,
  users: SnSeedUserSpec[],
): Promise<string> {
  const docsRootName = "bns_seed_docs";
  const docsRoot = ensureDir(path.join(targetDir, docsRootName));
  const txs: string[] = [];

  for (const user of users) {
    const env = await loadSeedUserEnv(envRoot, user);
    const evm = deriveUserEvmAccount(user.username);
    const userDocsDir = ensureDir(path.join(docsRoot, user.username));
    const docLines: string[] = [];

    const ownerRel = `${docsRootName}/${user.username}/owner.json`;
    writeJson(path.join(userDocsDir, "owner.json"), {
      id: `did:bns:${user.username}`,
      x: env.pkx,
    });
    docLines.push(
      `      - doc_type: owner`,
      `        inline_json_file: ${yamlQuote(ownerRel)}`,
    );

    if (!user.userDomain) {
      const zoneRel = `${docsRootName}/${user.username}/zone.json`;
      writeJson(
        path.join(userDocsDir, "zone.json"),
        toZoneDocumentJson(user.username, env),
      );
      docLines.push(
        `      - doc_type: zone`,
        `        inline_json_file: ${yamlQuote(zoneRel)}`,
      );

      const bootRel = `${docsRootName}/${user.username}/boot.jwt`;
      fs.writeFileSync(
        path.join(userDocsDir, "boot.jwt"),
        `${env.bootConfigJwt}\n`,
      );
      console.log(`# Write file: ${path.join(userDocsDir, "boot.jwt")}`);
      docLines.push(
        `      - doc_type: boot`,
        `        inline_text_file: ${yamlQuote(bootRel)}`,
      );

      const params = getParamsFromGroupName(user.groupName);
      const miniPayload = decodeJwtPayload(env.deviceMiniDocJwt);
      const miniRel = `${docsRootName}/${user.username}/device_mini_doc.json`;
      writeJson(path.join(userDocsDir, "device_mini_doc.json"), {
        devices: {
          [params.node_name]: {
            ...miniPayload,
            mini_config_jwt: env.deviceMiniDocJwt,
          },
        },
      });
      docLines.push(
        `      - doc_type: device_mini_doc`,
        `        inline_json_file: ${yamlQuote(miniRel)}`,
      );
    }

    txs.push(
      [
        `  - type: register_name`,
        `    name: ${yamlQuote(user.username)}`,
        `    asset_owner: ${yamlQuote(evm.address)}`,
        // 注册后 owner 已锚定用户地址，重放 apply_mutations（种子文档变更）
        // 合约只认 owner 本人签名——托管 key 发会 EVM revert。anvil 账户表
        // 私钥是公开知识，仅限 devtest。
        `    asset_owner_key: ${yamlQuote(evm.privateKey)}`,
        `    if_exists: apply_mutations`,
        `    initial_documents:`,
        ...docLines,
      ].join("\n"),
    );
  }

  const seedYamlPath = path.join(targetDir, "bns_dv_seed.yaml");
  const yaml = [
    "# bns_dv_seed.yaml —— make_sn_config.ts (seed-v2) 生成，格式真值见",
    "# bns_dv.rs BnsDvInitConfig。种子经 bns_dv 托管 key 代发（等价 Web2 代",
    "# 注册），asset_owner 锚定各用户 EVM 地址（anvil 固定助记词账户表）；",
    "# asset_owner_key 供重启重放：文档变更时合约只认 owner 本人签名的",
    "# apply_mutations。仅限 devtest：托管 key 与账户表私钥都是公开知识。",
    "seed:",
    `  private_key: ${yamlQuote(BNS_DV_SEED_SENDER.privateKey)}`,
    "  if_exists: apply_mutations",
    "on_init_txs:",
    ...txs,
    "",
  ].join("\n");
  fs.writeFileSync(seedYamlPath, yaml);
  console.log(`# Write file: ${seedYamlPath}`);
  return seedYamlPath;
}

/**
 * 产出 cyfs-sn 的 C 类种子 <targetDir>/sn_seed.yaml，内容仅限 lazy-init 分类
 * 中无合理默认值、必须显式创建的部分：
 *   - activation_codes：若干未用激活码（Web2 注册流程测试）
 *   - sn_user 账号：username / 确定性测试密码 / owner 公钥 / bns_name 绑定
 *     / self_cert=true（仅 snAccount=true 的用户；devtest 已预置测试证书，
 *     ACME 在离线测试环境不可用；不含 zone_config——zone/boot 权威在 BNS）
 *   - user_domain 绑定：charlie.me -> sn_user + PKX + ZoneDocument
 *     （did:web:$zoneid 的 ZoneDocument 按 devenv 注释走 user_domain 机制）
 * 除了上述 devtest self_cert 例外，不产出：zone_info 运行字段、
 * device 在线态、relay 分配（B 类默认值）、
 * device_mini_doc（A 类，已在 makeBnsDvSeedConfig 上链）。
 * 消费方：cyfs-sn 启动幂等导入（web3_gateway.yaml web3_sn.seed_path）。
 * 格式真值：cyfs-sn/src/sn_seed.rs SnSeedConfig（TS 镜像 SnSeedConfigMirror）。
 */
export async function makeSnAuthSeedConfig(
  targetDir: string,
  envRoot: string,
  users: SnSeedUserSpec[],
): Promise<string> {
  const seed: SnSeedConfigMirror = {
    activation_codes: [...SEED_ACTIVATION_CODES],
    users: [],
    user_domains: [],
  };

  for (const user of users) {
    if (!user.snAccount) {
      continue;
    }
    const env = await loadSeedUserEnv(envRoot, user);
    seed.users.push({
      username: user.username,
      email: user.email,
      password: DEV_TEST_PASSWORD,
      owner_public_key: env.pkx,
      bns_name: user.username,
      self_cert: true,
    });
    if (user.userDomain) {
      seed.user_domains.push({
        domain: user.userDomain,
        owner: user.username,
        pkx: env.pkx,
        zone_document_jwt: env.bootConfigJwt,
      });
    }
  }

  const lines: string[] = [
    "# sn_seed.yaml —— make_sn_config.ts (seed-v2) 生成。格式真值：cyfs-sn",
    "# src/sn_seed.rs SnSeedConfig；幂等语义 ensure-exists，见 doc/SN/SN-Seed-Config.md。",
    "# C 类数据 + devtest self_cert=true（测试证书已预置，不依赖 ACME）。",
    "# 明文密码仅限 devtest。",
    `activation_codes: [${seed.activation_codes.map(yamlQuote).join(", ")}]`,
    "users:",
  ];
  for (const user of seed.users) {
    lines.push(
      `  - username: ${yamlQuote(user.username)}`,
      `    email: ${yamlQuote(user.email)}`,
      `    password: ${yamlQuote(user.password)}`,
      `    owner_public_key: ${yamlQuote(user.owner_public_key)}`,
      `    bns_name: ${yamlQuote(user.bns_name ?? user.username)}`,
      `    self_cert: ${user.self_cert === true ? "true" : "false"}`,
    );
  }
  if (seed.user_domains.length === 0) {
    lines.push("user_domains: []");
  } else {
    lines.push("user_domains:");
    for (const entry of seed.user_domains) {
      lines.push(
        `  - domain: ${yamlQuote(entry.domain)}`,
        `    owner: ${yamlQuote(entry.owner)}`,
        `    pkx: ${yamlQuote(entry.pkx)}`,
        `    zone_document_jwt: ${yamlQuote(entry.zone_document_jwt)}`,
      );
    }
  }
  lines.push("");

  const seedYamlPath = path.join(targetDir, "sn_seed.yaml");
  fs.writeFileSync(seedYamlPath, lines.join("\n"));
  console.log(`# Write file: ${seedYamlPath}`);
  return seedYamlPath;
}

// web3_gateway.yaml 五个 bind 的参数缺省值（VM/生产拓扑，行为与参数化前
// 一致）。tls_port 是 tls_raw_forward 内部 `forward tcp:///:<port>` 的目标，
// 必须与 tls_bind 的端口一致。
const VM_BIND_PARAMS: Record<string, string> = {
  dns_bind: "0.0.0.0:53",
  http_bind: "0.0.0.0:80",
  rtcp_bind: "0.0.0.0:2980",
  tls_bind: "0.0.0.0:3443",
  sni_bind: "0.0.0.0:443",
  tls_port: "3443",
};

// --dev-local profile：本机（非 VM）拉起用的高位端口，避开 bns_dv 的
// 18080 与 buckyos 测试常用 19xxx/2xxx 段（历史上有 TIME_WAIT 干扰）。
const DEV_LOCAL_BIND_PARAMS: Record<string, string> = {
  dns_bind: "127.0.0.1:15353",
  http_bind: "127.0.0.1:18081",
  rtcp_bind: "127.0.0.1:12980",
  tls_bind: "127.0.0.1:13443",
  sni_bind: "127.0.0.1:14443",
  tls_port: "13443",
};

/**
 * 保证 params.json 提供 web3_gateway.yaml 的 bind 参数：缺失的 key 补 VM
 * 缺省值（fresh rootfs 没有 staged params 时 {{dns_bind}} 等必须有值）；
 * --dev-local 时强制写入本机高位端口 profile。
 */
export function applyBindParams(targetDir: string, devLocal: boolean): void {
  const paramsPath = path.join(targetDir, "params.json");
  const json = fs.existsSync(paramsPath) ? readJson(paramsPath) : {};
  const params = (json.params && typeof json.params === "object")
    ? json.params as Record<string, unknown>
    : {};
  const profile = devLocal ? DEV_LOCAL_BIND_PARAMS : VM_BIND_PARAMS;
  for (const [key, value] of Object.entries(profile)) {
    if (devLocal || !(key in params)) {
      params[key] = value;
    }
  }
  json.params = params;
  writeJson(paramsPath, json);
}

/**
 * 把 BNS 运行参数收敛进 params.json，消除三处各自写死：start.py 的 RPC/合约
 * 常量、web3_gateway.yaml 写死的 bns_rpc_url、dv 环境实际产出的
 * dv-env.json（rpc_endpoint/chain_id/contract_address/server_url/
 * server_rpc_path）。存在 dv-env.json 时以其为准写入 bns_rpc_url /
 * bns_server_url 等 key；无 dv-env.json 时写 start.py 内置拓扑的缺省值
 * （web3_gateway.yaml 的 {{bns_rpc_url}} 必须始终有值）。
 */
export function alignBnsRuntimeParams(targetDir: string): void {
  const paramsPath = path.join(targetDir, "params.json");
  const json = fs.existsSync(paramsPath) ? readJson(paramsPath) : {};
  const params = (json.params && typeof json.params === "object")
    ? json.params as Record<string, unknown>
    : {};

  // start.py 内置拓扑的缺省值（bns_dv 固定拉起在 127.0.0.1:18080）。
  let serverUrl = "http://127.0.0.1:18080";

  const dvEnvPath = path.join(targetDir, "dv-env.json");
  if (fs.existsSync(dvEnvPath)) {
    const dvEnv = readJson(dvEnvPath);
    if (typeof dvEnv.server_url === "string" && dvEnv.server_url) {
      serverUrl = dvEnv.server_url;
    }
    for (
      const key of ["rpc_endpoint", "chain_id", "contract_address"] as const
    ) {
      const value = dvEnv[key];
      if (value !== undefined && value !== "") {
        // 网关 params 模板引擎只接受字符串值，数值一律字符串化。
        params[`bns_${key}`] = typeof value === "number"
          ? String(value)
          : value;
      }
    }
    console.log(`# params.json: BNS runtime params taken from ${dvEnvPath}`);
  }

  params.bns_rpc_url = serverUrl;
  params.bns_server_url = serverUrl;
  json.params = params;
  writeJson(paramsPath, json);
}

/**
 * --dev-local 的 sn-dev-up.sh 会先写 dv-env.json，再运行 make_sn_config。
 * 这里把真实 anvil/BNS 合约参数注入 SN 配置，打开 auth.register ->
 * SnBnsProxy -> bns-rpc 的写链路径；模板默认要求通过 secret 提供 key。
 */
function injectDevBnsProxy(
  targetDir: string,
  profile: string,
): void {
  const proxyBlock = [
    "    bns_proxy:",
    "      require_user_asset_owner: true",
    "      allowed_operations: [register_name_bootstrap, publish_dns_txt, publish_relay_assignment, publish_document]",
    "      controllers:",
    ...SN_DEV_BNS_PROXY_CONTROLLERS.flatMap(({ id, account }) => [
      `        - id: ${id}`,
      `          address: ${yamlQuote(account.address)}`,
      `          private_key: ${yamlQuote(account.privateKey)}`,
      "          weight: 1",
    ]),
  ].join("\n");
  const baseProxyBlock = [
    "    bns_evm:",
    "      controller_private_key_env: BNS_SN_CONTROLLER_PRIVATE_KEY",
    "    bns_proxy:",
    "      require_user_asset_owner: true",
  ].join("\n");

  let injected = false;
  for (const configFile of WEB3_GATEWAY_ALL_CONFIG_FILES) {
    const gatewayPath = path.join(targetDir, configFile);
    if (!fs.existsSync(gatewayPath)) {
      continue;
    }
    const before = fs.readFileSync(gatewayPath, "utf8");
    if (
      before.includes(
        "bns_proxy:\n      require_user_asset_owner: true\n      allowed_operations:",
      )
    ) {
      continue;
    }
    const after = before.replace(baseProxyBlock, proxyBlock);
    if (after === before) {
      throw new Error(
        `failed to inject ${profile} bns_proxy into ${gatewayPath}: base proxy block not found`,
      );
    }
    fs.writeFileSync(gatewayPath, after);
    injected = true;
  }
  if (injected) {
    console.log(`  ${profile} bns_proxy enabled for auth.register smoke path`);
  }
}

export function enableDevLocalBnsProxy(targetDir: string): void {
  injectDevBnsProxy(
    targetDir,
    "dev-local",
  );
}

/**
 * VM profile 的 Anvil/BNS RPC 在部署到 VM 后才初始化；生成阶段写入 dev
 * controller，init_anvil.py 再把 BNS RPC 地址写入 params.json。
 */
export function enableDevVmBnsProxy(targetDir: string): void {
  injectDevBnsProxy(
    targetDir,
    "dev-vm",
  );
}

// P1 骨架的占位错误（P0 seed-v2 主链路已实现，下面两个函数维持骨架）。
const SEED_V2_P1_TODO = "TODO(seed-v2 P1): not implemented";

/**
 * P1：Web2 托管代发路径的 SN controller 身份种子。
 * 生成/复用托管 EVM key，写 params.json 的 sn_controller_principal /
 * sn_controller_kid / allowed_controller_doc_types / bns_evm，并在种子 tx 里
 * 为相关 name 设置受限 controller policy（依赖组件侧需求 1 的 tx type 扩展）。
 * 对应 devenv 注释 add_dns_txt_record "代发 tx" 能力与 SN-测试计划 §7 的
 * controller policy 端到端缺口。
 */
export async function makeSnControllerSeed(targetDir: string): Promise<void> {
  throw new Error(SEED_V2_P1_TODO);
}

/**
 * 可选：用种子密钥再生 local_dns.toml（devtest zone test.buckyos.io 的
 * BOOT/PKX/DEV TXT）。该文件当前手工维护，JWT 长效所以能拖，但换 CA 或换
 * 种子密钥后即漂移；再生成本远低于排查一次 zone boot 失败。
 */
export function makeDevtestLocalDns(targetDir: string): void {
  throw new Error(SEED_V2_P1_TODO);
}

/**
 * seed-v2 目标编排。SN 自身身份/TLS/params 闭环仍由 makeSnConfigs 负责，
 * 此处只补各组件的种子配置产物。
 */
export async function makeSnSeedV2(
  targetDir: string,
  envRoot: string,
): Promise<void> {
  const users = getSeedUserSpecs();
  await makeBnsDvSeedConfig(targetDir, envRoot, users);
  await makeSnAuthSeedConfig(targetDir, envRoot, users);
  alignBnsRuntimeParams(targetDir);
  // P1 / 可选，默认不进编排：
  // await makeSnControllerSeed(targetDir);
  // makeDevtestLocalDns(targetDir);
}

async function main(): Promise<void> {
  let values: {
    rootfs?: string;
    ca?: string;
    sn_ip?: string;
    sn_base_host?: string;
    env_root?: string;
    "seed-v2"?: boolean;
    "dev-local"?: boolean;
    "dev-vm"?: boolean;
    help?: boolean;
  };
  let positionals: string[];
  try {
    const parsed = parseArgs({
      args: Deno.args,
      options: {
        rootfs: { type: "string" },
        ca: { type: "string" },
        sn_ip: { type: "string" },
        sn_base_host: { type: "string" },
        env_root: { type: "string" },
        "seed-v2": { type: "boolean" },
        "dev-local": { type: "boolean" },
        "dev-vm": { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
      allowPositionals: true,
    }) as {
      values: {
        rootfs?: string;
        ca?: string;
        sn_ip?: string;
        sn_base_host?: string;
        env_root?: string;
        "seed-v2"?: boolean;
        "dev-local"?: boolean;
        "dev-vm"?: boolean;
        help?: boolean;
      };
      positionals: string[];
    };
    values = parsed.values;
    positionals = parsed.positionals;
  } catch (e) {
    console.error(`argument error: ${e instanceof Error ? e.message : e}`);
    printUsage();
    Deno.exit(1);
  }

  if (values.help) {
    printUsage(console.log);
    return;
  }

  if (positionals.length > 0) {
    console.error(
      `argument error: expected no positional args, got ${positionals.length}`,
    );
    printUsage();
    Deno.exit(1);
  }

  try {
    assertProvisionRuntime();
  } catch (e) {
    console.error(
      `runtime check failed: ${e instanceof Error ? e.message : e}`,
    );
    console.error("make_sn_config.ts requires Deno >= 2.2");
    Deno.exit(1);
  }

  const targetDir = values.rootfs ?? defaultTargetRoot();
  const snBaseHost = values.sn_base_host ?? DEFAULT_SN_BASE_HOST;
  // --dev-local：本机拉起 profile，SN IP 固定 127.0.0.1、高位端口。
  const devLocal = values["dev-local"] === true;
  const devVm = values["dev-vm"] === true;
  if (devLocal && devVm) {
    console.error(
      "argument error: --dev-local and --dev-vm are mutually exclusive",
    );
    Deno.exit(1);
  }
  const snIp = values.sn_ip ??
    (devLocal ? "127.0.0.1" : Deno.env.get("BUCKYOS_SN_IP") ?? getLocalIp());
  const envRoot = values.env_root ?? ENV_ROOT_DIR;
  const caDir = values.ca ?? ensureDir(path.join(ENV_ROOT_DIR, "ca"));

  await makeSnConfigs(targetDir, snBaseHost, snIp, caDir, DEFAULT_CA_NAME);
  const snDbPath = path.join(targetDir, SN_DB_FILE);
  await makeSnSeedV2(targetDir, envRoot);
  applyBindParams(targetDir, devLocal);
  if (devLocal) {
    enableDevLocalBnsProxy(targetDir);
  } else if (devVm) {
    enableDevVmBnsProxy(targetDir);
  }

  console.log("\n[OK] SN configuration files generation completed!");
  console.log(`  Output directory: ${targetDir}`);
  console.log(`  SN database: ${snDbPath}`);
  console.log(
    `  SN token key dir: ${path.join(targetDir, SN_AUTH_DATA_DIR)}`,
  );
  console.log("Template/operator files that should be present:");
  console.log(`  - ${path.join(targetDir, WEB3_GATEWAY_CONFIG_FILE)}`);
  console.log(`  - ${path.join(targetDir, "website.yaml")}`);
  console.log(`  - ${path.join(targetDir, "local_dns.toml")}`);
  console.log("Other notes:");
  console.log(
    "  - Test environment needs to install the CA certificate into the client trust list",
  );
}

if (import.meta.main) {
  await main();
}
