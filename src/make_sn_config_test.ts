import { enableDevVmBnsProxy } from "./make_sn_config.ts";

Deno.test("dev-vm replaces the production BNS key source with controller list", async () => {
  const root = await Deno.makeTempDir();
  const configPath = `${root}/web3_gateway.yaml`;
  const baseConfig = `servers:
  web3_sn:
    id: web3_sn
    bns_rpc_url: "{{bns_rpc_url}}"
    bns_evm:
      controller_private_key_env: BNS_SN_CONTROLLER_PRIVATE_KEY
    bns_proxy:
      require_user_asset_owner: true
`;

  try {
    await Deno.writeTextFile(configPath, baseConfig);
    enableDevVmBnsProxy(root);
    const configured = await Deno.readTextFile(configPath);
    if (configured.includes("BNS_SN_CONTROLLER_PRIVATE_KEY")) {
      throw new Error(`production key source was not removed:\n${configured}`);
    }
    for (
      const expected of [
        "allowed_operations:",
        "controllers:",
        "id: controller-a",
        "id: controller-b",
      ]
    ) {
      if (!configured.includes(expected)) {
        throw new Error(`missing ${expected}:\n${configured}`);
      }
    }

    enableDevVmBnsProxy(root);
    const replayed = await Deno.readTextFile(configPath);
    if (replayed !== configured) {
      throw new Error("dev-vm BNS proxy injection is not idempotent");
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("dev-vm BNS proxy injection also covers the split config files", async () => {
  const root = await Deno.makeTempDir();
  const baseConfig = `servers:
  web3_sn:
    id: web3_sn
    bns_rpc_url: "{{bns_rpc_url}}"
    bns_evm:
      controller_private_key_env: BNS_SN_CONTROLLER_PRIVATE_KEY
    bns_proxy:
      require_user_asset_owner: true
`;
  // web3_sn_api.yaml 缺失：拆分文件是可选的，注入必须跳过而不是报错。
  const files = ["web3_gateway.yaml", "web3_dns.yaml", "web3_relay.yaml"];

  try {
    for (const file of files) {
      await Deno.writeTextFile(`${root}/${file}`, baseConfig);
    }
    enableDevVmBnsProxy(root);
    for (const file of files) {
      const configured = await Deno.readTextFile(`${root}/${file}`);
      if (configured.includes("BNS_SN_CONTROLLER_PRIVATE_KEY")) {
        throw new Error(
          `production key source was not removed from ${file}:\n${configured}`,
        );
      }
      if (!configured.includes("controllers:")) {
        throw new Error(`missing controllers in ${file}:\n${configured}`);
      }
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});
