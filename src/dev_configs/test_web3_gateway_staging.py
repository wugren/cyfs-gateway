import json
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import web3_gateway_staging as staging


class Web3GatewayStagingTests(unittest.TestCase):
    def test_devtest_configs_use_the_canonical_staging_path(self) -> None:
        for relative in (
            "dev_configs/apps/web3-gateway.json",
            "dev_configs/sn_test/apps/web3-gateway.json",
        ):
            config = json.loads((staging.SRC_ROOT / relative).read_text(encoding="utf-8"))
            directories = config["directories"]
            self.assertEqual(directories["source"], str(staging.STAGING_DIR))
            self.assertEqual(
                directories["source_bin"],
                str(staging.STAGING_DIR / "web3_gateway"),
            )
            for command_name in ("build", "build_all"):
                command = config["commands"][command_name][0]
                self.assertIn(
                    "{{system.base_dir}}/../../cyfs-gateway/src",
                    command,
                )
                self.assertIn("./dev_configs/web3_gateway_staging.py", command)

    def test_vm_app_commands_enable_and_configure_bns_proxy(self) -> None:
        for relative in (
            "dev_configs/apps/web3-gateway.json",
            "dev_configs/sn_test/apps/web3-gateway.json",
        ):
            config = json.loads((staging.SRC_ROOT / relative).read_text(encoding="utf-8"))
            commands = config["commands"]
            self.assertIn("--enable-bns-proxy", commands["build_all"][0])
            self.assertIn("--configure-sn-bns-proxy", commands["init_anvil"][0])
            self.assertIn("--configure-sn-bns-proxy", commands["init_anvil_fresh"][0])
            if "uninstall" in commands:
                self.assertIn("install -d -o ubuntu -g ubuntu", commands["uninstall"][-1])

    def test_make_sn_config_passes_vm_profile_when_enabled(self) -> None:
        with mock.patch.object(staging.subprocess, "run") as run:
            staging.make_sn_config("192.0.2.10", enable_bns_proxy=True)
        command = run.call_args.args[0]
        self.assertIn("--dev-vm", command)
        self.assertNotIn("--dev-local", command)

    def test_init_anvil_writes_sn_bns_runtime_params(self) -> None:
        module_path = staging.SRC_ROOT / "web3-gateway" / "init_anvil.py"
        spec = importlib.util.spec_from_file_location("web3_gateway_init_anvil", module_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            params_path = root / "params.json"
            params_path.write_text('{"params":{"sn_host":"devtests.org"}}\n')
            gateway_path = root / "web3_gateway.yaml"
            gateway_path.write_text(
                "servers:\n"
                "  web3_sn:\n"
                '    bns_rpc_url: "{{bns_rpc_url}}"\n'
            )
            with (
                mock.patch.object(module, "BNS_RPC_ENDPOINT", "http://127.0.0.1:8545"),
                mock.patch.object(module, "BNS_CHAIN_ID", "31337"),
                mock.patch.object(module, "BNS_SERVER_URL", "http://127.0.0.1:18080"),
                mock.patch.object(module, "BNS_SERVER_RPC_PATH", "/kapi/bns"),
            ):
                module.configure_sn_bns_proxy(root, "0x1234")

            params = json.loads(params_path.read_text())["params"]
            self.assertEqual(params["sn_host"], "devtests.org")
            self.assertEqual(params["bns_rpc_endpoint"], "http://127.0.0.1:8545")
            self.assertEqual(params["bns_chain_id"], "31337")
            self.assertEqual(params["bns_contract_address"], "0x1234")
            self.assertEqual(params["bns_rpc_url"], "http://127.0.0.1:18080")
            gateway = gateway_path.read_text()
            self.assertIn('bns_rpc_url: "{{bns_rpc_url}}"', gateway)

    def test_recreate_staging_only_removes_expected_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "web3-gateway"
            target.mkdir()
            (target / "old-file").write_text("old", encoding="utf-8")

            staging.recreate_staging(target, root)

            self.assertTrue(target.is_dir())
            self.assertEqual(list(target.iterdir()), [])
            with self.assertRaises(staging.StagingError):
                staging.recreate_staging(root, root)
            with self.assertRaises(staging.StagingError):
                staging.recreate_staging(root.parent / "web3-gateway", root)

    def test_runtime_validation_is_recursive_and_reports_all_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            nested = target / "nested"
            nested.mkdir()
            expected = {
                target / "sn.sqlite3-wal",
                nested / "bns_indexer.sqlite.backup",
                nested / "anvil-state.json.old",
                nested / "worker.pid",
                nested / "start.log.1",
                nested / "other.log",
                nested / "cache.sqlite",
            }
            for path in expected:
                path.write_text("runtime", encoding="utf-8")
            (nested / "params.json").write_text("{}", encoding="utf-8")

            self.assertEqual(set(staging.find_runtime_artifacts(target)), expected)
            with self.assertRaisesRegex(staging.StagingError, "worker.pid"):
                staging.validate_no_runtime_artifacts(target)

    def test_symlink_staging_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            real_root = temporary_path / "real"
            real_root.mkdir()
            linked_root = temporary_path / "linked"
            linked_root.symlink_to(real_root, target_is_directory=True)

            with self.assertRaisesRegex(staging.StagingError, "symlink"):
                staging.checked_staging_path(
                    linked_root / "web3-gateway",
                    linked_root,
                )

    def test_deployable_staging_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            real_file = target / "real"
            real_file.write_text("content", encoding="utf-8")
            (target / "linked").symlink_to(real_file)

            with self.assertRaisesRegex(staging.StagingError, "linked"):
                staging.validate_no_symlinks(target)

    def test_clean_tree_passes_runtime_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            (target / "params.json").write_text("{}", encoding="utf-8")

            staging.validate_no_runtime_artifacts(target)

    def test_deployable_config_cannot_embed_host_staging_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            (target / "params.json").write_text(
                '{"params":{"sn_db_path":"' + str(target / "sn.sqlite3") + '"}}',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(staging.StagingError, "params.json"):
                staging.validate_no_host_path_leaks(target)

            (target / "params.json").write_text(
                '{"params":{"sn_db_path":"sn.sqlite3"}}',
                encoding="utf-8",
            )
            staging.validate_no_host_path_leaks(target)


if __name__ == "__main__":
    unittest.main()
