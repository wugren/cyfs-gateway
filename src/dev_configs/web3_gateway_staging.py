#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


SRC_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SRC_ROOT.parent
STAGING_ROOT = Path("/tmp/buckyos-vmtest/cyfs-gateway")
STAGING_DIR = STAGING_ROOT / "web3-gateway"

RUNTIME_FILE_PREFIXES = (
    "sn.sqlite3",
    "bns_indexer.sqlite",
    "anvil-state.json",
    "anvil.pid",
    "start.log",
    "anvil.log",
)

REQUIRED_FILES = (
    "web3_gateway",
    "bns_dv",
    "web3_gateway.yaml",
    "params.json",
    "sn_seed.yaml",
    "bns_dv_seed.yaml",
    "sn_device_config.json",
    "sn_private_key.pem",
    "fullchain.cert",
    "fullchain.pem",
    "start.py",
    "stop.py",
    "init_anvil.py",
    "bns/foundry.toml",
)

REQUIRED_DIRS = (
    "bns/src",
    "ca",
    "sn_token_key",
)

DEPLOYMENT_CONFIG_FILES = (
    "params.json",
    "web3_gateway.yaml",
    "machine.json",
    "sn_seed.yaml",
    "bns_dv_seed.yaml",
)


class StagingError(RuntimeError):
    pass


def checked_staging_path(
    staging_dir: Path = STAGING_DIR,
    staging_root: Path = STAGING_ROOT,
) -> Path:
    if not os.fspath(staging_dir).strip():
        raise StagingError("refusing to use an empty staging path")
    if not staging_dir.is_absolute() or not staging_root.is_absolute():
        raise StagingError("staging path and staging root must be absolute")
    if staging_root.is_symlink() or staging_dir.is_symlink():
        raise StagingError(
            f"refusing to use a symlink staging root or path: "
            f"{staging_root}, {staging_dir}"
        )

    resolved_root = staging_root.resolve()
    resolved_staging = staging_dir.resolve()
    if staging_dir == STAGING_DIR and staging_root == STAGING_ROOT:
        expected_root = (
            Path("/tmp").resolve() / "buckyos-vmtest" / "cyfs-gateway"
        )
        if resolved_root != expected_root:
            raise StagingError(
                f"staging root resolves outside the canonical temporary tree: "
                f"{resolved_root}"
            )

    if resolved_staging == Path("/").resolve():
        raise StagingError(f"refusing dangerous staging path: {resolved_staging}")
    for forbidden_root in (Path("/opt").resolve(), REPO_ROOT.resolve()):
        try:
            resolved_staging.relative_to(forbidden_root)
        except ValueError:
            continue
        raise StagingError(f"refusing dangerous staging path: {resolved_staging}")

    expected = resolved_root / "web3-gateway"
    if resolved_staging != expected:
        raise StagingError(
            f"staging path must be the web3-gateway child of {resolved_root}: "
            f"{resolved_staging}"
        )
    try:
        resolved_staging.relative_to(resolved_root)
    except ValueError as error:
        raise StagingError(
            f"staging path is outside the temporary root: {resolved_staging}"
        ) from error

    return staging_dir


def recreate_staging(
    staging_dir: Path = STAGING_DIR,
    staging_root: Path = STAGING_ROOT,
) -> None:
    checked = checked_staging_path(staging_dir, staging_root)
    if checked.exists():
        if not checked.is_dir():
            raise StagingError(f"staging path exists but is not a directory: {checked}")
        shutil.rmtree(checked)
    checked.mkdir(parents=True, exist_ok=False)
    print(f"[staging] recreated empty directory: {checked}")


def is_runtime_artifact(path: Path) -> bool:
    name = path.name
    return (
        ".sqlite" in name
        or name.endswith((".log", ".pid"))
        or ".log." in name
        or ".pid." in name
        or any(
            name.startswith(prefix) for prefix in RUNTIME_FILE_PREFIXES
        )
    )


def find_runtime_artifacts(staging_dir: Path = STAGING_DIR) -> list[Path]:
    if not staging_dir.is_dir():
        raise StagingError(f"staging directory does not exist: {staging_dir}")
    return sorted(
        path
        for path in staging_dir.rglob("*")
        if is_runtime_artifact(path)
    )


def validate_no_runtime_artifacts(staging_dir: Path = STAGING_DIR) -> None:
    artifacts = find_runtime_artifacts(staging_dir)
    if artifacts:
        details = "\n".join(f"  - {path}" for path in artifacts)
        raise StagingError(
            "runtime files found in web3-gateway staging; refusing deployment:\n"
            f"{details}"
        )
    print(f"[staging] runtime-file validation passed: {staging_dir}")


def validate_no_host_path_leaks(staging_dir: Path = STAGING_DIR) -> None:
    leaks = []
    staging_text = os.fspath(staging_dir)
    for relative in DEPLOYMENT_CONFIG_FILES:
        config_path = staging_dir / relative
        if config_path.is_file() and staging_text in config_path.read_text(
            encoding="utf-8"
        ):
            leaks.append(config_path)
    if leaks:
        details = "\n".join(f"  - {path}" for path in leaks)
        raise StagingError(
            "host staging path leaked into deployable configuration:\n"
            f"{details}"
        )
    print(f"[staging] host-path validation passed: {staging_dir}")


def validate_no_symlinks(staging_dir: Path = STAGING_DIR) -> None:
    symlinks = sorted(path for path in staging_dir.rglob("*") if path.is_symlink())
    if symlinks:
        details = "\n".join(f"  - {path}" for path in symlinks)
        raise StagingError(f"symlinks are not allowed in deployable staging:\n{details}")
    print(f"[staging] symlink validation passed: {staging_dir}")


def validate_complete_staging(staging_dir: Path = STAGING_DIR) -> None:
    validate_no_runtime_artifacts(staging_dir)
    validate_no_host_path_leaks(staging_dir)
    validate_no_symlinks(staging_dir)
    missing = [
        str(staging_dir / relative)
        for relative in REQUIRED_FILES
        if not (staging_dir / relative).is_file()
    ]
    missing.extend(
        str(staging_dir / relative)
        for relative in REQUIRED_DIRS
        if not (staging_dir / relative).is_dir()
    )
    if missing:
        details = "\n".join(f"  - {path}" for path in missing)
        raise StagingError(f"required staging content is missing:\n{details}")
    print(f"[staging] required-content validation passed: {staging_dir}")


def run_build(target: str) -> None:
    checked_staging_path()
    STAGING_DIR.mkdir(parents=True, exist_ok=True)
    staged_binary = STAGING_DIR / "web3_gateway"
    staged_binary.unlink(missing_ok=True)
    env = os.environ.copy()
    env["APPDATA"] = str(STAGING_ROOT)
    command = [sys.executable, str(SRC_ROOT / "build.py"), target]
    print(f"[staging] APPDATA={STAGING_ROOT}")
    print(f"[staging] running: {' '.join(command)}")
    subprocess.run(command, cwd=SRC_ROOT, env=env, check=True)


def discard_failed_staging() -> None:
    try:
        checked = checked_staging_path()
    except StagingError:
        return
    if checked.exists():
        if checked.is_dir():
            shutil.rmtree(checked)
        else:
            checked.unlink()
        print(
            f"[staging] removed incomplete staging after failure: {checked}",
            file=sys.stderr,
        )


def discard_failed_update_binary() -> None:
    try:
        checked_staging_path()
    except StagingError:
        return
    binary = STAGING_DIR / "web3_gateway"
    if binary.exists():
        binary.unlink()
        print(
            f"[staging] removed update binary after validation failure: {binary}",
            file=sys.stderr,
        )


def copy_bns_source() -> None:
    source = SRC_ROOT / "apps" / "bns"
    target = STAGING_DIR / "bns"
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    shutil.copy2(source / "foundry.toml", target / "foundry.toml")
    shutil.copytree(source / "src", target / "src")
    print(f"[staging] copied BNS Foundry source: {target}")


def make_sn_config(sn_ip: str, enable_bns_proxy: bool = False) -> None:
    command = [
        "deno",
        "run",
        "-A",
        "./make_sn_config.ts",
        "--rootfs",
        str(STAGING_DIR),
        "--seed-v2",
        "--sn_ip",
        sn_ip,
    ]
    if enable_bns_proxy:
        command.append("--dev-vm")
    print(f"[staging] running: {' '.join(command)}")
    subprocess.run(command, cwd=SRC_ROOT, check=True)


def build_all(target: str, sn_ip: str, enable_bns_proxy: bool = False) -> None:
    recreate_staging()
    run_build(target)
    copy_bns_source()
    make_sn_config(sn_ip, enable_bns_proxy)
    validate_complete_staging()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build and validate the host-only web3-gateway devtest staging directory."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser(
        "build", help="Refresh build outputs in staging for devtest update."
    )
    build_parser.add_argument("--target", default="aarch64")

    build_all_parser = subparsers.add_parser(
        "build-all", help="Recreate the complete staging directory from zero."
    )
    build_all_parser.add_argument("--target", default="aarch64")
    build_all_parser.add_argument("--sn-ip", required=True)
    build_all_parser.add_argument("--enable-bns-proxy", action="store_true")

    subparsers.add_parser(
        "validate", help="Reject runtime data anywhere below the staging directory."
    )
    subparsers.add_parser("path", help="Print the canonical staging directory.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "build":
            run_build(args.target)
            validate_no_runtime_artifacts()
        elif args.command == "build-all":
            build_all(args.target, args.sn_ip, args.enable_bns_proxy)
        elif args.command == "validate":
            checked_staging_path()
            validate_complete_staging()
        elif args.command == "path":
            print(STAGING_DIR)
    except subprocess.CalledProcessError as error:
        if args.command == "build-all":
            discard_failed_staging()
        elif args.command == "build":
            discard_failed_update_binary()
        print(
            f"[staging] command failed with exit code {error.returncode}: "
            f"{' '.join(map(str, error.cmd))}",
            file=sys.stderr,
        )
        return error.returncode or 1
    except (OSError, StagingError) as error:
        if args.command == "build-all":
            discard_failed_staging()
        elif args.command == "build":
            discard_failed_update_binary()
        print(f"[staging] error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
