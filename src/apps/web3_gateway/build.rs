const WINDOWS_MAIN_STACK_SIZE: usize = 4 * 1024 * 1024;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    match target_env.as_str() {
        "msvc" => {
            println!("cargo:rustc-link-arg-bin=web3_gateway=/STACK:{WINDOWS_MAIN_STACK_SIZE}");
        }
        "gnu" => {
            println!("cargo:rustc-link-arg-bin=web3_gateway=-Wl,--stack,{WINDOWS_MAIN_STACK_SIZE}");
        }
        _ => {}
    }
}
