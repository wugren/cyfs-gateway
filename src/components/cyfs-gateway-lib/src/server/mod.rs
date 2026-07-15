mod acme_http_challenge_server;
mod cyfs_dir_server;
mod dir_server;
mod dns_server;
mod http_compression;
mod http_server;

mod qa_server;
mod server;
mod socks5_server;
mod welcome_server;

use std::path::Path;
use std::path::PathBuf;

use log::*;

pub use acme_http_challenge_server::*;
pub use cyfs_dir_server::*;
pub use dir_server::*;
pub use dns_server::*;
pub use http_server::*;

pub use qa_server::*;
pub use server::*;
pub use socks5_server::*;
pub use welcome_server::*;

pub fn get_gateway_main_config_dir() -> PathBuf {
    //get env CYFS_GATEWAY_CONFIG_PATH
    let config_path_str = std::env::var("CYFS_GATEWAY_CONFIG_PATH");
    if config_path_str.is_ok() {
        return PathBuf::from(config_path_str.unwrap());
    } else {
        return buckyos_kit::get_buckyos_system_etc_dir();
    }
}

pub fn set_gateway_main_config_dir(path: &PathBuf) {
    // SAFETY: This function is typically called during application initialization
    // before any threads are spawned that might read this environment variable.
    unsafe {
        let mut real_path = path.to_string_lossy().to_string();
        if path.is_file() {
            real_path = path.parent().unwrap().to_string_lossy().to_string();
        }
        std::env::set_var("CYFS_GATEWAY_CONFIG_PATH", real_path);
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();

    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                result.pop();
            }
            _ => result.push(comp),
        }
    }

    result
}

//will move to buckyos_kit
pub fn normalize_config_file_path(path: PathBuf, base_dir: &Path) -> PathBuf {
    if path.is_relative() {
        let result_path = base_dir.join(path.clone());
        let ret = normalize_path(result_path.as_path());
        return ret;
    }
    path
}

fn normalize_config_path_value(value_str: &str, base_dir: &Path) -> String {
    let (path_str, fragment) = if let Some((path_str, fragment)) = value_str.split_once('#') {
        (path_str, Some(fragment))
    } else {
        (value_str, None)
    };

    let value_path = normalize_config_file_path(PathBuf::from(path_str), base_dir);
    let value_path = value_path.to_string_lossy().to_string();
    if let Some(fragment) = fragment {
        format!("{}#{}", value_path, fragment)
    } else {
        value_path
    }
}

fn is_config_path_key(key: &str) -> bool {
    key == "path"
        || key.ends_with("_path")
        // Keep the nginx-compatible directive name while treating it as
        // a file path during the common configuration normalization pass.
        || key == "proxy_ssl_trusted_certificate"
}

//will move to buckyos_kit
pub fn normalize_all_path_value_config(config: &mut serde_json::Value, base_dir: &Path) {
    if config.is_object() {
        for (key, value) in config.as_object_mut().unwrap() {
            if value.is_string() {
                if is_config_path_key(key) {
                    let value_str = value.as_str().unwrap();
                    let value_path = normalize_config_path_value(value_str, base_dir);
                    debug!(
                        "normalize_all_path_value_config: key: {}, value: {} -> {}",
                        key, value_str, value_path
                    );
                    *value = serde_json::Value::String(value_path);
                }
            } else {
                normalize_all_path_value_config(value, base_dir);
            }
        }
    }

    if config.is_array() {
        for value in config.as_array_mut().unwrap() {
            normalize_all_path_value_config(value, base_dir);
        }
    }
}

// normalize_all_path_value_config test case
#[cfg(test)]
mod test {
    use crate::server::normalize_path;
    use std::path::Path;

    #[test]
    fn test_normalize_path() {
        // Test simple path normalization (removing current directory references)
        let path = Path::new("./simple/path");
        let normalized = normalize_path(path);
        let normalized_str = normalized.to_string_lossy().replace("\\", "/");
        assert_eq!(normalized_str, "simple/path");

        // Test path with parent directory references
        let path = Path::new("a/b/../c/d/../../e");
        let normalized = normalize_path(path);
        let normalized_str = normalized.to_string_lossy().replace("\\", "/");
        assert_eq!(normalized_str, "a/e");

        // Test path with current directory references
        let path = Path::new("a/./b/./c");
        let normalized = normalize_path(path);
        let normalized_str = normalized.to_string_lossy().replace("\\", "/");
        assert_eq!(normalized_str, "a/b/c");

        // Test path with mixed components
        let path = Path::new("a/./b/../c/./d/../../e");
        let normalized = normalize_path(path);
        let normalized_str = normalized.to_string_lossy().replace("\\", "/");
        assert_eq!(normalized_str, "a/e");

        // Test Windows-style path
        let path = Path::new(".\\windows\\style\\path");
        let normalized = normalize_path(path);
        // Should remove the current directory reference
        let normalized_str = normalized.to_string_lossy().to_string();
        if cfg!(windows) {
            assert_eq!(normalized_str, "windows\\style\\path");
        } else {
            assert_eq!(normalized_str, ".\\windows\\style\\path");
        }

        // Test Windows-style path
        let path = Path::new("C:\\windows\\.\\style\\path");
        let normalized = normalize_path(path);
        // Should remove the current directory reference
        let normalized_str = normalized.to_string_lossy().to_string();
        if cfg!(windows) {
            assert_eq!(normalized_str, "C:\\windows\\style\\path");
        } else {
            assert_eq!(normalized_str, "C:\\windows\\.\\style\\path");
        }

        // Test Windows-style path
        let path = Path::new("C:\\windows\\..\\style\\path");
        let normalized = normalize_path(path);
        // Should remove the current directory reference
        let normalized_str = normalized.to_string_lossy().to_string();
        if cfg!(windows) {
            assert_eq!(normalized_str, "C:\\style\\path");
        } else {
            assert_eq!(normalized_str, "C:\\windows\\..\\style\\path");
        }

        // Test path with parent directory at the beginning
        let path = Path::new("../a/b/c");
        let normalized = normalize_path(path);
        // The result should still contain a, b, c but may have a leading ..
        let normalized_str = normalized.to_string_lossy().to_string();
        assert!(
            normalized_str.contains("a")
                && normalized_str.contains("b")
                && normalized_str.contains("c")
        );

        // Test complex path with multiple parent directories
        let path = Path::new("a/b/c/d/../../../e/f/g/../../h");
        let normalized = normalize_path(path);
        let normalized_str = normalized.to_string_lossy().replace("\\", "/");
        assert_eq!(normalized_str, "a/e/h");

        // Test path that goes completely up to root
        let path = Path::new("a/b/../../c");
        let normalized = normalize_path(path);
        let normalized_str = normalized.to_string_lossy().replace("\\", "/");
        assert_eq!(normalized_str, "c");

        // Test single component paths
        let path = Path::new(".");
        let normalized = normalize_path(path);
        // On Windows, this results in an empty path, on Unix it might stay as current dir
        let normalized_str = normalized.to_string_lossy();
        assert!(normalized_str.is_empty() || normalized_str == ".");

        // Test empty path
        let path = Path::new("");
        let normalized = normalize_path(path);
        let normalized_str = normalized.to_string_lossy();
        assert_eq!(normalized_str, "");
    }

    #[test]
    fn test_normalize_all_path_value_config() {
        use super::normalize_config_path_value;
        use crate::normalize_all_path_value_config;
        use buckyos_kit::init_logging;
        use std::path::PathBuf;
        unsafe {
            std::env::set_var("BUCKY_LOG", "debug");
        }
        init_logging("test_normalize_all_path_value_config", false);
        let config_str = r#"
        {
            "servers":[
                {
                    "type":"cyfs-warp",
                    "bind":"0.0.0.0",
                    "http_port":80,
                    "https_port":443,
                    "tls_only":1,
                    "tls": {
                        "cert_path": "cyfs_gateway.yaml"
                    },
                    "proxy_ssl_trusted_certificate": "certs/upstream-ca.pem"
                }
            ],
            "path": "cyfs_gateway.yaml"
        }
        "#;
        let mut config: serde_json::Value = serde_json::from_str(config_str).unwrap();
        let base_dir = PathBuf::from("/opt/buckyos/etc");
        normalize_all_path_value_config(&mut config, &base_dir);
        assert_eq!(
            config
                .get("path")
                .unwrap()
                .as_str()
                .unwrap()
                .replace("\\", "/"),
            "/opt/buckyos/etc/cyfs_gateway.yaml"
        );
        assert_eq!(
            normalize_config_path_value("./all_info.json#app_info", &base_dir).replace("\\", "/"),
            "/opt/buckyos/etc/all_info.json#app_info"
        );
        assert_eq!(
            config
                .get("servers")
                .unwrap()
                .as_array()
                .unwrap()
                .get(0)
                .unwrap()
                .as_object()
                .unwrap()
                .get("tls")
                .unwrap()
                .as_object()
                .unwrap()
                .get("cert_path")
                .unwrap()
                .as_str()
                .unwrap()
                .replace("\\", "/"),
            "/opt/buckyos/etc/cyfs_gateway.yaml"
        );
        assert_eq!(
            config
                .get("servers")
                .unwrap()
                .as_array()
                .unwrap()
                .first()
                .unwrap()
                .get("proxy_ssl_trusted_certificate")
                .unwrap()
                .as_str()
                .unwrap()
                .replace("\\", "/"),
            "/opt/buckyos/etc/certs/upstream-ca.pem"
        );
    }
}
