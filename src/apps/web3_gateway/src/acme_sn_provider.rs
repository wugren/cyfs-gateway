use anyhow::anyhow;
use cyfs_acme::{
    AcmeCertManager, AcmeCertManagerRef, DnsProvider, DnsProviderFactory, DnsProviderRef,
};
use cyfs_gateway_lib::{RtcpStackConfig, StackProtocol};
use cyfs_sn::OODInfo;
use kRPC::RPCSessionToken;
use name_lib::{
    encode_ed25519_pkcs8_sk_to_pk, get_x_from_jwk, load_raw_private_key, DeviceConfig, DID,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

pub struct AcmeSnProviderFactory {
    data_path: PathBuf,
}

fn normalize_sn_rpc_url(sn: &str) -> String {
    let sn = sn.trim().trim_end_matches('/');
    for suffix in [
        "/kapi/sn/deviceinfo",
        "/kapi/sn/auth",
        "/kapi/sn/bns",
        "/kapi/sn",
    ] {
        if let Some(base) = sn.strip_suffix(suffix) {
            return base.to_string();
        }
    }
    sn.to_string()
}

impl AcmeSnProviderFactory {
    pub fn new(data_path: PathBuf) -> Arc<AcmeSnProviderFactory> {
        Arc::new(AcmeSnProviderFactory { data_path })
    }
}

#[derive(Deserialize)]
pub struct AcmdSnProviderConfig {
    pub sn: String,
    pub key_path: String,
    pub device_config_path: Option<String>,
    pub access_token: Option<String>,
}

#[async_trait::async_trait]
impl DnsProviderFactory for AcmeSnProviderFactory {
    async fn create(
        &self,
        acme_mgr: Weak<AcmeCertManager>,
        params: serde_json::Value,
    ) -> anyhow::Result<DnsProviderRef> {
        let config: AcmdSnProviderConfig = serde_json::from_value(params.clone())
            .map_err(|_| anyhow!("invalid acme sn provider config.{}", params.to_string()))?;

        let private_key = load_raw_private_key(Path::new(config.key_path.as_str()))
            .map_err(|_| anyhow!("load private key {} failed", config.key_path))?;
        let public_key = encode_ed25519_pkcs8_sk_to_pk(&private_key);

        let device_config = if config.device_config_path.is_some() {
            let content = tokio::fs::read_to_string(config.device_config_path.as_ref().unwrap())
                .await
                .map_err(|e| {
                    anyhow!(
                        "load device config {} failed.{}",
                        config.device_config_path.as_ref().unwrap(),
                        e
                    )
                })?;
            let device_config =
                serde_json::from_str::<DeviceConfig>(content.as_str()).map_err(|e| {
                    anyhow!(
                        "parse device config {} failed.{}",
                        config.device_config_path.as_ref().unwrap(),
                        e
                    )
                })?;

            let default_key = device_config.get_default_key().ok_or(anyhow!(
                "device config {} no default key found",
                config.device_config_path.as_ref().unwrap()
            ))?;
            let x_of_auth_key = get_x_from_jwk(&default_key).map_err(|_e| {
                anyhow!(
                    "device config {} has no auth key",
                    config.device_config_path.as_ref().unwrap()
                )
            })?;
            if x_of_auth_key != public_key {
                return Err(anyhow!(
                    "device config {} auth key not match",
                    config.device_config_path.as_ref().unwrap()
                ));
            }
            device_config
        } else {
            DeviceConfig::new("cyfs_gateway", public_key)
        };
        let private_key = jsonwebtoken::EncodingKey::from_ed_der(private_key.as_slice());

        Ok(AcmeSnProvider::new(
            self.data_path.clone(),
            acme_mgr,
            normalize_sn_rpc_url(config.sn.as_str()),
            private_key,
            device_config.id,
            device_config.name,
            config.access_token,
        ))
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
struct CertStateItem {
    did: String,
    domain: String,
    state: bool,
}

struct AcmeSnProvider {
    data_path: PathBuf,
    weak_acme_mgr: Weak<AcmeCertManager>,
    sn: String,
    private_key: jsonwebtoken::EncodingKey,
    did: DID,
    user_name: String,
    access_token: Option<String>,
    cert_state_cache: Mutex<Vec<CertStateItem>>,
    handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for AcmeSnProvider {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.lock().unwrap().take() {
            handle.abort();
        }
    }
}

impl AcmeSnProvider {
    pub fn new(
        data_path: PathBuf,
        weak_acme_mgr: Weak<AcmeCertManager>,
        sn: String,
        private_key: jsonwebtoken::EncodingKey,
        did: DID,
        user_name: String,
        access_token: Option<String>,
    ) -> Arc<AcmeSnProvider> {
        let this = Arc::new(AcmeSnProvider {
            data_path,
            weak_acme_mgr,
            sn,
            private_key,
            did,
            user_name,
            access_token,
            cert_state_cache: Mutex::new(Default::default()),
            handle: Mutex::new(None),
        });

        let obj = this.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let _ = obj.load_cert_state().await;
            loop {
                if let Err(e) = obj.update_cert_state().await {
                    log::error!("update cert state failed.{}", e);
                }
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });

        *this.handle.lock().unwrap() = Some(handle);
        this
    }

    async fn add_cert(&self, domain: impl Into<String>) -> anyhow::Result<()> {
        let state_content = {
            let mut cache = self.cert_state_cache.lock().unwrap();
            let item = CertStateItem {
                did: self.did.to_string(),
                domain: domain.into(),
                state: false,
            };
            if cache.contains(&item) {
                return Ok(());
            }
            cache.push(item);
            serde_json::to_string(cache.deref())
                .map_err(|_| anyhow!("save cert state cache failed"))?
        };
        tokio::fs::write(self.data_path.join("self_cert_state.json"), state_content)
            .await
            .map_err(|_| anyhow!("save cert state cache failed"))?;
        Ok(())
    }

    async fn load_cert_state(&self) -> anyhow::Result<()> {
        let content = tokio::fs::read_to_string(self.data_path.join("self_cert_state.json"))
            .await
            .map_err(|_| anyhow!("load cert state cache failed"))?;
        let cache: Vec<CertStateItem> = serde_json::from_str(content.as_str())
            .map_err(|_| anyhow!("parse cert state cache failed"))?;
        *self.cert_state_cache.lock().unwrap() = cache;
        Ok(())
    }

    async fn update_cert_state(&self) -> anyhow::Result<()> {
        let cache = {
            let cache = self.cert_state_cache.lock().unwrap();
            cache.clone()
        };

        for item in cache.iter() {
            if item.state {
                continue;
            }
            if item.did != self.did.to_string() {
                continue;
            }

            let mut has_cert = false;
            if let Some(acme_mgr) = self.weak_acme_mgr.upgrade() {
                if let Some(cert) = acme_mgr.get_cert_by_host(item.domain.as_str()) {
                    if let Some(_) = cert.get_cert() {
                        has_cert = true;
                    }
                }
            }
            if !has_cert {
                continue;
            }
            self.report_user_cert_ok().await?;
            self.set_cert_ok().await?;
        }
        Ok(())
    }
    fn get_krpc_for_route(&self, route: &str) -> anyhow::Result<kRPC::kRPC> {
        let token = if let Some(access_token) = self.access_token.clone() {
            access_token
        } else {
            let (token, _) = RPCSessionToken::generate_jwt_token(
                self.user_name.as_str(),
                "cyfs_gateway",
                None,
                &self.private_key,
            )
            .map_err(|_| anyhow!("generate jwt token failed"))?;
            token
        };
        let url = format!(
            "{}/{}",
            self.sn.trim_end_matches('/'),
            route.trim_start_matches('/')
        );
        let krpc = kRPC::kRPC::new(url.as_str(), Some(token));
        Ok(krpc)
    }

    async fn report_user_cert_ok(&self) -> anyhow::Result<()> {
        let deviceinfo_krpc = self.get_krpc_for_route("/kapi/sn/deviceinfo")?;
        let result = deviceinfo_krpc
            .call(
                "deviceinfo.resolve_ood_by_did",
                json!({
                    "source_device_id": self.did.to_string()
                }),
            )
            .await
            .map_err(|e| anyhow!("resolve_ood_by_did failed.{:?}", e))?;
        let _ood_info = serde_json::from_value::<OODInfo>(result)
            .map_err(|_| anyhow!("parse resolve_ood_by_did result failed"))?;

        let auth_krpc = self.get_krpc_for_route("/kapi/sn/auth")?;
        auth_krpc
            .call(
                "user.set_self_cert",
                json!({
                    "self_cert": true,
                    "device_did": self.did.to_string()
                }),
            )
            .await
            .map_err(|e| anyhow!("set_user_self_cert failed.{:?}", e))?;
        Ok(())
    }

    async fn set_cert_ok(&self) -> anyhow::Result<()> {
        let state_content = {
            let mut cache = self.cert_state_cache.lock().unwrap();
            for item in cache.iter_mut() {
                if item.did != self.did.to_string() {
                    continue;
                }
                item.state = true;
            }
            serde_json::to_string(cache.deref())
                .map_err(|_| anyhow!("save cert state cache failed"))?
        };
        tokio::fs::write(self.data_path.join("self_cert_state.json"), state_content)
            .await
            .map_err(|_| anyhow!("save cert state cache failed"))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl DnsProvider for AcmeSnProvider {
    async fn call(&self, op: String, domain: String, key_hash: String) -> anyhow::Result<()> {
        let krpc = self.get_krpc_for_route("/kapi/sn/auth")?;
        if op == "add_challenge" {
            let original = domain.replace("_acme-challenge.", "*.");
            self.add_cert(original).await?;
            krpc.call(
                "user.add_dns_record",
                json!({
                    "device_did": self.did.to_string(),
                    "domain": domain,
                    "record_type": "TXT",
                    "record": key_hash,
                    "ttl": 600
                }),
            )
            .await
            .map_err(|e| anyhow!("add_dns_record failed.{:?}", e))?;
        } else if op == "del_challenge" {
            let mut has_cert = false;
            if let Some(acme_mgr) = self.weak_acme_mgr.upgrade() {
                let original = domain.replace("_acme-challenge.", "*.");
                if let Some(cert) = acme_mgr.get_cert_by_host(original.as_str()) {
                    if let Some(_) = cert.get_cert() {
                        has_cert = true;
                    }
                }
                if !has_cert {
                    let original = domain.replace("_acme-challenge.", "");
                    if let Some(cert) = acme_mgr.get_cert_by_host(original.as_str()) {
                        if let Some(_) = cert.get_cert() {
                            has_cert = true;
                        }
                    }
                }
            }
            krpc.call(
                "user.remove_dns_record",
                json!({
                    "device_did": self.did.to_string(),
                    "domain": domain,
                    "record_type": "TXT",
                    "has_cert": has_cert,
                }),
            )
            .await
            .map_err(|e| anyhow!("add_dns_record failed.{:?}", e))?;

            let deviceinfo_krpc = self.get_krpc_for_route("/kapi/sn/deviceinfo")?;
            let result = deviceinfo_krpc
                .call(
                    "deviceinfo.resolve_ood_by_did",
                    json!({
                        "source_device_id": self.did.to_string()
                    }),
                )
                .await
                .map_err(|e| anyhow!("resolve_ood_by_did failed.{:?}", e))?;
            let ood_info = serde_json::from_value::<OODInfo>(result)
                .map_err(|_| anyhow!("parse resolve_ood_by_did result failed"))?;

            if ood_info.self_cert {
                self.set_cert_ok().await?;
            }
        }
        Ok(())
    }
}
