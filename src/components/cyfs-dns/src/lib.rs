#![allow(unused)]

mod cmd_resolve;
mod dns_server;
mod local_dns;

pub use cmd_resolve::*;
use cyfs_gateway_lib::{into_server_err, server_err, ServerErrorCode, ServerResult};
use cyfs_process_chain::SetCollection;
use cyfs_process_chain::{
    CollectionValue, MapCollectionRef, MemoryMapCollection, MemorySetCollection,
};
pub use dns_server::*;
use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR, TXT};
use hickory_proto::rr::{Name, RData};
pub use local_dns::*;
use log::{debug, warn};
use name_client::NameInfo;
use name_lib::EncodedDocument;
use std::net::IpAddr;
use std::sync::Arc;

pub(crate) async fn nameinfo_to_map_collection(
    record_type: &str,
    name_info: &NameInfo,
) -> ServerResult<MapCollectionRef> {
    let map = MemoryMapCollection::new_ref();
    map.insert(
        "record_type",
        CollectionValue::String(record_type.to_string()),
    )
    .await
    .map_err(|e| {
        server_err!(
            ServerErrorCode::ProcessChainError,
            "add record_type {} err {}",
            record_type,
            e
        )
    })?;
    if name_info.ttl.is_some() {
        map.insert(
            "ttl",
            CollectionValue::String(name_info.ttl.unwrap().to_string()),
        )
        .await
        .map_err(|e| {
            server_err!(
                ServerErrorCode::ProcessChainError,
                "add ttl {} err {}",
                name_info.ttl.unwrap(),
                e
            )
        })?;
    }
    map.insert("name", CollectionValue::String(name_info.name.clone()))
        .await
        .map_err(|e| {
            server_err!(
                ServerErrorCode::ProcessChainError,
                "add name {} err {}",
                name_info.name,
                e
            )
        })?;
    match record_type {
        "A" => {
            let ip_set = MemorySetCollection::new();
            // Convert all IPv4 addresses to A records
            for addr in name_info.address.iter() {
                match addr {
                    IpAddr::V4(addr) => {
                        ip_set
                            .insert(addr.to_string().as_str())
                            .await
                            .map_err(|e| {
                                server_err!(
                                    ServerErrorCode::ProcessChainError,
                                    "add address {} err {}",
                                    addr,
                                    e
                                )
                            })?;
                    }
                    _ => {
                        debug!("Skipping non-IPv4 address");
                        continue;
                    }
                }
            }

            map.insert("address", CollectionValue::Set(Arc::new(Box::new(ip_set))))
                .await
                .map_err(|e| {
                    server_err!(ServerErrorCode::ProcessChainError, "add address err {}", e)
                })?;
            Ok(map)
        }
        "AAAA" => {
            let ip_set = MemorySetCollection::new();
            // Convert all IPv6 addresses to AAAA records
            for addr in name_info.address.iter() {
                match addr {
                    IpAddr::V6(addr) => {
                        ip_set
                            .insert(addr.to_string().as_str())
                            .await
                            .map_err(|e| {
                                server_err!(
                                    ServerErrorCode::ProcessChainError,
                                    "add address {} err {}",
                                    addr,
                                    e
                                )
                            })?;
                    }
                    _ => {
                        debug!("Skipping non-IPv6 address");
                        continue;
                    }
                }
            }

            map.insert("address", CollectionValue::Set(Arc::new(Box::new(ip_set))))
                .await
                .map_err(|e| {
                    server_err!(ServerErrorCode::ProcessChainError, "add address err {}", e)
                })?;
            Ok(map)
        }
        "CNAME" => {
            if name_info.cname.is_none() {
                return Err(server_err!(ServerErrorCode::InvalidParam, "CNAME is none"));
            }
            let cname = name_info.cname.clone().unwrap();
            map.insert("cname", CollectionValue::String(cname))
                .await
                .map_err(|e| {
                    server_err!(
                        ServerErrorCode::ProcessChainError,
                        "add cname {:?} err {}",
                        name_info.cname,
                        e
                    )
                })?;
            return Ok(map);
        }
        "HTTPS" => {
            return Ok(map);
        }
        "TXT" => {
            if name_info.txt.is_empty() {
                return Err(server_err!(ServerErrorCode::InvalidParam, "TXT is empty"));
            }
            let txt_set = MemorySetCollection::new();
            for txt in name_info.txt.iter() {
                txt_set.insert(txt).await.map_err(|e| {
                    server_err!(
                        ServerErrorCode::ProcessChainError,
                        "add txt {} err {}",
                        txt,
                        e
                    )
                })?;
            }
            map.insert("txt", CollectionValue::Set(Arc::new(Box::new(txt_set))))
                .await
                .map_err(|e| {
                    server_err!(ServerErrorCode::ProcessChainError, "add txt err {}", e)
                })?;
            return Ok(map);
        }
        "CAA" => {
            let caa_set = MemorySetCollection::new();
            for caa in name_info.caa.iter() {
                caa_set.insert(caa).await.map_err(|e| {
                    server_err!(
                        ServerErrorCode::ProcessChainError,
                        "add caa {} err {}",
                        caa,
                        e
                    )
                })?;
            }
            map.insert("caa", CollectionValue::Set(Arc::new(Box::new(caa_set))))
                .await
                .map_err(|e| {
                    server_err!(ServerErrorCode::ProcessChainError, "add caa err {}", e)
                })?;
            return Ok(map);
        }
        "PTR" => {
            if name_info.ptr_records.is_empty() {
                return Err(server_err!(ServerErrorCode::InvalidParam, "PTR is empty"));
            }
            let ptr_set = MemorySetCollection::new();
            for ptr in name_info.ptr_records.iter() {
                ptr_set.insert(ptr).await.map_err(|e| {
                    server_err!(
                        ServerErrorCode::ProcessChainError,
                        "add ptr {} err {}",
                        ptr,
                        e
                    )
                })?;
            }
            map.insert(
                "ptr_records",
                CollectionValue::Set(Arc::new(Box::new(ptr_set))),
            )
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "add ptr err {}", e))?;
            return Ok(map);
        }
        _ => {
            return Err(server_err!(
                ServerErrorCode::InvalidParam,
                "Unknown record type:{}",
                record_type
            ));
        }
    }
}

pub(crate) async fn map_collection_to_nameinfo(map: &MapCollectionRef) -> ServerResult<NameInfo> {
    let record_type = map
        .get("record_type")
        .await
        .map_err(|_e| server_err!(ServerErrorCode::ProcessChainError, "get record_type err"))?
        .ok_or_else(|| server_err!(ServerErrorCode::ProcessChainError, "record_type is none"))?;
    let record_type = match record_type {
        CollectionValue::String(s) => s,
        _ => {
            return Err(server_err!(
                ServerErrorCode::ProcessChainError,
                "record_type is not string"
            ))
        }
    };
    let ttl = map
        .get("ttl")
        .await
        .map_err(|_e| server_err!(ServerErrorCode::ProcessChainError, "get ttl err"))?;
    let ttl = if let Some(ttl) = ttl {
        match ttl {
            CollectionValue::String(n) => n.parse::<u32>().map_err(|_e| {
                server_err!(ServerErrorCode::ProcessChainError, "ttl is not number")
            })?,
            _ => {
                return Err(server_err!(
                    ServerErrorCode::ProcessChainError,
                    "ttl is not number"
                ))
            }
        }
    } else {
        600
    };

    let name = map
        .get("name")
        .await
        .map_err(|_e| server_err!(ServerErrorCode::ProcessChainError, "get name err"))?
        .ok_or_else(|| server_err!(ServerErrorCode::ProcessChainError, "name is none"))?;
    let name = match name {
        CollectionValue::String(s) => s,
        _ => {
            return Err(server_err!(
                ServerErrorCode::ProcessChainError,
                "name is not string"
            ))
        }
    };

    match record_type.as_str() {
        "A" => {
            let address = map
                .get("address")
                .await
                .map_err(|_e| server_err!(ServerErrorCode::ProcessChainError, "get address err"))?
                .ok_or_else(|| {
                    server_err!(ServerErrorCode::ProcessChainError, "address is none")
                })?;
            match address {
                CollectionValue::Set(s) => {
                    let mut addresses = Vec::new();
                    let all = s.get_all().await.map_err(|e| {
                        server_err!(
                            ServerErrorCode::ProcessChainError,
                            "get address set all err {}",
                            e
                        )
                    })?;
                    for item in all.iter() {
                        addresses.push(item.parse::<IpAddr>().map_err(into_server_err!(
                            ServerErrorCode::ProcessChainError,
                            "parse ip err"
                        ))?);
                    }
                    let mut name_info = NameInfo::from_address_vec(name.as_str(), addresses);
                    name_info.ttl = Some(ttl);
                    Ok(name_info)
                }
                _ => Err(server_err!(
                    ServerErrorCode::ProcessChainError,
                    "address is not set"
                )),
            }
        }
        "AAAA" => {
            let address = map.get("address").await.map_err(|e| {
                server_err!(ServerErrorCode::ProcessChainError, "get address err {}", e)
            })?;
            if let Some(address) = address {
                match address {
                    CollectionValue::Set(s) => {
                        let mut addresses = Vec::new();
                        let all = s.get_all().await.map_err(|e| {
                            server_err!(
                                ServerErrorCode::ProcessChainError,
                                "get address set all err {}",
                                e
                            )
                        })?;
                        for item in all.iter() {
                            addresses.push(item.parse::<IpAddr>().map_err(into_server_err!(
                                ServerErrorCode::ProcessChainError,
                                "parse ip err"
                            ))?);
                        }
                        let mut name_info = NameInfo::from_address_vec(name.as_str(), addresses);
                        name_info.ttl = Some(ttl);
                        Ok(name_info)
                    }
                    _ => Err(server_err!(
                        ServerErrorCode::ProcessChainError,
                        "address is not set"
                    )),
                }
            } else {
                return Err(server_err!(
                    ServerErrorCode::ProcessChainError,
                    "address is not exist"
                ));
            }
        }
        "CNAME" => {
            let cname = map.get("cname").await.map_err(|e| {
                server_err!(ServerErrorCode::ProcessChainError, "get cname err {}", e)
            })?;
            if let Some(cname) = cname {
                match cname {
                    CollectionValue::String(s) => {
                        let mut name_info = NameInfo::new(name.as_str());
                        name_info.cname = Some(s);
                        Ok(name_info)
                    }
                    _ => Err(server_err!(
                        ServerErrorCode::ProcessChainError,
                        "cname is not string"
                    )),
                }
            } else {
                return Err(server_err!(
                    ServerErrorCode::ProcessChainError,
                    "cname is not exist"
                ));
            }
        }
        "HTTPS" => {
            let mut name_info = NameInfo::new(name.as_str());
            name_info.ttl = Some(ttl);
            Ok(name_info)
        }
        "TXT" => {
            let mut name_info = NameInfo::new(name.as_str());
            name_info.ttl = Some(ttl);
            let txt = map.get("txt").await.map_err(|e| {
                server_err!(ServerErrorCode::ProcessChainError, "get txt err {}", e)
            })?;
            if let Some(txt) = txt {
                match txt {
                    CollectionValue::String(s) => {
                        name_info.txt.push(s);
                    }
                    CollectionValue::Set(s) => {
                        let all = s.get_all().await.map_err(|e| {
                            server_err!(
                                ServerErrorCode::ProcessChainError,
                                "get txt set all err {}",
                                e
                            )
                        })?;
                        for item in all.iter() {
                            name_info.txt.push(item.clone());
                        }
                    }
                    _ => {
                        return Err(server_err!(
                            ServerErrorCode::ProcessChainError,
                            "txt is not string"
                        ))
                    }
                }
            }

            Ok(name_info)
        }
        "CAA" => {
            let mut name_info = NameInfo::new(name.as_str());
            name_info.ttl = Some(ttl);
            let caa = map.get("caa").await.map_err(|e| {
                server_err!(ServerErrorCode::ProcessChainError, "get caa err {}", e)
            })?;
            if let Some(caa) = caa {
                match caa {
                    CollectionValue::String(s) => {
                        name_info.caa.push(s);
                    }
                    CollectionValue::Set(s) => {
                        let all = s.get_all().await.map_err(|e| {
                            server_err!(
                                ServerErrorCode::ProcessChainError,
                                "get caa set all err {}",
                                e
                            )
                        })?;
                        for item in all.iter() {
                            name_info.caa.push(item.clone());
                        }
                    }
                    _ => {
                        return Err(server_err!(
                            ServerErrorCode::ProcessChainError,
                            "caa is not string"
                        ))
                    }
                }
            }

            Ok(name_info)
        }
        "PTR" => {
            let mut name_info = NameInfo::new(name.as_str());
            name_info.ttl = Some(ttl);
            let ptr_records = map.get("ptr_records").await.map_err(|e| {
                server_err!(
                    ServerErrorCode::ProcessChainError,
                    "get ptr_records err {}",
                    e
                )
            })?;
            if let Some(ptr_records) = ptr_records {
                match ptr_records {
                    CollectionValue::String(s) => {
                        name_info.ptr_records.push(s);
                    }
                    CollectionValue::Set(s) => {
                        let all = s.get_all().await.map_err(|e| {
                            server_err!(
                                ServerErrorCode::ProcessChainError,
                                "get ptr set all err {}",
                                e
                            )
                        })?;
                        for item in all.iter() {
                            name_info.ptr_records.push(item.clone());
                        }
                    }
                    _ => {
                        return Err(server_err!(
                            ServerErrorCode::ProcessChainError,
                            "ptr_records is not string"
                        ))
                    }
                }
            }

            Ok(name_info)
        }
        _ => Err(server_err!(
            ServerErrorCode::InvalidParam,
            "Unknown record type:{}",
            record_type
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_caa_map_collection_round_trip() {
        let mut name_info = NameInfo::new("web3.buckyos.ai");
        name_info.ttl = Some(600);
        name_info.caa = vec![
            "0 issue \"letsencrypt.org\"".to_string(),
            "0 iodef \"mailto:ops@buckyos.ai\"".to_string(),
        ];

        let map = nameinfo_to_map_collection("CAA", &name_info).await.unwrap();
        let restored = map_collection_to_nameinfo(&map).await.unwrap();

        assert_eq!(restored.name, "web3.buckyos.ai");
        assert_eq!(restored.caa, name_info.caa);
    }

    #[tokio::test]
    async fn test_empty_caa_map_collection_round_trip() {
        let mut name_info = NameInfo::new("web3.buckyos.ai");
        name_info.ttl = Some(300);

        let map = nameinfo_to_map_collection("CAA", &name_info).await.unwrap();
        let restored = map_collection_to_nameinfo(&map).await.unwrap();

        assert_eq!(restored.name, "web3.buckyos.ai");
        assert!(restored.caa.is_empty());
    }

    #[tokio::test]
    async fn test_https_map_collection_round_trip() {
        let mut name_info = NameInfo::new("web3.buckyos.ai");
        name_info.ttl = Some(300);

        let map = nameinfo_to_map_collection("HTTPS", &name_info)
            .await
            .unwrap();
        let restored = map_collection_to_nameinfo(&map).await.unwrap();

        assert_eq!(restored.name, "web3.buckyos.ai");
        assert_eq!(restored.ttl, Some(300));
        assert!(restored.address.is_empty());
        assert!(restored.txt.is_empty());
        assert!(restored.caa.is_empty());
    }
}
