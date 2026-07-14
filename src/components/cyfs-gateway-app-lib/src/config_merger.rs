use anyhow::{Result, anyhow};
use httpdate::{fmt_http_date, parse_http_date};
use log::*;
use reqwest::header::{IF_MODIFIED_SINCE, LAST_MODIFIED};
use serde::Deserialize;
use serde_json::json;
use serde_json::value::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use url::Url;

#[derive(Debug, Clone)]
struct ConfigItem {
    path: String,
    value: JsonValue,
}

#[derive(Debug, Clone)]
enum ConfigSource {
    Local(PathBuf),
    Remote(Url),
}

impl ConfigSource {
    fn display(&self) -> String {
        match self {
            ConfigSource::Local(path) => path.to_string_lossy().to_string(),
            ConfigSource::Remote(url) => url.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
enum IncludeBase {
    Local(PathBuf),
    Remote(Url),
}

#[derive(Debug, Deserialize)]
struct Include {
    path: String,
}

#[derive(Debug, Deserialize)]
struct RootConfig {
    includes: Option<Vec<Include>>,
}

pub struct ConfigMerger {}

impl ConfigMerger {
    pub async fn load_dir(
        dir: &Path,
        modified_since: Option<SystemTime>,
        cache_dir: &Path,
    ) -> Result<JsonValue> {
        debug!("Loading config files from directory: {:?}", dir);

        let configs = load_dir_internal(dir, modified_since, cache_dir).await?;
        let merged = merge_configs(&configs)?;

        Ok(merged)
    }

    pub async fn load_dir_with_root(
        dir: &Path,
        root_file: &Path,
        modified_since: Option<SystemTime>,
        cache_dir: &Path,
    ) -> Result<JsonValue> {
        debug!(
            "Loading config files from directory: {:?} with root file: {:?}",
            dir, root_file
        );

        let configs =
            load_dir_with_root_internal(dir, root_file, modified_since, cache_dir).await?;
        if configs.is_empty() {
            return Ok(json!({}));
        }

        let merged = merge_configs(&configs)?;

        Ok(merged)
    }

    pub async fn load_config<T>(
        dir: &Path,
        modified_since: Option<SystemTime>,
        cache_dir: &Path,
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let value = Self::load_dir(dir, modified_since, cache_dir).await?;
        let config: T = serde_json::from_value(value).map_err(|e| {
            let msg = format!("Failed to parse config: {:?}", e);
            error!("{}", msg);
            anyhow!(msg)
        })?;
        Ok(config)
    }
}

fn merge_configs(configs: &[ConfigItem]) -> Result<JsonValue> {
    if configs.is_empty() {
        return Err(anyhow!("no config files loaded"));
    }

    debug!("Loaded {} config files: {:?}", configs.len(), configs);

    let mut merged = configs[0].clone();
    for config in configs.iter().skip(1) {
        debug!("Will merge config: {:?} -> {:?}", config.path, merged.path);
        merge(&mut merged.value, &config.value);
    }

    Ok(merged.value)
}

pub fn merge(current: &mut JsonValue, new_value: &JsonValue) {
    match (current, new_value) {
        (JsonValue::Object(current_map), JsonValue::Object(new_map)) => {
            for (key, value) in new_map {
                merge(
                    current_map.entry(key).or_insert_with(|| JsonValue::Null),
                    value,
                );
            }
        }
        (JsonValue::Array(current_array), JsonValue::Array(new_array)) => {
            current_array.reserve(new_array.len());
            for value in new_array.iter() {
                if !current_array.iter().any(|existing| existing == value) {
                    current_array.push(value.clone());
                }
            }
        }
        (JsonValue::Array(current_array), new_value) => {
            if !current_array.iter().any(|existing| existing == new_value) {
                current_array.push(new_value.clone());
            }
        }
        (current, new_value) => {
            *current = new_value.clone();
        }
    }
}

fn get_root_file(dir: &Path) -> Option<PathBuf> {
    let root_file = dir.join("root");
    if root_file.exists() {
        return Some(root_file);
    }

    let root_file = dir.join("root.json");
    if root_file.exists() {
        return Some(root_file);
    }

    let root_file = dir.join("root.toml");
    if root_file.exists() {
        return Some(root_file);
    }
    None
}

fn toml_to_json(toml_value: toml::Value) -> Result<JsonValue> {
    let json_string = serde_json::to_string(&toml_value).map_err(|e| {
        let msg = format!("Failed to convert TOML to JSON: {:?}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;

    let json_value: JsonValue = serde_json::from_str(&json_string).map_err(|e| {
        let msg = format!("Failed to parse JSON: {:?}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;

    Ok(json_value)
}

fn yaml_to_json(yaml_value: serde_yaml_ng::Value) -> Result<JsonValue> {
    let json_value = serde_json::Value::deserialize(yaml_value).map_err(|e| {
        let msg = format!("Failed to convert YAML to JSON: {:?}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;
    Ok(json_value)
}

fn parse_config_content(content: &str, ext: Option<&str>) -> Result<JsonValue> {
    if let Some(ext) = ext {
        match ext {
            "json" => {
                return serde_json::from_str(content).map_err(|e| {
                    let msg = format!("Failed to parse JSON: {:?}", e);
                    error!("{}", msg);
                    anyhow!(msg)
                });
            }
            "toml" => {
                let toml_value: toml::Value = toml::from_str(content).map_err(|e| {
                    let msg = format!("Failed to parse TOML: {:?}", e);
                    error!("{}", msg);
                    anyhow!(msg)
                })?;

                return toml_to_json(toml_value);
            }
            "yaml" | "yml" => {
                let yaml_value: serde_yaml_ng::Value =
                    serde_yaml_ng::from_str(content).map_err(|e| {
                        let msg = format!("Failed to parse YAML: {:?}", e);
                        error!("{}", msg);
                        anyhow!(msg)
                    })?;

                return yaml_to_json(yaml_value);
            }
            _ => {}
        }
    }

    if content.trim_start().starts_with('{') {
        serde_json::from_str(content).map_err(|e| {
            let msg = format!("Failed to parse JSON: {:?}", e);
            error!("{}", msg);
            anyhow!(msg)
        })
    } else {
        let toml_value: toml::Value = toml::from_str(content).map_err(|e| {
            let msg = format!("Failed to parse TOML: {:?}", e);
            error!("{}", msg);
            anyhow!(msg)
        })?;
        toml_to_json(toml_value)
    }
}

#[derive(Debug)]
struct LoadedConfig {
    value: JsonValue,
    last_modified: Option<SystemTime>,
}

async fn load_local_file(file: &Path) -> Result<LoadedConfig> {
    debug!("Loading config file: {:?}", file);
    assert!(file.exists());

    let content = tokio::fs::read_to_string(file).await.map_err(|e| {
        let msg = format!("Failed to read file: {:?}, error: {:?}", file, e);
        error!("{}", msg);
        anyhow!(msg)
    })?;

    let ext = file.extension().and_then(|s| s.to_str());
    let value = parse_config_content(&content, ext)?;
    let last_modified = std::fs::metadata(file)
        .and_then(|meta| meta.modified())
        .ok();

    Ok(LoadedConfig {
        value,
        last_modified,
    })
}

fn extension_from_url(url: &Url) -> Option<String> {
    let path = url.path();
    let ext = Path::new(path).extension().and_then(|s| s.to_str())?;
    Some(ext.to_string())
}

fn remote_cache_path(url: &Url, cache_dir: &Path) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(url.as_str().as_bytes());
    let hash = hex::encode(hasher.finalize());

    let mut filename = hash;
    if let Some(ext) = extension_from_url(url) {
        filename.push('.');
        filename.push_str(&ext);
    }

    cache_dir.join(filename)
}

fn remote_cache_meta_path(url: &Url, cache_dir: &Path) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(url.as_str().as_bytes());
    let hash = hex::encode(hasher.finalize());
    cache_dir.join(format!("{}.last_modified", hash))
}

async fn read_cached_last_modified(path: &Path) -> Option<SystemTime> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    parse_http_date(content.trim()).ok()
}

fn parse_last_modified(headers: &reqwest::header::HeaderMap) -> Option<SystemTime> {
    let value = headers.get(LAST_MODIFIED)?;
    let value = value.to_str().ok()?;
    parse_http_date(value).ok()
}

async fn load_cached_config(
    cache_path: &Path,
    url: &Url,
    meta_modified: Option<SystemTime>,
    cache_modified: Option<SystemTime>,
) -> Result<LoadedConfig> {
    if !cache_path.exists() {
        let msg = format!("Cache file missing: {}", cache_path.to_string_lossy());
        error!("{}", msg);
        return Err(anyhow!(msg));
    }
    let content = tokio::fs::read_to_string(cache_path).await.map_err(|e| {
        let msg = format!(
            "Failed to read cached config: {:?}, error: {:?}",
            cache_path, e
        );
        error!("{}", msg);
        anyhow!(msg)
    })?;
    let ext = extension_from_url(url);
    let value = parse_config_content(&content, ext.as_deref())?;
    Ok(LoadedConfig {
        value,
        last_modified: meta_modified.or(cache_modified),
    })
}

async fn load_remote_file(url: &Url, cache_dir: &Path) -> Result<LoadedConfig> {
    match url.scheme() {
        "http" | "https" => {}
        _ => {
            let msg = format!("Unsupported url scheme: {}", url.scheme());
            error!("{}", msg);
            return Err(anyhow!(msg));
        }
    }

    debug!("Downloading config file: {}", url);

    let cache_path = remote_cache_path(url, cache_dir);
    let meta_path = remote_cache_meta_path(url, cache_dir);
    let cache_modified = std::fs::metadata(&cache_path)
        .and_then(|meta| meta.modified())
        .ok();
    let meta_modified = read_cached_last_modified(&meta_path).await;
    let header_since = meta_modified.or(cache_modified);

    let client = reqwest::Client::new();
    let mut request = client.get(url.clone());
    if let Some(since) = header_since {
        request = request.header(IF_MODIFIED_SINCE, fmt_http_date(since));
    }

    let resp = match request.send().await {
        Ok(resp) => resp,
        Err(e) => {
            let msg = format!("Failed to download config file: {}, error: {:?}", url, e);
            error!("{}", msg);
            if cache_path.exists() {
                warn!(
                    "Using cached config after download failure: {}",
                    cache_path.to_string_lossy()
                );
                return load_cached_config(&cache_path, url, meta_modified, cache_modified).await;
            }
            return Err(anyhow!(msg));
        }
    };

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return load_cached_config(&cache_path, url, meta_modified, cache_modified).await;
    }

    if !resp.status().is_success() {
        let msg = format!(
            "Failed to download config file: {}, status: {}",
            url,
            resp.status()
        );
        error!("{}", msg);
        if cache_path.exists() {
            warn!(
                "Using cached config after bad status: {}",
                cache_path.to_string_lossy()
            );
            return load_cached_config(&cache_path, url, meta_modified, cache_modified).await;
        }
        return Err(anyhow!(msg));
    }

    let last_modified = parse_last_modified(resp.headers());
    let content = match resp.text().await {
        Ok(content) => content,
        Err(e) => {
            let msg = format!("Failed to read config body: {}, error: {:?}", url, e);
            error!("{}", msg);
            if cache_path.exists() {
                warn!(
                    "Using cached config after read failure: {}",
                    cache_path.to_string_lossy()
                );
                return load_cached_config(&cache_path, url, meta_modified, cache_modified).await;
            }
            return Err(anyhow!(msg));
        }
    };

    if let Err(e) = std::fs::create_dir_all(cache_dir) {
        warn!(
            "Failed to create cache dir: {:?}, error: {:?}",
            cache_dir, e
        );
    }
    if let Err(e) = tokio::fs::write(&cache_path, &content).await {
        warn!(
            "Failed to write cache file: {:?}, error: {:?}",
            cache_path, e
        );
    }
    if let Some(last_modified) = last_modified {
        let text = fmt_http_date(last_modified);
        if let Err(e) = tokio::fs::write(&meta_path, text).await {
            warn!(
                "Failed to write cache meta file: {:?}, error: {:?}",
                meta_path, e
            );
        }
    }

    let ext = extension_from_url(url);
    let value = parse_config_content(&content, ext.as_deref())?;

    Ok(LoadedConfig {
        value,
        last_modified,
    })
}

fn should_load_file(file: &Path, modified_since: Option<SystemTime>) -> bool {
    let Some(modified_since) = modified_since else {
        return true;
    };

    match std::fs::metadata(file).and_then(|meta| meta.modified()) {
        Ok(modified) => modified > modified_since,
        Err(_) => true,
    }
}

fn should_load_remote(
    last_modified: Option<SystemTime>,
    modified_since: Option<SystemTime>,
) -> bool {
    let Some(modified_since) = modified_since else {
        return true;
    };

    match last_modified {
        Some(modified) => modified > modified_since,
        None => true,
    }
}

fn is_remote_path(path: &str) -> bool {
    let path = path.trim_start();
    path.starts_with("http://") || path.starts_with("https://")
}

fn parse_remote_url(path: &str) -> Result<Url> {
    let url = Url::parse(path).map_err(|e| {
        let msg = format!("Invalid url: {}, error: {:?}", path, e);
        error!("{}", msg);
        anyhow!(msg)
    })?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        _ => Err(anyhow!("Unsupported url scheme: {}", url.scheme())),
    }
}

fn include_base_for_source(source: &ConfigSource) -> IncludeBase {
    match source {
        ConfigSource::Local(path) => {
            let base = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            IncludeBase::Local(base)
        }
        ConfigSource::Remote(url) => IncludeBase::Remote(remote_base_url(url)),
    }
}

fn remote_base_url(url: &Url) -> Url {
    let mut base = url.clone();
    base.set_query(None);
    base.set_fragment(None);

    let path = base.path().to_string();
    if path.is_empty() {
        base.set_path("/");
        return base;
    }

    if path.ends_with('/') {
        return base;
    }

    let parent = Path::new(&path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| String::from("/"));
    let mut parent_path = parent;
    if !parent_path.ends_with('/') {
        parent_path.push('/');
    }
    base.set_path(&parent_path);
    base
}

fn resolve_include_source(base: &IncludeBase, include_path: &str) -> Result<ConfigSource> {
    match base {
        IncludeBase::Remote(base_url) => {
            if is_remote_path(include_path) {
                return Ok(ConfigSource::Remote(parse_remote_url(include_path)?));
            }
            let url = base_url.join(include_path).map_err(|e| {
                let msg = format!(
                    "Failed to resolve include url: {}, error: {:?}",
                    include_path, e
                );
                error!("{}", msg);
                anyhow!(msg)
            })?;
            Ok(ConfigSource::Remote(url))
        }
        IncludeBase::Local(base_dir) => {
            if is_remote_path(include_path) {
                return Ok(ConfigSource::Remote(parse_remote_url(include_path)?));
            }
            let path = PathBuf::from(include_path);
            if path.is_absolute() {
                return Ok(ConfigSource::Local(path));
            }
            Ok(ConfigSource::Local(base_dir.join(path)))
        }
    }
}

#[async_recursion::async_recursion]
async fn load_config_source(
    source: &ConfigSource,
    modified_since: Option<SystemTime>,
    cache_dir: &Path,
) -> Result<Vec<ConfigItem>> {
    let loaded = match source {
        ConfigSource::Local(path) => load_local_file(path).await?,
        ConfigSource::Remote(url) => load_remote_file(url, cache_dir).await?,
    };

    let value = loaded.value;
    let root_config: RootConfig = serde_json::from_value(value.clone()).map_err(|e| {
        let msg = format!("Failed to parse config includes: {:?}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;

    let base = include_base_for_source(source);
    let mut configs = Vec::new();

    if let Some(includes) = root_config.includes {
        for include in includes {
            let include_source = resolve_include_source(&base, &include.path)?;
            match include_source {
                ConfigSource::Local(path) => {
                    if !path.exists() {
                        let msg = format!("Include path not exists: {:?}", path);
                        error!("{}", msg);
                        return Err(anyhow!(msg));
                    }

                    if path.is_dir() {
                        let items = load_dir_internal(&path, modified_since, cache_dir).await?;
                        configs.extend(items);
                    } else {
                        let items = load_config_source(
                            &ConfigSource::Local(path),
                            modified_since,
                            cache_dir,
                        )
                        .await?;
                        configs.extend(items);
                    }
                }
                ConfigSource::Remote(url) => {
                    let items =
                        load_config_source(&ConfigSource::Remote(url), modified_since, cache_dir)
                            .await?;
                    configs.extend(items);
                }
            }
        }
    }

    let should_include = match source {
        ConfigSource::Local(path) => should_load_file(path, modified_since),
        ConfigSource::Remote(_) => should_load_remote(loaded.last_modified, modified_since),
    };

    if should_include {
        configs.push(ConfigItem {
            path: source.display(),
            value,
        });
    }

    Ok(configs)
}

async fn load_dir_with_root_internal(
    _dir: &Path,
    root_file: &Path,
    modified_since: Option<SystemTime>,
    cache_dir: &Path,
) -> Result<Vec<ConfigItem>> {
    assert!(root_file.exists());

    let root_source = ConfigSource::Local(root_file.to_path_buf());
    load_config_source(&root_source, modified_since, cache_dir).await
}

#[derive(Debug)]
struct IndexedFile {
    index: Option<u32>,
    scan_order: usize,
    path: PathBuf,
}

async fn scan_files(dir: &Path) -> Result<Vec<IndexedFile>> {
    let mut indexed_files = Vec::new();

    let mut dir_entries = tokio::fs::read_dir(dir).await.map_err(|e| {
        let msg = format!("Failed to read dir: {:?}, error: {:?}", dir, e);
        error!("{}", msg);
        e
    })?;

    let mut scan_order = 0;
    while let Some(entry) = dir_entries.next_entry().await? {
        let path = entry.path();

        let index = extract_index_from_filename(&path);
        indexed_files.push(IndexedFile {
            index,
            scan_order,
            path,
        });
        scan_order += 1;
    }

    sort_indexed_files(&mut indexed_files)?;

    Ok(indexed_files)
}

fn sort_indexed_files(indexed_files: &mut [IndexedFile]) -> Result<()> {
    let mut index_set = std::collections::HashSet::new();
    for file in indexed_files.iter() {
        if let Some(index) = file.index {
            if !index_set.insert(index) {
                let msg = format!("Duplicated index found: {} {:?}", index, file.path);
                error!("{}", msg);
                return Err(anyhow!(msg));
            }
        }
    }

    indexed_files.sort_by_key(|file| {
        (
            file.index.is_none(),
            file.index.unwrap_or(u32::MAX),
            file.scan_order,
        )
    });

    Ok(())
}

fn extract_index_from_filename(path: &Path) -> Option<u32> {
    let file_stem = path.file_name()?.to_str()?;
    let index_part = file_stem.rsplit('.').next()?;
    let index = index_part.parse::<u32>().ok();
    if index.is_none() {
        let index_part = file_stem.rsplit('.').nth(1)?;
        return index_part.parse::<u32>().ok();
    }
    index
}

async fn load_dir_without_root(
    dir: &Path,
    modified_since: Option<SystemTime>,
    cache_dir: &Path,
) -> Result<Vec<ConfigItem>> {
    let indexed_files = scan_files(dir).await?;

    debug!("Indexed files: {:?} in {:?}", indexed_files, dir);

    let mut config = Vec::new();
    for file in indexed_files {
        if file.path.is_file() {
            let items =
                load_config_source(&ConfigSource::Local(file.path), modified_since, cache_dir)
                    .await?;
            config.extend(items);
        } else {
            let items = load_dir_internal(&file.path, modified_since, cache_dir).await?;
            config.extend(items);
        }
    }

    Ok(config)
}

#[async_recursion::async_recursion]
async fn load_dir_internal(
    dir: &Path,
    modified_since: Option<SystemTime>,
    cache_dir: &Path,
) -> Result<Vec<ConfigItem>> {
    let root_file = get_root_file(dir);

    match root_file {
        Some(root_file) => {
            load_dir_with_root_internal(dir, &root_file, modified_since, cache_dir).await
        }
        None => load_dir_without_root(dir, modified_since, cache_dir).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_is_remote_path() {
        assert!(is_remote_path("http://example.com"));
        assert!(is_remote_path(" https://example.com"));
        assert!(!is_remote_path("ftp://example.com"));
        assert!(!is_remote_path("config.json"));
    }

    #[test]
    fn test_parse_remote_url_ok() {
        let url = parse_remote_url("https://example.com/a/b.json").unwrap();
        assert_eq!(url.scheme(), "https");
    }

    #[test]
    fn test_parse_remote_url_invalid_scheme() {
        assert!(parse_remote_url("ftp://example.com/config.json").is_err());
    }

    #[test]
    fn test_parse_remote_url_invalid_value() {
        assert!(parse_remote_url("http://[::1").is_err());
    }

    #[test]
    fn test_remote_base_url_parent() {
        let url = Url::parse("https://example.com/a/b/c.json?x=1#frag").unwrap();
        let base = remote_base_url(&url);
        assert_eq!(base.as_str(), "https://example.com/a/b/");
    }

    #[test]
    fn test_remote_base_url_root() {
        let url = Url::parse("https://example.com").unwrap();
        let base = remote_base_url(&url);
        assert_eq!(base.as_str(), "https://example.com/");
    }

    #[test]
    fn test_include_base_for_source_local() {
        let path = PathBuf::from("config/root.json");
        let base = include_base_for_source(&ConfigSource::Local(path));
        match base {
            IncludeBase::Local(base_dir) => {
                assert_eq!(base_dir, PathBuf::from("config"));
            }
            IncludeBase::Remote(_) => panic!("expected local base"),
        }
    }

    #[test]
    fn test_include_base_for_source_remote() {
        let url = Url::parse("https://example.com/a/b/config.json").unwrap();
        let base = include_base_for_source(&ConfigSource::Remote(url));
        match base {
            IncludeBase::Remote(base_url) => {
                assert_eq!(base_url.as_str(), "https://example.com/a/b/");
            }
            IncludeBase::Local(_) => panic!("expected remote base"),
        }
    }

    #[test]
    fn test_resolve_include_source_remote_relative() {
        let base = IncludeBase::Remote(Url::parse("https://example.com/a/b/").unwrap());
        let source = resolve_include_source(&base, "child.yaml").unwrap();
        match source {
            ConfigSource::Remote(url) => {
                assert_eq!(url.as_str(), "https://example.com/a/b/child.yaml");
            }
            ConfigSource::Local(_) => panic!("expected remote source"),
        }

        let source = resolve_include_source(&base, "./child.yaml").unwrap();
        match source {
            ConfigSource::Remote(url) => {
                assert_eq!(url.as_str(), "https://example.com/a/b/child.yaml");
            }
            ConfigSource::Local(_) => panic!("expected remote source"),
        }

        let source = resolve_include_source(&base, "../child.yaml").unwrap();
        match source {
            ConfigSource::Remote(url) => {
                assert_eq!(url.as_str(), "https://example.com/a/child.yaml");
            }
            ConfigSource::Local(_) => panic!("expected remote source"),
        }

        let source = resolve_include_source(&base, "/child.yaml").unwrap();
        match source {
            ConfigSource::Remote(url) => {
                assert_eq!(url.as_str(), "https://example.com/child.yaml");
            }
            ConfigSource::Local(_) => panic!("expected remote source"),
        }
    }

    #[test]
    fn test_resolve_include_source_remote_absolute() {
        let base = IncludeBase::Remote(Url::parse("https://example.com/a/b/").unwrap());
        let source = resolve_include_source(&base, "https://other.com/x.json").unwrap();
        match source {
            ConfigSource::Remote(url) => {
                assert_eq!(url.as_str(), "https://other.com/x.json");
            }
            ConfigSource::Local(_) => panic!("expected remote source"),
        }
    }

    #[test]
    fn test_resolve_include_source_remote_invalid_absolute() {
        let base = IncludeBase::Remote(Url::parse("https://example.com/a/b/").unwrap());
        assert!(resolve_include_source(&base, "http://[::1").is_err());
    }

    #[test]
    fn test_resolve_include_source_local_relative() {
        let base_dir = PathBuf::from("config");
        let base = IncludeBase::Local(base_dir.clone());
        let source = resolve_include_source(&base, "child.json").unwrap();
        match source {
            ConfigSource::Local(path) => {
                assert_eq!(path, base_dir.join("child.json"));
            }
            ConfigSource::Remote(_) => panic!("expected local source"),
        }
    }

    #[test]
    fn test_resolve_include_source_local_absolute() {
        let base = IncludeBase::Local(PathBuf::from("config"));
        let abs = if cfg!(windows) {
            r"C:\config\child.json"
        } else {
            "/config/child.json"
        };
        let source = resolve_include_source(&base, abs).unwrap();
        match source {
            ConfigSource::Local(path) => {
                assert_eq!(path, PathBuf::from(abs));
            }
            ConfigSource::Remote(_) => panic!("expected local source"),
        }
    }

    #[test]
    fn test_resolve_include_source_local_remote() {
        let base = IncludeBase::Local(PathBuf::from("config"));
        let source = resolve_include_source(&base, "https://example.com/child.json").unwrap();
        match source {
            ConfigSource::Remote(url) => {
                assert_eq!(url.as_str(), "https://example.com/child.json");
            }
            ConfigSource::Local(_) => panic!("expected remote source"),
        }
    }

    #[test]
    fn test_sort_indexed_files_keeps_unindexed_after_indexed_and_in_scan_order() {
        let mut indexed_files = vec![
            IndexedFile {
                index: None,
                scan_order: 0,
                path: PathBuf::from("plain-b.yaml"),
            },
            IndexedFile {
                index: Some(20),
                scan_order: 1,
                path: PathBuf::from("second.20.yaml"),
            },
            IndexedFile {
                index: None,
                scan_order: 2,
                path: PathBuf::from("plain-a.yaml"),
            },
            IndexedFile {
                index: Some(10),
                scan_order: 3,
                path: PathBuf::from("first.10.yaml"),
            },
        ];

        sort_indexed_files(&mut indexed_files).unwrap();

        let ordered_paths: Vec<_> = indexed_files
            .iter()
            .map(|file| file.path.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            ordered_paths,
            vec![
                "first.10.yaml",
                "second.20.yaml",
                "plain-b.yaml",
                "plain-a.yaml",
            ]
        );
    }

    #[test]
    fn test_sort_indexed_files_rejects_duplicate_explicit_indexes() {
        let mut indexed_files = vec![
            IndexedFile {
                index: Some(10),
                scan_order: 0,
                path: PathBuf::from("first.10.yaml"),
            },
            IndexedFile {
                index: Some(10),
                scan_order: 1,
                path: PathBuf::from("second.10.yaml"),
            },
        ];

        let err = sort_indexed_files(&mut indexed_files).unwrap_err();
        assert!(err.to_string().contains("Duplicated index found: 10"));
    }

    #[tokio::test]
    async fn test_scan_files_sorts_explicit_indexes_before_unindexed() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("plain.yaml"), b"plain").unwrap();
        std::fs::write(dir.path().join("second.20.yaml"), b"second").unwrap();
        std::fs::write(dir.path().join("first.10.yaml"), b"first").unwrap();

        let files = scan_files(dir.path()).await.unwrap();
        let ordered_paths: Vec<_> = files
            .iter()
            .map(|file| file.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert_eq!(
            ordered_paths,
            vec!["first.10.yaml", "second.20.yaml", "plain.yaml"]
        );
    }

    #[tokio::test]
    async fn test_scan_files_allows_multiple_unindexed_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("plain-a.yaml"), b"a").unwrap();
        std::fs::write(dir.path().join("plain-b.yaml"), b"b").unwrap();

        let files = scan_files(dir.path()).await.unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|file| file.index.is_none()));
    }

    #[tokio::test]
    async fn test_scan_files_rejects_duplicate_explicit_indexes() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("first.10.yaml"), b"first").unwrap();
        std::fs::write(dir.path().join("second.10.yaml"), b"second").unwrap();

        let err = scan_files(dir.path()).await.unwrap_err();
        assert!(err.to_string().contains("Duplicated index found: 10"));
    }
}
