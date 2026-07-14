use alloy_primitives::{Address, Bytes, Log, B256};
use alloy_sol_types::SolCall;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{BnsEvmError, BnsEvmResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockRange {
    Latest,
    Number(u64),
}

impl BlockRange {
    fn to_rpc_value(&self) -> Value {
        match self {
            Self::Latest => Value::String("latest".to_string()),
            Self::Number(number) => Value::String(quantity_hex(*number)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcLogFilter {
    pub address: Address,
    pub from_block: BlockRange,
    pub to_block: BlockRange,
    pub topics: Vec<Option<B256>>,
}

impl RpcLogFilter {
    fn to_rpc_value(&self) -> Value {
        let topics: Vec<Value> = self
            .topics
            .iter()
            .map(|topic| match topic {
                Some(topic) => Value::String(hex_b256(*topic)),
                None => Value::Null,
            })
            .collect();
        json!({
            "address": hex_address(self.address),
            "fromBlock": self.from_block.to_rpc_value(),
            "toBlock": self.to_block.to_rpc_value(),
            "topics": topics,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    #[serde(default, deserialize_with = "deserialize_optional_quantity")]
    pub block_number: Option<u64>,
    #[serde(default)]
    pub block_hash: Option<B256>,
    #[serde(default)]
    pub transaction_hash: Option<B256>,
    #[serde(default, deserialize_with = "deserialize_optional_quantity")]
    pub transaction_index: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_quantity")]
    pub log_index: Option<u64>,
    #[serde(default)]
    pub removed: bool,
}

impl EthLog {
    pub fn as_alloy_log(&self) -> Log {
        Log::new_unchecked(self.address, self.topics.clone(), self.data.clone())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthBlock {
    #[serde(default, deserialize_with = "deserialize_optional_quantity")]
    pub number: Option<u64>,
    #[serde(default)]
    pub hash: Option<B256>,
    #[serde(default)]
    pub parent_hash: Option<B256>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTransaction {
    pub hash: B256,
    #[serde(default)]
    pub from: Option<Address>,
    #[serde(default)]
    pub to: Option<Address>,
    #[serde(default)]
    pub input: Bytes,
    #[serde(default, deserialize_with = "deserialize_optional_quantity")]
    pub block_number: Option<u64>,
    #[serde(default)]
    pub block_hash: Option<B256>,
    #[serde(default, deserialize_with = "deserialize_optional_quantity")]
    pub transaction_index: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTransactionReceipt {
    pub transaction_hash: B256,
    #[serde(default)]
    pub block_hash: Option<B256>,
    #[serde(default, deserialize_with = "deserialize_optional_quantity")]
    pub block_number: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_quantity")]
    pub transaction_index: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_quantity")]
    pub status: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_quantity")]
    pub gas_used: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip1559FeeSuggestion {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

#[derive(Debug, Clone)]
pub struct EthRpcClient {
    endpoint: String,
    client: reqwest::Client,
}

impl EthRpcClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: reqwest::Client::new(),
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn chain_id(&self) -> BnsEvmResult<u64> {
        let value: String = self.call("eth_chainId", json!([])).await?;
        parse_quantity(&value)
    }

    pub async fn block_number(&self) -> BnsEvmResult<u64> {
        let value: String = self.call("eth_blockNumber", json!([])).await?;
        parse_quantity(&value)
    }

    pub async fn transaction_count(&self, address: Address) -> BnsEvmResult<u64> {
        let value: String = self
            .call(
                "eth_getTransactionCount",
                json!([hex_address(address), "pending"]),
            )
            .await?;
        parse_quantity(&value)
    }

    pub async fn gas_price(&self) -> BnsEvmResult<u128> {
        let value: String = self.call("eth_gasPrice", json!([])).await?;
        parse_quantity(&value).map(u128::from)
    }

    pub async fn max_priority_fee_per_gas(&self) -> BnsEvmResult<u128> {
        let value: String = self.call("eth_maxPriorityFeePerGas", json!([])).await?;
        parse_quantity(&value).map(u128::from)
    }

    /// Suggest EIP-1559 fee caps from the node's current gas price and priority
    /// fee. The doubled gas price leaves room for short-term base-fee growth.
    pub async fn suggest_eip1559_fees(&self) -> BnsEvmResult<Eip1559FeeSuggestion> {
        let gas_price = self.gas_price().await?;
        let priority_fee = self.max_priority_fee_per_gas().await?;
        Ok(Eip1559FeeSuggestion {
            max_fee_per_gas: gas_price.saturating_mul(2).saturating_add(priority_fee),
            max_priority_fee_per_gas: priority_fee,
        })
    }

    pub async fn estimate_gas(
        &self,
        from: Address,
        to: Address,
        calldata: &[u8],
    ) -> BnsEvmResult<u64> {
        let value: String = self
            .call(
                "eth_estimateGas",
                json!([{
                    "from": hex_address(from),
                    "to": hex_address(to),
                    "data": format!("0x{}", hex::encode(calldata)),
                    "value": "0x0",
                }]),
            )
            .await?;
        parse_quantity(&value)
    }

    pub async fn send_raw_transaction(&self, raw_tx: &[u8]) -> BnsEvmResult<B256> {
        let tx_hash: B256 = self
            .call(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(raw_tx))]),
            )
            .await?;
        Ok(tx_hash)
    }

    pub async fn eth_call(&self, to: Address, calldata: &[u8]) -> BnsEvmResult<Bytes> {
        let value: String = self
            .call(
                "eth_call",
                json!([{
                    "to": hex_address(to),
                    "data": format!("0x{}", hex::encode(calldata)),
                }, "latest"]),
            )
            .await?;
        parse_hex_bytes(&value).map(Bytes::from)
    }

    pub async fn call_contract<C>(&self, to: Address, call: &C) -> BnsEvmResult<C::Return>
    where
        C: SolCall,
    {
        let output = self.eth_call(to, &call.abi_encode()).await?;
        C::abi_decode_returns(&output).map_err(|err| BnsEvmError::Abi(err.to_string()))
    }

    pub async fn get_logs(&self, filter: &RpcLogFilter) -> BnsEvmResult<Vec<EthLog>> {
        self.call("eth_getLogs", json!([filter.to_rpc_value()]))
            .await
    }

    pub async fn block_by_number(&self, block_number: u64) -> BnsEvmResult<Option<EthBlock>> {
        self.call_nullable(
            "eth_getBlockByNumber",
            json!([quantity_hex(block_number), false]),
        )
        .await
    }

    pub async fn transaction_by_hash(&self, tx_hash: B256) -> BnsEvmResult<Option<EthTransaction>> {
        self.call_nullable("eth_getTransactionByHash", json!([hex_b256(tx_hash)]))
            .await
    }

    pub async fn transaction_receipt(
        &self,
        tx_hash: B256,
    ) -> BnsEvmResult<Option<EthTransactionReceipt>> {
        self.call_nullable("eth_getTransactionReceipt", json!([hex_b256(tx_hash)]))
            .await
    }

    pub async fn call<R>(&self, method: &str, params: Value) -> BnsEvmResult<R>
    where
        R: DeserializeOwned,
    {
        let value = self.call_value(method, params).await?;
        if value.is_null() {
            return Err(BnsEvmError::Rpc(
                "JSON-RPC response missing result".to_string(),
            ));
        }
        serde_json::from_value(value).map_err(|err| BnsEvmError::Rpc(err.to_string()))
    }

    pub async fn call_nullable<R>(&self, method: &str, params: Value) -> BnsEvmResult<Option<R>>
    where
        R: DeserializeOwned,
    {
        let value = self.call_value(method, params).await?;
        if value.is_null() {
            return Ok(None);
        }
        serde_json::from_value(value)
            .map(Some)
            .map_err(|err| BnsEvmError::Rpc(err.to_string()))
    }

    async fn call_value(&self, method: &str, params: Value) -> BnsEvmResult<Value> {
        let request = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };
        let response = self
            .client
            .post(&self.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|err| BnsEvmError::Rpc(err.to_string()))?
            .error_for_status()
            .map_err(|err| BnsEvmError::Rpc(err.to_string()))?
            .json::<RpcResponse>()
            .await
            .map_err(|err| BnsEvmError::Rpc(err.to_string()))?;

        if let Some(error) = response.error {
            return Err(BnsEvmError::Rpc(format!(
                "{} ({})",
                error.message, error.code
            )));
        }
        Ok(response.result)
    }
}

#[derive(Debug, Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: Value,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Value,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

fn quantity_hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn hex_address(address: Address) -> String {
    format!("{address:#x}")
}

fn hex_b256(value: B256) -> String {
    format!("{value:#x}")
}

fn parse_quantity(value: &str) -> BnsEvmResult<u64> {
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| BnsEvmError::Parse(format!("quantity `{value}` missing 0x prefix")))?;
    u64::from_str_radix(if hex.is_empty() { "0" } else { hex }, 16)
        .map_err(|err| BnsEvmError::Parse(format!("invalid quantity `{value}`: {err}")))
}

fn parse_hex_bytes(value: &str) -> BnsEvmResult<Vec<u8>> {
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| BnsEvmError::Parse(format!("hex bytes `{value}` missing 0x prefix")))?;
    if hex.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(hex)
        .map_err(|err| BnsEvmError::Parse(format!("invalid hex bytes `{value}`: {err}")))
}

fn deserialize_optional_quantity<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .as_deref()
        .map(parse_quantity)
        .transpose()
        .map_err(serde::de::Error::custom)
}
