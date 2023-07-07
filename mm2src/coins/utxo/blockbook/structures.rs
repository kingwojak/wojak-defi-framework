use crate::utxo::utxo_block_header_storage::BlockHeaderStorage;
use crate::utxo::{GetBlockHeaderError, NonZeroU64};
use chain::TransactionInput;
use keys::Address;
use mm2_number::BigDecimal;
use rpc::v1::types::{deserialize_null_default, Bytes, RawTransaction, SignedTransactionOutput, Transaction,
                     TransactionInputEnum, TransactionOutput, TransactionOutputScript, H256};
use serde::{Deserialize, Deserializer};
use serde_json::{self as json, Value as Json};
use serialization::CoinVariant;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt::Display;
use std::sync::Arc;
use uuid::Timestamp;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BlookBookFrontendStatus {
    pub coin: String,
    pub host: String,
    pub version: String,
    #[serde(rename = "gitCommit")]
    pub git_commit: String,
    #[serde(rename = "buildTime")]
    pub build_time: String,
    #[serde(rename = "syncMode")]
    pub sync_mode: bool,
    #[serde(rename = "initialSync")]
    pub initial_sync: bool,
    #[serde(rename = "inSync")]
    pub in_sync: bool,
    #[serde(rename = "bestHeight")]
    pub best_height: u32,
    #[serde(rename = "lastBlockTime")]
    pub last_blocktime: String,
    #[serde(rename = "inSyncMempool")]
    pub in_sync_mempool: bool,
    #[serde(rename = "lastMempoolTime")]
    pub last_mempool_time: String,
    #[serde(rename = "mempoolSize")]
    pub mempool_size: u32,
    pub decimals: u8,
    #[serde(rename = "dbSize")]
    pub db_size: u64,
    pub about: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BlookBookBackendStatus {
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    #[serde(rename = "bestBlockHash")]
    pub best_block_hash: H256,
    pub difficulty: String,
    pub version: String,
    pub subversion: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_verison: String,
    #[serde(rename = "timeOffset")]
    pub time_offset: Option<u32>,
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BlookBookStatus {
    pub backend: BlookBookBackendStatus,
    pub blockbook: BlookBookFrontendStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct BlockBookTransaction {
    /// Raw transaction
    pub hex: RawTransaction,
    /// The transaction id (same as provided)
    pub txid: H256,
    /// The version
    pub version: i32,
    /// Hash of the block this transaction is included in
    #[serde(default)]
    #[serde(rename = "blockHash")]
    pub block_hash: H256,
    /// The block time in seconds since epoch (Jan 1 1970 GMT)
    #[serde(rename = "blockTime")]
    pub block_time: u32,
    /// The block height transaction mined in
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "blockHeight")]
    pub height: Option<u64>,
    /// The serialized transaction size
    pub size: Option<usize>,
    /// The virtual transaction size (differs from size for witness transactions)
    pub vsize: Option<usize>,
    /// Transaction inputs
    pub vin: Vec<TransactionInputEnum>,
    /// Transaction outputs
    pub vout: Vec<SignedTransactionOutput>,
    /// Number of confirmations of this transaction
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_null_default")]
    pub confirmations: u32,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_null_default")]
    #[serde(rename = "confirmationETABlocks")]
    pub confirmations_eta_blocks: u32,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_null_default")]
    #[serde(rename = "confirmationETASeconds")]
    pub confirmations_eta_seconds: u32,
    pub value: Option<f64>,
    #[serde(rename = "valueIn")]
    pub value_in: Option<f64>,
    pub fees: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct VShieldedSpend {
    pub cv: H256,
    pub anchor: H256,
    pub nullifier: H256,
    pub rk: H256,
    pub proof: H256,
    #[serde(rename = "spendAuthSig")]
    pub spend_auth_sig: Bytes,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct VShieldedSpendOutput {
    pub cv: H256,
    pub cmu: H256,
    #[serde(rename = "ephemeralKey")]
    pub ephemeral_key: H256,
    #[serde(rename = "encCiphertext")]
    pub enc_cipher_text: Bytes,
    #[serde(rename = "outCiphertext")]
    pub out_cipher_text: Bytes,
    #[serde(rename = "spendAuthSig")]
    pub spend_auth_sig: Bytes,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct BlockBookTransactionSpecific {
    /// Raw transaction
    pub hex: RawTransaction,
    /// The transaction id (same as provided)
    pub txid: H256,
    /// The version
    pub version: i32,
    pub overwintered: Option<bool>,
    #[serde(rename = "versiongroupid")]
    pub version_group_id: Option<String>,
    #[serde(rename = "locktime")]
    pub locktime: u32,
    #[serde(rename = "expiryHeight")]
    pub expiry_height: Option<u64>,
    pub v_join_split: Option<Vec<String>>,
    pub v_shielded_spend: Option<Vec<String>>,
    /// Hash of the block this transaction is included in
    #[serde(default)]
    #[serde(rename = "blockHash")]
    pub blockhash: H256,
    /// The block time in seconds since epoch (Jan 1 1970 GMT)
    #[serde(rename = "blocktime")]
    pub blocktime: u32,
    pub time: u32,
    /// The block height transaction mined in
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "blockHeight")]
    pub height: Option<u64>,
    /// The serialized transaction size
    pub size: Option<usize>,
    /// The virtual transaction size (differs from size for witness transactions)
    pub vsize: Option<usize>,
    /// Transaction inputs
    pub vin: Vec<TransactionInputEnum>,
    /// Transaction outputs
    pub vout: Vec<SignedTransactionOutput>,
    /// Number of confirmations of this transaction
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_null_default")]
    pub confirmations: u32,
    #[serde(rename = "bindingSig")]
    pub binding_sig: Option<Bytes>,
}

impl From<BlockBookTransactionSpecific> for Transaction {
    fn from(value: BlockBookTransactionSpecific) -> Self {
        Self {
            hex: value.hex,
            txid: value.txid,
            hash: None,
            size: value.size,
            vsize: value.vsize,
            version: value.version,
            locktime: value.locktime,
            vin: value.vin,
            vout: value.vout,
            blockhash: value.blockhash,
            confirmations: value.confirmations,
            rawconfirmations: None,
            time: value.time,
            blocktime: value.blocktime,
            height: value.height,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct BlockBookAddress {
    pub page: u32,
    #[serde(rename = "totalPages")]
    pub total_pages: u32,
    #[serde(rename = "itemsOnPge")]
    pub items_on_page: u32,
    pub address: String,
    pub balance: Option<f64>,
    #[serde(rename = "totalReceived")]
    pub total_received: Option<f64>,
    #[serde(rename = "totalSent")]
    pub total_sent: Option<f64>,
    #[serde(rename = "unconfirmedBalance")]
    pub unconfirmed_balance: Option<f64>,
    #[serde(rename = "unconfirmedTxs")]
    pub unconfirmed_txs: u32,
    pub txs: u32,
    pub txids: Vec<H256>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum GetAddressParamsDetailsEnum {
    Basic,
    Token,
    TokenBalances,
    Txids,
    Txlights,
    Txs,
}

impl ToString for GetAddressParamsDetailsEnum {
    fn to_string(&self) -> String {
        match self {
            GetAddressParamsDetailsEnum::Basic => "basic".to_string(),
            GetAddressParamsDetailsEnum::Token => "token".to_string(),
            GetAddressParamsDetailsEnum::TokenBalances => "tokenBalance".to_string(),
            GetAddressParamsDetailsEnum::Txids => "txids".to_string(),
            GetAddressParamsDetailsEnum::Txlights => "txlights".to_string(),
            GetAddressParamsDetailsEnum::Txs => "txs".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GetAddressParams {
    /// page: specifies page of returned transactions, starting from 1. If out of range, Blockbook returns the closest possible page.
    pub page: Option<u32>,
    /// pageSize: number of transactions returned by call (default and maximum 1000)
    pub page_size: Option<u32>,
    /// from, to: filter of the returned transactions from block height to block height (default no filter)
    pub from: Option<u64>,
    pub to: Option<u64>,
    /// details: specifies level of details returned by request (default txids)
    pub details: Option<GetAddressParamsDetailsEnum>,
    /// contract: return only transactions which affect specified contract (applicable only to coins which support
    /// contracts
    pub contract: Option<String>,
    /// secondary: specifies secondary (fiat) currency in which the token and total balances are returned in addition to crypto values
    pub secondary: Option<String>,
}

impl GetAddressParams {
    fn new(
        page: Option<u32>,
        page_size: Option<u32>,
        from: Option<u64>,
        to: Option<u64>,
        details: Option<GetAddressParamsDetailsEnum>,
        contract: Option<String>,
        secondary: Option<String>,
    ) -> Self {
        Self {
            page,
            page_size,
            from,
            to,
            details,
            contract,
            secondary,
        }
    }

    fn to_query_params(&self) -> String {
        let mut q = String::from("[?");
        if let Some(page) = self.page {
            q.push_str(&format!("page={page}&"));
        }
        if let Some(page) = self.page_size {
            q.push_str(&format!("pageSize={page}&"));
        }
        if let Some(from) = self.from {
            q.push_str(&format!("from={from}&"));
        }
        if let Some(to) = self.to {
            q.push_str(&format!("to={to}&"));
        }
        if let Some(details) = &self.details {
            q.push_str(&format!("details={}&", details.to_string()));
        }
        if let Some(contract) = &self.contract {
            q.push_str(&format!("contract={contract}&"));
        }
        if let Some(secondary) = &self.secondary {
            q.push_str(&format!("secondary={secondary}]"));
        }

        q
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct Tokens {
    #[serde(rename = "type")]
    pub token_type: String,
    pub name: String,
    pub path: String,
    pub decimals: u8,
    pub transfers: u32,
    pub balance: Option<f64>,
    #[serde(rename = "totalReceived")]
    pub total_received: Option<f64>,
    #[serde(rename = "totalSent")]
    pub total_sent: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct XpubTransactions {
    pub page: u32,
    #[serde(rename = "totalPages")]
    pub total_pages: u32,
    #[serde(rename = "itemsOnPge")]
    pub items_on_page: u32,
    pub address: String,
    pub balance: Option<f64>,
    #[serde(rename = "totalReceived")]
    pub total_received: Option<f64>,
    #[serde(rename = "totalSent")]
    pub total_sent: Option<f64>,
    #[serde(rename = "unconfirmedBalance")]
    pub unconfirmed_balance: Option<f64>,
    #[serde(rename = "unconfirmedTxs")]
    pub unconfirmed_txs: u32,
    pub txs: u32,
    pub txids: Vec<H256>,
    #[serde(rename = "usedTokens")]
    pub used_tokens: u16,
    #[serde(default)]
    pub tokens: Vec<Tokens>,
    #[serde(default)]
    pub secondary_value: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct BlockBookUtxo {
    pub txid: H256,
    pub vout: u32,
    pub value: Option<f64>,
    pub confirmations: u32,
    #[serde(rename = "locktime")]
    pub lock_time: u32,
}

#[derive(Debug)]
pub struct GetBlockByHashHeight<T: Clone>(T);

impl<T: Clone + Display> GetBlockByHashHeight<T> {
    pub fn get_inner(&self) -> T { self.0.clone() }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct BlockBookBlock {
    pub page: u32,
    #[serde(rename = "totalPages")]
    pub total_pages: u32,
    #[serde(rename = "itemsOnPge")]
    pub items_on_page: u32,
    #[serde(default)]
    #[serde(rename = "blockHash")]
    pub block_hash: H256,
    #[serde(default)]
    #[serde(rename = "previousBlockHash")]
    pub previous_block_hash: Option<H256>,
    #[serde(default)]
    #[serde(rename = "nextBlockHash")]
    pub next_block_hash: Option<H256>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "blockHeight")]
    pub height: Option<u64>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_null_default")]
    pub confirmations: u32,
    pub size: Option<usize>,
    pub time: u32,
    /// The version
    pub version: i32,
    #[serde(default)]
    #[serde(rename = "merkleRoot")]
    pub merkle_root: H256,
    pub nounce: u32,
    pub bits: String,
    pub difficulty: String,
    pub tx_count: u32,
    pub txs: Vec<BlockBookTransaction>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct BlockBookTickersList {
    pub ts: u64,
    pub available_currencies: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "test", serde(deny_unknown_fields))]
pub struct BlockBookTickers {
    pub ts: u64,
    pub rates: HashMap<String, f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockBookBalanceHistory {
    pub time: u32,
    pub txs: u32,
    pub received: Option<f64>,
    pub sent: Option<f64>,
    #[serde(rename = "sentToSelf")]
    pub sent_to_self: Option<f64>,
    pub rates: HashMap<String, f64>,
}

pub struct BalanceHistoryParams {
    /// from: specifies a start date as a Unix timestamp
    from: Option<u32>,
    /// to: specifies an end date as a Unix timestamp
    to: Option<u32>,
    /// fiatcurrency: if specified, the response will contain secondary (fiat) rate at the time of transaction. If not, all available currencies will be returned.
    currency: Option<String>,
    /// groupBy: an interval in seconds, to group results by. Default is 3600 seconds.
    group_by: Option<u32>,
}

impl BalanceHistoryParams {
    pub fn new(from: Option<u32>, to: Option<u32>, currency: Option<String>, group_by: Option<u32>) -> Self {
        Self {
            from,
            to,
            currency,
            group_by,
        }
    }

    pub fn to_query_params(&self) -> String {
        let mut q = String::from("?");

        if let Some(from) = self.from {
            q.push_str(&format!("from={from}&"));
        };
        if let Some(to) = self.to {
            q.push_str(&format!("to={to}"));
        };
        if let Some(currency) = &self.currency {
            q.push_str(&format!("[fiatcurrency={currency}&"));
        };
        if let Some(group_by) = &self.group_by {
            q.push_str(&format!("[groupBy={group_by}]"));
        };

        q
    }
}
