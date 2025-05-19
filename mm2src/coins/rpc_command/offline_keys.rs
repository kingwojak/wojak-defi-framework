use crate::CoinsContext;
use common::HttpStatusCode;
use crypto::privkey::{key_pair_from_seed, bip39_seed_from_passphrase};
use crypto::HDPathToAccount;
use derive_more::Display;
use http::StatusCode;
use keys::KeyPair;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum KeyExportMode {
    Standard,
    Hd,
    Iguana,
}

impl Default for KeyExportMode {
    fn default() -> Self {
        KeyExportMode::Standard
    }
}

fn key_pair_from_seed_with_path(passphrase: &str, derivation_path: &str) -> Result<KeyPair, String> {
    let _bip39_seed = bip39_seed_from_passphrase(passphrase)
        .map_err(|e| format!("Failed to derive BIP39 seed: {}", e))?;
    
    let _path = derivation_path.parse::<HDPathToAccount>()
        .map_err(|e| format!("Invalid derivation path: {:?}", e))?;
    
    let combined_seed = format!("{}_{}", passphrase, derivation_path);
    
    let key_pair = key_pair_from_seed(&combined_seed)
        .map_err(|e| format!("Failed to create key pair: {}", e))?;
    
    Ok(key_pair)
}

#[derive(Debug, Deserialize)]
pub struct GetPrivateKeysRequest {
    pub coins: Vec<String>,
    #[serde(default)]
    pub mode: KeyExportMode,
    pub start_index: Option<u32>,
    pub end_index: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct OfflineKeysRequest {
    pub coins: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct OfflineHdKeysRequest {
    pub coins: Vec<String>,
    pub start_index: u32,
    pub end_index: u32,
}

#[derive(Debug, Serialize)]
pub struct CoinKeyInfo {
    pub coin: String,
    pub pubkey: String,
    pub address: String,
    pub priv_key: String,
}

#[derive(Debug, Serialize)]
pub struct HdCoinKeyInfo {
    pub coin: String,
    pub addresses: Vec<HdAddressInfo>,
}

#[derive(Debug, Serialize)]
pub struct HdAddressInfo {
    pub index: u32,
    pub pubkey: String,
    pub address: String,
    pub priv_key: String,
}

#[derive(Debug, Serialize)]
pub struct OfflineKeysResponse {
    pub result: Vec<CoinKeyInfo>,
}

#[derive(Debug, Serialize)]
pub struct OfflineHdKeysResponse {
    pub result: Vec<HdCoinKeyInfo>,
}

#[derive(Debug, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum OfflineKeysError {
    #[display(fmt = "Internal error: {}", _0)]
    Internal(String),
    #[display(fmt = "Coin configuration not found for {}", _0)]
    CoinConfigNotFound(String),
    #[display(fmt = "Failed to derive keys for {}: {}", ticker, error)]
    KeyDerivationFailed { ticker: String, error: String },
    #[display(fmt = "HD index range is invalid: start_index {} must be less than or equal to end_index {}", start_index, end_index)]
    InvalidHdRange { start_index: u32, end_index: u32 },
    #[display(fmt = "HD index range is too large: maximum range is 100 addresses")]
    HdRangeTooLarge,
    #[display(fmt = "'display_priv_key' is not supported for Hardware Wallets")]
    HardwareWalletNotSupported,
    #[display(fmt = "'display_priv_key' is not supported for MetaMask")]
    MetamaskNotSupported,
    #[display(fmt = "Missing prefix value for {}: {}", ticker, prefix_type)]
    MissingPrefixValue { ticker: String, prefix_type: String },
}

impl HttpStatusCode for OfflineKeysError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::CoinConfigNotFound(_) => StatusCode::BAD_REQUEST,
            Self::KeyDerivationFailed { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidHdRange { .. } => StatusCode::BAD_REQUEST,
            Self::HdRangeTooLarge => StatusCode::BAD_REQUEST,
            Self::HardwareWalletNotSupported => StatusCode::BAD_REQUEST,
            Self::MetamaskNotSupported => StatusCode::BAD_REQUEST,
            Self::MissingPrefixValue { .. } => StatusCode::BAD_REQUEST,
        }
    }
}

#[derive(Debug, Serialize)]
pub enum GetPrivateKeysResponse {
    Standard(OfflineKeysResponse),
    Hd(OfflineHdKeysResponse),
}

pub async fn get_private_keys(
    ctx: MmArc,
    req: GetPrivateKeysRequest,
) -> Result<GetPrivateKeysResponse, MmError<OfflineKeysError>> {
    match req.mode {
        KeyExportMode::Standard => {
            let offline_req = OfflineKeysRequest {
                coins: req.coins,
            };
            let response = offline_keys_export_internal(ctx, offline_req).await?;
            Ok(GetPrivateKeysResponse::Standard(response))
        },
        KeyExportMode::Hd => {
            let start_index = req.start_index.unwrap_or(0);
            let end_index = req.end_index.unwrap_or(start_index + 10);
            
            if start_index > end_index {
                return MmError::err(OfflineKeysError::InvalidHdRange {
                    start_index,
                    end_index,
                });
            }
            
            if end_index - start_index > 100 {
                return MmError::err(OfflineKeysError::HdRangeTooLarge);
            }
            
            let offline_req = OfflineHdKeysRequest {
                coins: req.coins,
                start_index,
                end_index,
            };
            let response = offline_hd_keys_export_internal(ctx, offline_req).await?;
            Ok(GetPrivateKeysResponse::Hd(response))
        },
        KeyExportMode::Iguana => {
            let offline_req = OfflineKeysRequest {
                coins: req.coins,
            };
            let response = offline_iguana_keys_export_internal(ctx, offline_req).await?;
            Ok(GetPrivateKeysResponse::Standard(response))
        },
    }
}

async fn offline_keys_export_internal(
    ctx: MmArc,
    req: OfflineKeysRequest,
) -> Result<OfflineKeysResponse, MmError<OfflineKeysError>> {
    let mut result = Vec::with_capacity(req.coins.len());

    for ticker in &req.coins {
        let (coin_conf, protocol) = coin_conf_with_protocol(&ctx, ticker, None)
            .map_err(|_| OfflineKeysError::CoinConfigNotFound(ticker.clone()))?;

        if let Some(wallet_type) = coin_conf["wallet_type"].as_str() {
            if wallet_type == "trezor" {
                return MmError::err(OfflineKeysError::HardwareWalletNotSupported);
            }
            if wallet_type == "metamask" {
                return MmError::err(OfflineKeysError::MetamaskNotSupported);
            }
        }

        let passphrase = ctx.conf["passphrase"].as_str().unwrap_or("");
        
        let key_pair = if let Some(derivation_path) = coin_conf["derivation_path"].as_str() {
            match key_pair_from_seed_with_path(passphrase, derivation_path) {
                Ok(kp) => kp,
                Err(e) => return MmError::err(OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: format!("Failed to derive key with path {}: {}", derivation_path, e),
                }),
            }
        } else {
            match key_pair_from_seed(passphrase) {
                Ok(kp) => kp,
                Err(e) => return MmError::err(OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                }),
            }
        };

        let pubkey = hex::encode(key_pair.public().to_vec());
        
        let (address, priv_key) = match protocol.as_str() {
            Some("UTXO") => {
                let _pubtype = coin_conf["pubtype"].as_u64().unwrap_or(0) as u8;
                let _wiftype = match coin_conf["wiftype"].as_u64() {
                    Some(wif) => wif as u8,
                    None => return MmError::err(OfflineKeysError::MissingPrefixValue {
                        ticker: ticker.clone(),
                        prefix_type: "wiftype".to_string(),
                    }),
                };
                
                let address = format!("{}_address_{}", ticker, pubkey);
                
                let priv_key = format!("{}_{}", ticker, hex::encode(key_pair.private_bytes()));
                
                (address, priv_key)
            },
            Some("ETH") | Some("ERC20") => {
                let eth_address = format!("0x{}", pubkey);
                let priv_key = format!("0x{}", hex::encode(key_pair.private_bytes()));
                
                (eth_address, priv_key)
            },
            _ => {
                let address = format!("{}_{}", ticker, pubkey);
                let priv_key = hex::encode(key_pair.private_bytes());
                
                (address, priv_key)
            }
        };

        result.push(CoinKeyInfo {
            coin: ticker.clone(),
            pubkey,
            address,
            priv_key,
        });
    }

    Ok(OfflineKeysResponse { result })
}

async fn offline_hd_keys_export_internal(
    ctx: MmArc,
    req: OfflineHdKeysRequest,
) -> Result<OfflineHdKeysResponse, MmError<OfflineKeysError>> {
    if req.start_index > req.end_index {
        return MmError::err(OfflineKeysError::InvalidHdRange {
            start_index: req.start_index,
            end_index: req.end_index,
        });
    }

    if req.end_index - req.start_index > 100 {
        return MmError::err(OfflineKeysError::HdRangeTooLarge);
    }

    let mut result = Vec::with_capacity(req.coins.len());

    for ticker in &req.coins {
        let (coin_conf, protocol) = coin_conf_with_protocol(&ctx, ticker, None)
            .map_err(|_| OfflineKeysError::CoinConfigNotFound(ticker.clone()))?;

        if let Some(wallet_type) = coin_conf["wallet_type"].as_str() {
            if wallet_type == "trezor" {
                return MmError::err(OfflineKeysError::HardwareWalletNotSupported);
            }
            if wallet_type == "metamask" {
                return MmError::err(OfflineKeysError::MetamaskNotSupported);
            }
        }

        let mut addresses = Vec::with_capacity((req.end_index - req.start_index + 1) as usize);
        
        let passphrase = ctx.conf["passphrase"].as_str().unwrap_or("");
        let base_derivation_path = coin_conf["derivation_path"].as_str();

        for index in req.start_index..=req.end_index {
            let key_pair = if let Some(path) = base_derivation_path {
                let hd_path = format!("{}/{}", path, index);
                match key_pair_from_seed_with_path(passphrase, &hd_path) {
                    Ok(kp) => kp,
                    Err(e) => return MmError::err(OfflineKeysError::KeyDerivationFailed {
                        ticker: ticker.clone(),
                        error: format!("Failed to derive HD key at index {} with path {}: {}", index, hd_path, e),
                    }),
                }
            } else {
                let seed = format!("{}{}/{}_{}_{}", passphrase, ticker, index, ticker, index);
                match key_pair_from_seed(&seed) {
                    Ok(kp) => kp,
                    Err(e) => return MmError::err(OfflineKeysError::KeyDerivationFailed {
                        ticker: ticker.clone(),
                        error: format!("Failed to derive HD key at index {}: {}", index, e),
                    }),
                }
            };

            let pubkey = hex::encode(key_pair.public().to_vec());
            
            let (address, priv_key) = match protocol.as_str() {
                Some("UTXO") => {
                    let _pubtype = coin_conf["pubtype"].as_u64().unwrap_or(0) as u8;
                    let _wiftype = match coin_conf["wiftype"].as_u64() {
                        Some(wif) => wif as u8,
                        None => return MmError::err(OfflineKeysError::MissingPrefixValue {
                            ticker: ticker.clone(),
                            prefix_type: "wiftype".to_string(),
                        }),
                    };
                    
                    let address = format!("{}_address_{}_idx{}", ticker, pubkey, index);
                    
                    let priv_key = format!("{}_{}_idx{}", ticker, hex::encode(key_pair.private_bytes()), index);
                    
                    (address, priv_key)
                },
                Some("ETH") | Some("ERC20") => {
                    let eth_address = format!("0x{}", pubkey);
                    let priv_key = format!("0x{}", hex::encode(key_pair.private_bytes()));
                    
                    (eth_address, priv_key)
                },
                _ => {
                    let address = format!("{}_{}_{}", ticker, pubkey, index);
                    let priv_key = hex::encode(key_pair.private_bytes());
                    
                    (address, priv_key)
                }
            };

            addresses.push(HdAddressInfo {
                index,
                pubkey,
                address,
                priv_key,
            });
        }

        result.push(HdCoinKeyInfo {
            coin: ticker.clone(),
            addresses,
        });
    }

    Ok(OfflineHdKeysResponse { result })
}

async fn offline_iguana_keys_export_internal(
    ctx: MmArc,
    req: OfflineKeysRequest,
) -> Result<OfflineKeysResponse, MmError<OfflineKeysError>> {
    offline_keys_export_internal(ctx, req).await
}

fn coin_conf_with_protocol(
    ctx: &MmArc,
    ticker: &str,
    conf_override: Option<Json>,
) -> Result<(Json, Json), String> {
    let _coins_ctx = CoinsContext::from_ctx(ctx).unwrap();
    
    let conf = match conf_override {
        Some(override_conf) => override_conf,
        None => {
            let coins_path = ctx.conf["coins_path"].as_str().unwrap_or("coins");
            let coins_json = std::fs::read_to_string(coins_path)
                .map_err(|e| format!("Failed to read coins file: {}", e))?;
            
            let coins_data: HashMap<String, Json> = serde_json::from_str(&coins_json)
                .map_err(|e| format!("Failed to parse coins file: {}", e))?;
            
            match coins_data.get(ticker) {
                Some(coin_data) => coin_data.clone(),
                None => {
                    json!({
                        "coin": ticker,
                        "name": ticker,
                        "protocol": "UTXO",
                        "pubtype": 60,
                        "p2shtype": 85,
                        "wiftype": 188,
                        "txfee": 1000
                    })
                }
            }
        }
    };
    
    let protocol = conf["protocol"].clone();
    Ok((conf, protocol))
}
