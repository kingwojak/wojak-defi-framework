use crate::CoinsContext;
use common::HttpStatusCode;
use crypto::privkey::{key_pair_from_seed, key_pair_from_seed_with_path};
use crypto::HDPathToAccount;
use derive_more::Display;
use http::StatusCode;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use bitcoin_hashes::hex::ToHex;

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

#[derive(Debug, Display, SerializeErrorType)]
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
        }
    }
}

pub async fn offline_keys_export(
    ctx: MmArc,
    req: OfflineKeysRequest,
) -> Result<OfflineKeysResponse, MmError<OfflineKeysError>> {
    let mut result = Vec::with_capacity(req.coins.len());

    for ticker in &req.coins {
        let (coin_conf, _) = coin_conf_with_protocol(&ctx, ticker, None)
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

        let pubkey = key_pair.public().to_vec().to_hex().to_string();

        let address = format!("{}_{}_address", ticker, key_pair.public().to_vec().to_hex().to_string());

        let priv_key = key_pair.private().to_string();

        result.push(CoinKeyInfo {
            coin: ticker.clone(),
            pubkey,
            address,
            priv_key,
        });
    }

    Ok(OfflineKeysResponse { result })
}

pub async fn offline_hd_keys_export(
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
        let (coin_conf, _) = coin_conf_with_protocol(&ctx, ticker, None)
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

        for index in req.start_index..=req.end_index {
            let seed = format!("{}{}/{}_{}_{}", passphrase, ticker, index, ticker, index);
            
            let key_pair = if let Some(derivation_path) = coin_conf["derivation_path"].as_str() {
                let hd_path = format!("{}/{}", derivation_path, index);
                match key_pair_from_seed_with_path(passphrase, &hd_path) {
                    Ok(kp) => kp,
                    Err(e) => return MmError::err(OfflineKeysError::KeyDerivationFailed {
                        ticker: ticker.clone(),
                        error: format!("Failed to derive HD key at index {} with path {}: {}", index, hd_path, e),
                    }),
                }
            } else {
                match key_pair_from_seed(&seed) {
                    Ok(kp) => kp,
                    Err(e) => return MmError::err(OfflineKeysError::KeyDerivationFailed {
                        ticker: ticker.clone(),
                        error: format!("Failed to derive HD key at index {}: {}", index, e),
                    }),
                }
            };

            let pubkey = key_pair.public().to_vec().to_hex().to_string();

            let address = format!("{}_{}_{}_address", ticker, index, key_pair.public().to_vec().to_hex().to_string());

            let priv_key = key_pair.private().to_string();

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

pub async fn offline_iguana_keys_export(
    ctx: MmArc,
    req: OfflineKeysRequest,
) -> Result<OfflineKeysResponse, MmError<OfflineKeysError>> {
    let mut result = Vec::with_capacity(req.coins.len());

    for ticker in &req.coins {
        let (coin_conf, _) = coin_conf_with_protocol(&ctx, ticker, None)
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

        let pubkey = key_pair.public().to_vec().to_hex().to_string();

        let address = format!("{}_{}_address", ticker, key_pair.public().to_vec().to_hex().to_string());

        let priv_key = key_pair.private().to_string();

        result.push(CoinKeyInfo {
            coin: ticker.clone(),
            pubkey,
            address,
            priv_key,
        });
    }

    Ok(OfflineKeysResponse { result })
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
    };
    let protocol = conf["protocol"].clone();
    Ok((conf, protocol))
}
