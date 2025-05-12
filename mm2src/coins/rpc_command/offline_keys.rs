use crate::CoinsContext;
use common::HttpStatusCode;
use crypto::{derive_secp256k1_secret, DerivationPath, privkey::{key_pair_from_seed, key_pair_from_secret}};
use derive_more::Display;
use http::StatusCode;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as Json};
use bitcoin_hashes::hex::ToHex;
use std::str::FromStr;
use keys::{AddressBuilder, AddressFormat, NetworkAddressPrefixes, Private};
use bitcrypto::ChecksumType;

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
    #[display(fmt = "Invalid derivation path: {}", _0)]
    InvalidDerivationPath(String),
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
            Self::InvalidDerivationPath(_) => StatusCode::BAD_REQUEST,
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
        
        let key_pair = if let Some(derivation_path_str) = coin_conf["derivation_path"].as_str() {
            let derivation_path = DerivationPath::from_str(derivation_path_str)
                .map_err(|e| OfflineKeysError::InvalidDerivationPath(e.to_string()))?;
            
            let seed = crypto::privkey::bip39_seed_from_passphrase(passphrase)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                })?;
            
            let extended_priv_key = bip32::ExtendedPrivateKey::<secp256k1::SecretKey>::new(seed.0)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                })?;
            
            let secret = derive_secp256k1_secret(extended_priv_key, &derivation_path)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                })?;
            
            let secret_bytes = secret.as_ref();
            let mut secret_array = [0u8; 32];
            secret_array.copy_from_slice(secret_bytes);
            
            key_pair_from_secret(&secret_array)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                })?
        } else {
            key_pair_from_seed(passphrase)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                })?
        };

        let pubkey = key_pair.public().to_vec().to_hex().to_string();
        
        let is_utxo = if let Some(protocol_type) = coin_conf["protocol"]["type"].as_str() {
            protocol_type == "UTXO"
        } else {
            coin_conf["protocol"].as_str() == Some("UTXO")
        };
        
        let checksum_type = if let Some(checksum) = coin_conf["checksum_type"].as_str() {
            match checksum {
                "dgroestl512" => ChecksumType::DGROESTL512,
                "keccak256" => ChecksumType::KECCAK256,
                _ => ChecksumType::DSHA256,
            }
        } else {
            ChecksumType::DSHA256
        };
        
        let priv_key = if is_utxo {
            let wif_type = coin_conf["wiftype"].as_u64().unwrap_or(188) as u8;
            
            let private = Private {
                prefix: wif_type,
                secret: key_pair.private().secret.clone(),
                compressed: true,
                checksum_type,
            };
            
            private.to_string()
        } else {
            key_pair.private().to_string()
        };
        
        let address = if is_utxo {
            let pub_type = coin_conf["pubtype"].as_u64().unwrap_or(60) as u8;
            let p2sh_type = coin_conf["p2shtype"].as_u64().unwrap_or(85) as u8;
            
            let address_format = if coin_conf["segwit"].as_bool().unwrap_or(false) {
                AddressFormat::Segwit
            } else {
                AddressFormat::Standard
            };
            
            let hrp = if address_format.is_segwit() {
                coin_conf["bech32_hrp"].as_str().map(|s| s.to_string())
            } else {
                None
            };
            
            let address_prefixes = NetworkAddressPrefixes {
                p2pkh: [pub_type].into(),
                p2sh: [p2sh_type].into(),
            };
            
            let address = AddressBuilder::new(
                address_format,
                checksum_type,
                address_prefixes,
                hrp,
            )
            .as_pkh_from_pk(*key_pair.public())
            .build()
            .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                ticker: ticker.clone(),
                error: format!("Failed to build address: {}", e),
            })?;
            
            address.to_string()
        } else {
            format!("0x{}", key_pair.public().to_vec().to_hex().to_string())
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

        let is_utxo = if let Some(protocol_type) = coin_conf["protocol"]["type"].as_str() {
            protocol_type == "UTXO"
        } else {
            coin_conf["protocol"].as_str() == Some("UTXO")
        };
        
        let checksum_type = if let Some(checksum) = coin_conf["checksum_type"].as_str() {
            match checksum {
                "dgroestl512" => ChecksumType::DGROESTL512,
                "keccak256" => ChecksumType::KECCAK256,
                _ => ChecksumType::DSHA256,
            }
        } else {
            ChecksumType::DSHA256
        };
        
        let wif_type = coin_conf["wiftype"].as_u64().unwrap_or(188) as u8;
        let pub_type = coin_conf["pubtype"].as_u64().unwrap_or(60) as u8;
        let p2sh_type = coin_conf["p2shtype"].as_u64().unwrap_or(85) as u8;
        
        let address_format = if coin_conf["segwit"].as_bool().unwrap_or(false) {
            AddressFormat::Segwit
        } else {
            AddressFormat::Standard
        };
        
        let hrp = if address_format.is_segwit() {
            coin_conf["bech32_hrp"].as_str().map(|s| s.to_string())
        } else {
            None
        };
        
        let address_prefixes = NetworkAddressPrefixes {
            p2pkh: [pub_type].into(),
            p2sh: [p2sh_type].into(),
        };

        let seed = crypto::privkey::bip39_seed_from_passphrase(passphrase)
            .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                ticker: ticker.clone(),
                error: e.to_string(),
            })?;
        
        let extended_priv_key = bip32::ExtendedPrivateKey::<secp256k1::SecretKey>::new(seed.0)
            .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                ticker: ticker.clone(),
                error: e.to_string(),
            })?;

        for index in req.start_index..=req.end_index {
            let derivation_path_str = if let Some(base_path) = coin_conf["derivation_path"].as_str() {
                format!("{}/{}", base_path, index)
            } else {
                format!("m/44'/0'/{}'", index)
            };
            
            let derivation_path = DerivationPath::from_str(&derivation_path_str)
                .map_err(|e| OfflineKeysError::InvalidDerivationPath(e.to_string()))?;
            
            let secret = derive_secp256k1_secret(extended_priv_key.clone(), &derivation_path)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: format!("Failed to derive HD key at index {}: {}", index, e),
                })?;
            
            let secret_bytes = secret.as_ref();
            let mut secret_array = [0u8; 32];
            secret_array.copy_from_slice(secret_bytes);
            
            let key_pair = key_pair_from_secret(&secret_array)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: format!("Failed to create key pair at index {}: {}", index, e),
                })?;

            let pubkey = key_pair.public().to_vec().to_hex().to_string();
            
            let priv_key = if is_utxo {
                let private = Private {
                    prefix: wif_type,
                    secret: key_pair.private().secret.clone(),
                    compressed: true,
                    checksum_type,
                };
                
                private.to_string()
            } else {
                key_pair.private().to_string()
            };
            
            let address = if is_utxo {
                let address = AddressBuilder::new(
                    address_format.clone(),
                    checksum_type,
                    address_prefixes.clone(),
                    hrp.clone(),
                )
                .as_pkh_from_pk(*key_pair.public())
                .build()
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: format!("Failed to build address at index {}: {}", index, e),
                })?;
                
                address.to_string()
            } else {
                format!("0x{}", key_pair.public().to_vec().to_hex().to_string())
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
        
        let key_pair = if let Some(derivation_path_str) = coin_conf["derivation_path"].as_str() {
            let derivation_path = DerivationPath::from_str(derivation_path_str)
                .map_err(|e| OfflineKeysError::InvalidDerivationPath(e.to_string()))?;
            
            let seed = crypto::privkey::bip39_seed_from_passphrase(passphrase)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                })?;
            
            let extended_priv_key = bip32::ExtendedPrivateKey::<secp256k1::SecretKey>::new(seed.0)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                })?;
            
            let secret = derive_secp256k1_secret(extended_priv_key, &derivation_path)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                })?;
            
            let secret_bytes = secret.as_ref();
            let mut secret_array = [0u8; 32];
            secret_array.copy_from_slice(secret_bytes);
            
            key_pair_from_secret(&secret_array)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                })?
        } else {
            key_pair_from_seed(passphrase)
                .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                    ticker: ticker.clone(),
                    error: e.to_string(),
                })?
        };

        let pubkey = key_pair.public().to_vec().to_hex().to_string();
        
        let is_utxo = if let Some(protocol_type) = coin_conf["protocol"]["type"].as_str() {
            protocol_type == "UTXO"
        } else {
            coin_conf["protocol"].as_str() == Some("UTXO")
        };
        
        let checksum_type = if let Some(checksum) = coin_conf["checksum_type"].as_str() {
            match checksum {
                "dgroestl512" => ChecksumType::DGROESTL512,
                "keccak256" => ChecksumType::KECCAK256,
                _ => ChecksumType::DSHA256,
            }
        } else {
            ChecksumType::DSHA256
        };
        
        let priv_key = if is_utxo {
            let wif_type = coin_conf["wiftype"].as_u64().unwrap_or(188) as u8;
            
            let private = Private {
                prefix: wif_type,
                secret: key_pair.private().secret.clone(),
                compressed: true,
                checksum_type,
            };
            
            private.to_string()
        } else {
            key_pair.private().to_string()
        };
        
        let address = if is_utxo {
            let pub_type = coin_conf["pubtype"].as_u64().unwrap_or(60) as u8;
            let p2sh_type = coin_conf["p2shtype"].as_u64().unwrap_or(85) as u8;
            
            let address_format = if coin_conf["segwit"].as_bool().unwrap_or(false) {
                AddressFormat::Segwit
            } else {
                AddressFormat::Standard
            };
            
            let hrp = if address_format.is_segwit() {
                coin_conf["bech32_hrp"].as_str().map(|s| s.to_string())
            } else {
                None
            };
            
            let address_prefixes = NetworkAddressPrefixes {
                p2pkh: [pub_type].into(),
                p2sh: [p2sh_type].into(),
            };
            
            let address = AddressBuilder::new(
                address_format,
                checksum_type,
                address_prefixes,
                hrp,
            )
            .as_pkh_from_pk(*key_pair.public())
            .build()
            .map_err(|e| OfflineKeysError::KeyDerivationFailed {
                ticker: ticker.clone(),
                error: format!("Failed to build address: {}", e),
            })?;
            
            address.to_string()
        } else {
            format!("0x{}", key_pair.public().to_vec().to_hex().to_string())
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
