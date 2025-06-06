use super::*;
use crate::eth::erc20::{get_enabled_erc20_by_contract, get_token_decimals};
use crate::eth::web3_transport::http_transport::HttpTransport;
use crate::hd_wallet::{load_hd_accounts_from_storage, HDAccountsMutex, HDPathAccountToAddressId, HDWalletCoinStorage,
                       HDWalletStorageError, DEFAULT_GAP_LIMIT};
use crate::nft::get_nfts_for_activation;
use crate::nft::nft_errors::{GetNftInfoError, ParseChainTypeError};
use crate::nft::nft_structs::Chain;
#[cfg(target_arch = "wasm32")] use crate::EthMetamaskPolicy;
use common::executor::AbortedError;
use compatible_time::Instant;
use crypto::{trezor::TrezorError, Bip32Error, CryptoCtxError, HwError};
use enum_derives::EnumFromTrait;
use mm2_err_handle::common_errors::WithInternal;
#[cfg(target_arch = "wasm32")]
use mm2_metamask::{from_metamask_error, MetamaskError, MetamaskRpcError, WithMetamaskRpcError};
use mm2_p2p::p2p_ctx::P2PContext;
use proxy_signature::RawMessage;
use rpc_task::RpcTaskError;
use std::sync::atomic::Ordering;
use url::Url;
use web3_transport::websocket_transport::WebsocketTransport;

#[derive(Clone, Debug, Deserialize, Display, EnumFromTrait, PartialEq, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum EthActivationV2Error {
    InvalidPayload(String),
    InvalidSwapContractAddr(String),
    InvalidFallbackSwapContract(String),
    InvalidPathToAddress(String),
    #[display(fmt = "`chain_id` should be set for evm coins or tokens")]
    ChainIdNotSet,
    #[display(fmt = "Platform coin {} activation failed. {}", ticker, error)]
    ActivationFailed {
        ticker: String,
        error: String,
    },
    CouldNotFetchBalance(String),
    UnreachableNodes(String),
    #[display(fmt = "Enable request for ETH coin must have at least 1 node")]
    AtLeastOneNodeRequired,
    #[display(fmt = "Error deserializing 'derivation_path': {}", _0)]
    ErrorDeserializingDerivationPath(String),
    PrivKeyPolicyNotAllowed(PrivKeyPolicyNotAllowed),
    #[display(fmt = "Failed spawning balance events. Error: {_0}")]
    FailedSpawningBalanceEvents(String),
    HDWalletStorageError(String),
    #[cfg(target_arch = "wasm32")]
    #[from_trait(WithMetamaskRpcError::metamask_rpc_error)]
    #[display(fmt = "{}", _0)]
    MetamaskError(MetamaskRpcError),
    #[from_trait(WithInternal::internal)]
    #[display(fmt = "Internal: {}", _0)]
    InternalError(String),
    Transport(String),
    UnexpectedDerivationMethod(UnexpectedDerivationMethod),
    CoinDoesntSupportTrezor,
    HwContextNotInitialized,
    #[display(fmt = "Initialization task has timed out {:?}", duration)]
    TaskTimedOut {
        duration: Duration,
    },
    HwError(HwRpcError),
    #[display(fmt = "Hardware wallet must be called within rpc task framework")]
    InvalidHardwareWalletCall,
    #[display(fmt = "Custom token error: {}", _0)]
    CustomTokenError(CustomTokenError),
}

impl From<MyAddressError> for EthActivationV2Error {
    fn from(err: MyAddressError) -> Self { Self::InternalError(err.to_string()) }
}

impl From<AbortedError> for EthActivationV2Error {
    fn from(e: AbortedError) -> Self { EthActivationV2Error::InternalError(e.to_string()) }
}

impl From<CryptoCtxError> for EthActivationV2Error {
    fn from(e: CryptoCtxError) -> Self { EthActivationV2Error::InternalError(e.to_string()) }
}

impl From<UnexpectedDerivationMethod> for EthActivationV2Error {
    fn from(e: UnexpectedDerivationMethod) -> Self { EthActivationV2Error::InternalError(e.to_string()) }
}

impl From<EthTokenActivationError> for EthActivationV2Error {
    fn from(e: EthTokenActivationError) -> Self {
        match e {
            EthTokenActivationError::InternalError(err) => EthActivationV2Error::InternalError(err),
            EthTokenActivationError::CouldNotFetchBalance(err) => EthActivationV2Error::CouldNotFetchBalance(err),
            EthTokenActivationError::InvalidPayload(err) => EthActivationV2Error::InvalidPayload(err),
            EthTokenActivationError::Transport(err) | EthTokenActivationError::ClientConnectionFailed(err) => {
                EthActivationV2Error::Transport(err)
            },
            EthTokenActivationError::UnexpectedDerivationMethod(err) => {
                EthActivationV2Error::UnexpectedDerivationMethod(err)
            },
            EthTokenActivationError::PrivKeyPolicyNotAllowed(e) => EthActivationV2Error::PrivKeyPolicyNotAllowed(e),
            EthTokenActivationError::CustomTokenError(e) => EthActivationV2Error::CustomTokenError(e),
        }
    }
}

impl From<HDWalletStorageError> for EthActivationV2Error {
    fn from(e: HDWalletStorageError) -> Self { EthActivationV2Error::HDWalletStorageError(e.to_string()) }
}

impl From<HwError> for EthActivationV2Error {
    fn from(e: HwError) -> Self { EthActivationV2Error::InternalError(e.to_string()) }
}

impl From<Bip32Error> for EthActivationV2Error {
    fn from(e: Bip32Error) -> Self { EthActivationV2Error::InternalError(e.to_string()) }
}

impl From<TrezorError> for EthActivationV2Error {
    fn from(e: TrezorError) -> Self { EthActivationV2Error::InternalError(e.to_string()) }
}

impl From<RpcTaskError> for EthActivationV2Error {
    fn from(rpc_err: RpcTaskError) -> Self {
        match rpc_err {
            RpcTaskError::Timeout(duration) => EthActivationV2Error::TaskTimedOut { duration },
            internal_error => EthActivationV2Error::InternalError(internal_error.to_string()),
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl From<MetamaskError> for EthActivationV2Error {
    fn from(e: MetamaskError) -> Self { from_metamask_error(e) }
}

impl From<ParseChainTypeError> for EthActivationV2Error {
    fn from(e: ParseChainTypeError) -> Self { EthActivationV2Error::InternalError(e.to_string()) }
}

impl From<String> for EthActivationV2Error {
    fn from(e: String) -> Self { EthActivationV2Error::InternalError(e) }
}

impl From<EnableCoinBalanceError> for EthActivationV2Error {
    fn from(e: EnableCoinBalanceError) -> Self {
        match e {
            EnableCoinBalanceError::NewAddressDerivingError(err) => {
                EthActivationV2Error::InternalError(err.to_string())
            },
            EnableCoinBalanceError::NewAccountCreationError(err) => {
                EthActivationV2Error::InternalError(err.to_string())
            },
            EnableCoinBalanceError::BalanceError(err) => EthActivationV2Error::CouldNotFetchBalance(err.to_string()),
        }
    }
}

/// An alternative to `crate::PrivKeyActivationPolicy`, typical only for ETH coin.
#[derive(Clone, Deserialize, Default)]
pub enum EthPrivKeyActivationPolicy {
    #[default]
    ContextPrivKey,
    Trezor,
    #[cfg(target_arch = "wasm32")]
    Metamask,
}

impl EthPrivKeyActivationPolicy {
    pub fn is_hw_policy(&self) -> bool { matches!(self, EthPrivKeyActivationPolicy::Trezor) }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub enum EthRpcMode {
    #[default]
    Default,
    #[cfg(target_arch = "wasm32")]
    Metamask,
}

#[derive(Clone, Deserialize)]
pub struct EthActivationV2Request {
    #[serde(default)]
    pub nodes: Vec<EthNode>,
    #[serde(default)]
    pub rpc_mode: EthRpcMode,
    pub swap_contract_address: Address,
    #[serde(default)]
    pub swap_v2_contracts: Option<SwapV2Contracts>,
    pub fallback_swap_contract: Option<Address>,
    #[serde(default)]
    pub contract_supports_watchers: bool,
    pub mm2: Option<u8>,
    pub required_confirmations: Option<u64>,
    #[serde(default)]
    pub priv_key_policy: EthPrivKeyActivationPolicy,
    #[serde(flatten)]
    pub enable_params: EnabledCoinBalanceParams,
    #[serde(default)]
    pub path_to_address: HDPathAccountToAddressId,
    pub gap_limit: Option<u32>,
}

#[derive(Clone, Deserialize)]
pub struct EthNode {
    pub url: String,
    #[serde(default)]
    pub komodo_proxy: bool,
}

#[derive(Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum EthTokenActivationError {
    InternalError(String),
    ClientConnectionFailed(String),
    CouldNotFetchBalance(String),
    InvalidPayload(String),
    Transport(String),
    UnexpectedDerivationMethod(UnexpectedDerivationMethod),
    PrivKeyPolicyNotAllowed(PrivKeyPolicyNotAllowed),
    CustomTokenError(CustomTokenError),
}

impl From<AbortedError> for EthTokenActivationError {
    fn from(e: AbortedError) -> Self { EthTokenActivationError::InternalError(e.to_string()) }
}

impl From<MyAddressError> for EthTokenActivationError {
    fn from(err: MyAddressError) -> Self { Self::InternalError(err.to_string()) }
}

impl From<UnexpectedDerivationMethod> for EthTokenActivationError {
    fn from(e: UnexpectedDerivationMethod) -> Self { EthTokenActivationError::UnexpectedDerivationMethod(e) }
}

impl From<GetNftInfoError> for EthTokenActivationError {
    fn from(e: GetNftInfoError) -> Self {
        match e {
            GetNftInfoError::InvalidRequest(err) => EthTokenActivationError::InvalidPayload(err),
            GetNftInfoError::ContractTypeIsNull => EthTokenActivationError::InvalidPayload(
                "The contract type is required and should not be null.".to_string(),
            ),
            GetNftInfoError::Transport(err) | GetNftInfoError::InvalidResponse(err) => {
                EthTokenActivationError::Transport(err)
            },
            GetNftInfoError::Internal(err) | GetNftInfoError::DbError(err) | GetNftInfoError::NumConversError(err) => {
                EthTokenActivationError::InternalError(err)
            },
            GetNftInfoError::GetEthAddressError(err) => EthTokenActivationError::InternalError(err.to_string()),
            GetNftInfoError::ParseRfc3339Err(err) => EthTokenActivationError::InternalError(err.to_string()),
            GetNftInfoError::ProtectFromSpamError(err) => EthTokenActivationError::InternalError(err.to_string()),
            GetNftInfoError::TransferConfirmationsError(err) => EthTokenActivationError::InternalError(err.to_string()),
            GetNftInfoError::TokenNotFoundInWallet {
                token_address,
                token_id,
            } => EthTokenActivationError::InternalError(format!(
                "Token not found in wallet: {}, {}",
                token_address, token_id
            )),
        }
    }
}

impl From<ParseChainTypeError> for EthTokenActivationError {
    fn from(e: ParseChainTypeError) -> Self { EthTokenActivationError::InternalError(e.to_string()) }
}

impl From<String> for EthTokenActivationError {
    fn from(e: String) -> Self { EthTokenActivationError::InternalError(e) }
}

impl From<PrivKeyPolicyNotAllowed> for EthTokenActivationError {
    fn from(e: PrivKeyPolicyNotAllowed) -> Self { EthTokenActivationError::PrivKeyPolicyNotAllowed(e) }
}

impl From<GenerateSignedMessageError> for EthTokenActivationError {
    fn from(e: GenerateSignedMessageError) -> Self {
        match e {
            GenerateSignedMessageError::InternalError(e) => EthTokenActivationError::InternalError(e),
            GenerateSignedMessageError::PrivKeyPolicyNotAllowed(e) => {
                EthTokenActivationError::PrivKeyPolicyNotAllowed(e)
            },
        }
    }
}

#[derive(Display, Serialize)]
pub enum GenerateSignedMessageError {
    #[display(fmt = "Internal: {}", _0)]
    InternalError(String),
    PrivKeyPolicyNotAllowed(PrivKeyPolicyNotAllowed),
}

impl From<PrivKeyPolicyNotAllowed> for GenerateSignedMessageError {
    fn from(e: PrivKeyPolicyNotAllowed) -> Self { GenerateSignedMessageError::PrivKeyPolicyNotAllowed(e) }
}

impl From<SignatureError> for GenerateSignedMessageError {
    fn from(e: SignatureError) -> Self { GenerateSignedMessageError::InternalError(e.to_string()) }
}

/// Represents the parameters required for activating either an ERC-20 token or an NFT on the Ethereum platform.
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum EthTokenActivationParams {
    Nft(NftActivationRequest),
    Erc20(Erc20TokenActivationRequest),
}

/// Holds ERC-20 token-specific activation parameters, including optional confirmation requirements.
#[derive(Clone, Deserialize)]
pub struct Erc20TokenActivationRequest {
    pub required_confirmations: Option<u64>,
}

/// Holds ERC-20 token-specific activation parameters when using the task manager for activation.
#[derive(Clone, Deserialize)]
pub struct InitErc20TokenActivationRequest {
    /// The number of confirmations required for swap transactions.
    pub required_confirmations: Option<u64>,
    /// Parameters for HD wallet account and addresses initialization.
    #[serde(flatten)]
    pub enable_params: EnabledCoinBalanceParams,
    /// This determines which Address of the HD account to be used for swaps for this Token.
    /// If not specified, the first non-change address for the first account is used.
    #[serde(default)]
    pub path_to_address: HDPathAccountToAddressId,
}

impl From<InitErc20TokenActivationRequest> for Erc20TokenActivationRequest {
    fn from(req: InitErc20TokenActivationRequest) -> Self {
        Erc20TokenActivationRequest {
            required_confirmations: req.required_confirmations,
        }
    }
}

/// Encapsulates the request parameters for NFT activation, specifying the provider to be used.
#[derive(Clone, Deserialize)]
pub struct NftActivationRequest {
    pub provider: NftProviderEnum,
}

/// Defines available NFT providers and their configuration.
#[derive(Clone, Deserialize)]
#[serde(tag = "type", content = "info")]
pub enum NftProviderEnum {
    Moralis {
        url: Url,
        #[serde(default)]
        komodo_proxy: bool,
    },
}

/// Represents the protocol type for an Ethereum-based token, distinguishing between ERC-20 tokens and NFTs.
pub enum EthTokenProtocol {
    Erc20(Erc20Protocol),
    Nft(NftProtocol),
}

/// Details for an ERC-20 token protocol.
#[derive(Clone)]
pub struct Erc20Protocol {
    pub platform: String,
    pub token_addr: Address,
}

impl From<Erc20Protocol> for CoinProtocol {
    fn from(erc20_protocol: Erc20Protocol) -> Self {
        CoinProtocol::ERC20 {
            platform: erc20_protocol.platform,
            contract_address: erc20_protocol.token_addr.to_string(),
        }
    }
}

/// Details for an NFT protocol.
#[derive(Debug)]
pub struct NftProtocol {
    pub platform: String,
}

#[cfg_attr(test, mockable)]
impl EthCoin {
    pub async fn initialize_erc20_token(
        &self,
        ticker: String,
        activation_params: Erc20TokenActivationRequest,
        token_conf: Json,
        protocol: Erc20Protocol,
        is_custom: bool,
    ) -> MmResult<EthCoin, EthTokenActivationError> {
        // TODO
        // Check if ctx is required.
        // Remove it to avoid circular references if possible
        let ctx = MmArc::from_weak(&self.ctx)
            .ok_or_else(|| String::from("No context"))
            .map_err(EthTokenActivationError::InternalError)?;

        // Todo: when custom token config storage is added, this might not be needed
        // `is_custom` was added to avoid this unnecessary check for non-custom tokens
        if is_custom {
            match get_enabled_erc20_by_contract(&ctx, protocol.token_addr).await {
                Ok(Some(token)) => {
                    return MmError::err(EthTokenActivationError::CustomTokenError(
                        CustomTokenError::TokenWithSameContractAlreadyActivated {
                            ticker: token.ticker().to_string(),
                            contract_address: protocol.token_addr.display_address(),
                        },
                    ));
                },
                Ok(None) => {},
                Err(e) => return MmError::err(EthTokenActivationError::InternalError(e.to_string())),
            }
        }

        let decimals = match token_conf["decimals"].as_u64() {
            None | Some(0) => get_token_decimals(
                &self
                    .web3()
                    .await
                    .map_err(|e| EthTokenActivationError::ClientConnectionFailed(e.to_string()))?,
                protocol.token_addr,
            )
            .await
            .map_err(EthTokenActivationError::InternalError)?,
            Some(d) => d as u8,
        };

        let required_confirmations = activation_params
            .required_confirmations
            .unwrap_or_else(|| {
                token_conf["required_confirmations"]
                    .as_u64()
                    .unwrap_or(self.required_confirmations())
            })
            .into();

        // Create an abortable system linked to the `MmCtx` so if the app is stopped on `MmArc::stop`,
        // all spawned futures related to `ERC20` coin will be aborted as well.
        let abortable_system = ctx.abortable_system.create_subsystem()?;

        let coin_type = EthCoinType::Erc20 {
            platform: protocol.platform,
            token_addr: protocol.token_addr,
        };
        let max_eth_tx_type = get_max_eth_tx_type_conf(&ctx, &token_conf, &coin_type).await?;
        let gas_limit: EthGasLimit = extract_gas_limit_from_conf(&token_conf)
            .map_to_mm(|e| EthTokenActivationError::InternalError(format!("invalid gas_limit config {}", e)))?;
        let gas_limit_v2: EthGasLimitV2 = extract_gas_limit_from_conf(&token_conf)
            .map_to_mm(|e| EthTokenActivationError::InternalError(format!("invalid gas_limit config {}", e)))?;

        let token = EthCoinImpl {
            priv_key_policy: self.priv_key_policy.clone(),
            // We inherit the derivation method from the parent/platform coin
            // If we want a new wallet for each token we can add this as an option in the future
            // storage ticker will be the platform coin ticker
            derivation_method: self.derivation_method.clone(),
            coin_type,
            sign_message_prefix: self.sign_message_prefix.clone(),
            swap_contract_address: self.swap_contract_address,
            swap_v2_contracts: self.swap_v2_contracts,
            fallback_swap_contract: self.fallback_swap_contract,
            contract_supports_watchers: self.contract_supports_watchers,
            decimals,
            ticker,
            web3_instances: AsyncMutex::new(self.web3_instances.lock().await.clone()),
            history_sync_state: Mutex::new(self.history_sync_state.lock().unwrap().clone()),
            swap_txfee_policy: Mutex::new(SwapTxFeePolicy::Internal),
            max_eth_tx_type,
            ctx: self.ctx.clone(),
            required_confirmations,
            chain_id: self.chain_id,
            trezor_coin: self.trezor_coin.clone(),
            logs_block_range: self.logs_block_range,
            address_nonce_locks: self.address_nonce_locks.clone(),
            erc20_tokens_infos: Default::default(),
            nfts_infos: Default::default(),
            gas_limit,
            gas_limit_v2,
            abortable_system,
        };

        Ok(EthCoin(Arc::new(token)))
    }

    /// Initializes a Global NFT instance for a specific blockchain platform (e.g., Ethereum, Polygon).
    ///
    /// A "Global NFT" consolidates information about all NFTs owned by a user into a single `EthCoin` instance,
    /// avoiding the need for separate instances for each NFT.
    /// The function configures the necessary settings for the Global NFT, including web3 connections and confirmation requirements.
    /// It fetches NFT details from a given URL to populate the `nfts_infos` field, which stores information about the user's NFTs.
    ///
    /// This setup allows the Global NFT to function like a coin, supporting swap operations and providing easy access to NFT details via `nfts_infos`.
    pub async fn initialize_global_nft(
        &self,
        original_url: &Url,
        komodo_proxy: bool,
    ) -> MmResult<EthCoin, EthTokenActivationError> {
        let chain = Chain::from_ticker(self.ticker())?;
        let ticker = chain.to_nft_ticker().to_string();

        let ctx = MmArc::from_weak(&self.ctx)
            .ok_or_else(|| String::from("No context"))
            .map_err(EthTokenActivationError::InternalError)?;
        let p2p_ctx = P2PContext::fetch_from_mm_arc(&ctx);

        let conf = coin_conf(&ctx, &ticker);

        let required_confirmations = AtomicU64::new(
            conf["required_confirmations"]
                .as_u64()
                .unwrap_or_else(|| self.required_confirmations.load(Ordering::Relaxed)),
        );

        // Create an abortable system linked to the `platform_coin` (which is self) so if the platform coin is disabled,
        // all spawned futures related to global Non-Fungible Token will be aborted as well.
        let abortable_system = self.abortable_system.create_subsystem()?;

        // Todo: support HD wallet for NFTs, currently we get nfts for enabled address only and there might be some issues when activating NFTs while ETH is activated with HD wallet
        let my_address = self.derivation_method.single_addr_or_err().await?;

        let proxy_sign = if komodo_proxy {
            let uri = Uri::from_str(original_url.as_ref())
                .map_err(|e| EthTokenActivationError::InternalError(e.to_string()))?;
            let proxy_sign = RawMessage::sign(p2p_ctx.keypair(), &uri, 0, common::PROXY_REQUEST_EXPIRATION_SEC)
                .map_err(|e| EthTokenActivationError::InternalError(e.to_string()))?;
            Some(proxy_sign)
        } else {
            None
        };

        let nft_infos = get_nfts_for_activation(&chain, &my_address, original_url, proxy_sign).await?;
        let coin_type = EthCoinType::Nft {
            platform: self.ticker.clone(),
        };
        let max_eth_tx_type = get_max_eth_tx_type_conf(&ctx, &conf, &coin_type).await?;
        let gas_limit: EthGasLimit = extract_gas_limit_from_conf(&conf)
            .map_to_mm(|e| EthTokenActivationError::InternalError(format!("invalid gas_limit config {}", e)))?;
        let gas_limit_v2: EthGasLimitV2 = extract_gas_limit_from_conf(&conf)
            .map_to_mm(|e| EthTokenActivationError::InternalError(format!("invalid gas_limit config {}", e)))?;

        let global_nft = EthCoinImpl {
            ticker,
            coin_type,
            priv_key_policy: self.priv_key_policy.clone(),
            derivation_method: self.derivation_method.clone(),
            sign_message_prefix: self.sign_message_prefix.clone(),
            swap_contract_address: self.swap_contract_address,
            swap_v2_contracts: self.swap_v2_contracts,
            fallback_swap_contract: self.fallback_swap_contract,
            contract_supports_watchers: self.contract_supports_watchers,
            web3_instances: AsyncMutex::new(self.web3_instances.lock().await.clone()),
            decimals: self.decimals,
            history_sync_state: Mutex::new(self.history_sync_state.lock().unwrap().clone()),
            swap_txfee_policy: Mutex::new(SwapTxFeePolicy::Internal),
            max_eth_tx_type,
            required_confirmations,
            ctx: self.ctx.clone(),
            chain_id: self.chain_id,
            trezor_coin: self.trezor_coin.clone(),
            logs_block_range: self.logs_block_range,
            address_nonce_locks: self.address_nonce_locks.clone(),
            erc20_tokens_infos: Default::default(),
            nfts_infos: Arc::new(AsyncMutex::new(nft_infos)),
            gas_limit,
            gas_limit_v2,
            abortable_system,
        };
        Ok(EthCoin(Arc::new(global_nft)))
    }
}

/// Activate eth coin from coin config and private key build policy,
/// version 2 of the activation function, with no intrinsic tokens creation.
pub async fn eth_coin_from_conf_and_request_v2(
    ctx: &MmArc,
    ticker: &str,
    conf: &Json,
    req: EthActivationV2Request,
    priv_key_build_policy: EthPrivKeyBuildPolicy,
) -> MmResult<EthCoin, EthActivationV2Error> {
    if req.swap_contract_address == Address::default() {
        return Err(EthActivationV2Error::InvalidSwapContractAddr(
            "swap_contract_address can't be zero address".to_string(),
        )
        .into());
    }

    if ctx.use_trading_proto_v2() {
        let contracts = req.swap_v2_contracts.as_ref().ok_or_else(|| {
            EthActivationV2Error::InvalidPayload(
                "swap_v2_contracts must be provided when using trading protocol v2".to_string(),
            )
        })?;
        if contracts.maker_swap_v2_contract == Address::default()
            || contracts.taker_swap_v2_contract == Address::default()
            || contracts.nft_maker_swap_v2_contract == Address::default()
        {
            return Err(EthActivationV2Error::InvalidSwapContractAddr(
                "All swap_v2_contracts addresses must be non-zero".to_string(),
            )
            .into());
        }
    }

    if let Some(fallback) = req.fallback_swap_contract {
        if fallback == Address::default() {
            return Err(EthActivationV2Error::InvalidFallbackSwapContract(
                "fallback_swap_contract can't be zero address".to_string(),
            )
            .into());
        }
    }

    let (priv_key_policy, derivation_method) = build_address_and_priv_key_policy(
        ctx,
        ticker,
        conf,
        priv_key_build_policy,
        &req.path_to_address,
        req.gap_limit,
    )
    .await?;

    let chain_id = conf["chain_id"].as_u64().ok_or(EthActivationV2Error::ChainIdNotSet)?;
    let web3_instances = match (req.rpc_mode, &priv_key_policy) {
        (EthRpcMode::Default, EthPrivKeyPolicy::Iguana(_) | EthPrivKeyPolicy::HDWallet { .. })
        | (EthRpcMode::Default, EthPrivKeyPolicy::Trezor) => {
            build_web3_instances(ctx, ticker.to_string(), req.nodes.clone()).await?
        },
        #[cfg(target_arch = "wasm32")]
        (EthRpcMode::Metamask, EthPrivKeyPolicy::Metamask(_)) => {
            build_metamask_transport(ctx, ticker.to_string(), chain_id).await?
        },
        #[cfg(target_arch = "wasm32")]
        (EthRpcMode::Default, EthPrivKeyPolicy::Metamask(_)) | (EthRpcMode::Metamask, _) => {
            let error = r#"priv_key_policy="Metamask" and rpc_mode="Metamask" should be used both"#.to_string();
            return MmError::err(EthActivationV2Error::ActivationFailed {
                ticker: ticker.to_string(),
                error,
            });
        },
    };

    // param from request should override the config
    let required_confirmations = req
        .required_confirmations
        .unwrap_or_else(|| {
            conf["required_confirmations"]
                .as_u64()
                .unwrap_or(DEFAULT_REQUIRED_CONFIRMATIONS as u64)
        })
        .into();

    let sign_message_prefix: Option<String> = json::from_value(conf["sign_message_prefix"].clone()).ok();

    let trezor_coin: Option<String> = json::from_value(conf["trezor_coin"].clone()).ok();

    let address_nonce_locks = {
        let mut map = NONCE_LOCK.lock().unwrap();
        Arc::new(AsyncMutex::new(
            map.entry(ticker.to_string()).or_insert_with(new_nonce_lock).clone(),
        ))
    };

    // Create an abortable system linked to the `MmCtx` so if the app is stopped on `MmArc::stop`,
    // all spawned futures related to `ETH` coin will be aborted as well.
    let abortable_system = ctx.abortable_system.create_subsystem()?;
    let coin_type = EthCoinType::Eth;
    let max_eth_tx_type = get_max_eth_tx_type_conf(ctx, conf, &coin_type).await?;
    let gas_limit: EthGasLimit = extract_gas_limit_from_conf(conf)
        .map_to_mm(|e| EthActivationV2Error::InternalError(format!("invalid gas_limit config {}", e)))?;
    let gas_limit_v2: EthGasLimitV2 = extract_gas_limit_from_conf(conf)
        .map_to_mm(|e| EthActivationV2Error::InternalError(format!("invalid gas_limit config {}", e)))?;

    let coin = EthCoinImpl {
        priv_key_policy,
        derivation_method: Arc::new(derivation_method),
        coin_type,
        sign_message_prefix,
        swap_contract_address: req.swap_contract_address,
        swap_v2_contracts: req.swap_v2_contracts,
        fallback_swap_contract: req.fallback_swap_contract,
        contract_supports_watchers: req.contract_supports_watchers,
        decimals: ETH_DECIMALS,
        ticker: ticker.to_string(),
        web3_instances: AsyncMutex::new(web3_instances),
        history_sync_state: Mutex::new(HistorySyncState::NotEnabled),
        swap_txfee_policy: Mutex::new(SwapTxFeePolicy::Internal),
        max_eth_tx_type,
        ctx: ctx.weak(),
        required_confirmations,
        chain_id,
        trezor_coin,
        logs_block_range: conf["logs_block_range"].as_u64().unwrap_or(DEFAULT_LOGS_BLOCK_RANGE),
        address_nonce_locks,
        erc20_tokens_infos: Default::default(),
        nfts_infos: Default::default(),
        gas_limit,
        gas_limit_v2,
        abortable_system,
    };

    Ok(EthCoin(Arc::new(coin)))
}

/// Processes the given `priv_key_policy` and generates corresponding `KeyPair`.
/// This function expects either [`PrivKeyBuildPolicy::IguanaPrivKey`]
/// or [`PrivKeyBuildPolicy::GlobalHDAccount`], otherwise returns `PrivKeyPolicyNotAllowed` error.
pub(crate) async fn build_address_and_priv_key_policy(
    ctx: &MmArc,
    ticker: &str,
    conf: &Json,
    priv_key_build_policy: EthPrivKeyBuildPolicy,
    path_to_address: &HDPathAccountToAddressId,
    gap_limit: Option<u32>,
) -> MmResult<(EthPrivKeyPolicy, EthDerivationMethod), EthActivationV2Error> {
    match priv_key_build_policy {
        EthPrivKeyBuildPolicy::IguanaPrivKey(iguana) => {
            let key_pair = KeyPair::from_secret_slice(iguana.as_slice())
                .map_to_mm(|e| EthActivationV2Error::InternalError(e.to_string()))?;
            let address = key_pair.address();
            let derivation_method = DerivationMethod::SingleAddress(address);
            Ok((EthPrivKeyPolicy::Iguana(key_pair), derivation_method))
        },
        EthPrivKeyBuildPolicy::GlobalHDAccount(global_hd_ctx) => {
            // Consider storing `derivation_path` at `EthCoinImpl`.
            let path_to_coin = json::from_value(conf["derivation_path"].clone())
                .map_to_mm(|e| EthActivationV2Error::ErrorDeserializingDerivationPath(e.to_string()))?;
            let raw_priv_key = global_hd_ctx
                .derive_secp256k1_secret(
                    &path_to_address
                        .to_derivation_path(&path_to_coin)
                        .mm_err(|e| EthActivationV2Error::InvalidPathToAddress(e.to_string()))?,
                )
                .mm_err(|e| EthActivationV2Error::InternalError(e.to_string()))?;
            let activated_key = KeyPair::from_secret_slice(raw_priv_key.as_slice())
                .map_to_mm(|e| EthActivationV2Error::InternalError(e.to_string()))?;
            let bip39_secp_priv_key = global_hd_ctx.root_priv_key().clone();

            let hd_wallet_rmd160 = *ctx.rmd160();
            let hd_wallet_storage = HDWalletCoinStorage::init_with_rmd160(ctx, ticker.to_string(), hd_wallet_rmd160)
                .await
                .mm_err(EthActivationV2Error::from)?;
            let accounts = load_hd_accounts_from_storage(&hd_wallet_storage, &path_to_coin).await?;
            let gap_limit = gap_limit.unwrap_or(DEFAULT_GAP_LIMIT);
            let hd_wallet = EthHDWallet {
                hd_wallet_rmd160,
                hd_wallet_storage,
                derivation_path: path_to_coin.clone(),
                accounts: HDAccountsMutex::new(accounts),
                enabled_address: *path_to_address,
                gap_limit,
            };
            let derivation_method = DerivationMethod::HDWallet(hd_wallet);
            Ok((
                EthPrivKeyPolicy::HDWallet {
                    path_to_coin,
                    activated_key,
                    bip39_secp_priv_key,
                },
                derivation_method,
            ))
        },
        EthPrivKeyBuildPolicy::Trezor => {
            let path_to_coin = json::from_value(conf["derivation_path"].clone())
                .map_to_mm(|e| EthActivationV2Error::ErrorDeserializingDerivationPath(e.to_string()))?;

            let trezor_coin: Option<String> = json::from_value(conf["trezor_coin"].clone()).ok();
            if trezor_coin.is_none() {
                return MmError::err(EthActivationV2Error::CoinDoesntSupportTrezor);
            }
            let crypto_ctx = CryptoCtx::from_ctx(ctx)?;
            let hw_ctx = crypto_ctx
                .hw_ctx()
                .or_mm_err(|| EthActivationV2Error::HwContextNotInitialized)?;
            let hd_wallet_rmd160 = hw_ctx.rmd160();
            let hd_wallet_storage = HDWalletCoinStorage::init_with_rmd160(ctx, ticker.to_string(), hd_wallet_rmd160)
                .await
                .mm_err(EthActivationV2Error::from)?;
            let accounts = load_hd_accounts_from_storage(&hd_wallet_storage, &path_to_coin).await?;
            let gap_limit = gap_limit.unwrap_or(DEFAULT_GAP_LIMIT);
            let hd_wallet = EthHDWallet {
                hd_wallet_rmd160,
                hd_wallet_storage,
                derivation_path: path_to_coin.clone(),
                accounts: HDAccountsMutex::new(accounts),
                enabled_address: *path_to_address,
                gap_limit,
            };
            let derivation_method = DerivationMethod::HDWallet(hd_wallet);
            Ok((EthPrivKeyPolicy::Trezor, derivation_method))
        },
        #[cfg(target_arch = "wasm32")]
        EthPrivKeyBuildPolicy::Metamask(metamask_ctx) => {
            let address = *metamask_ctx.check_active_eth_account().await?;
            let public_key_uncompressed = metamask_ctx.eth_account_pubkey_uncompressed();
            let public_key = compress_public_key(public_key_uncompressed)?;
            Ok((
                EthPrivKeyPolicy::Metamask(EthMetamaskPolicy {
                    public_key,
                    public_key_uncompressed,
                }),
                DerivationMethod::SingleAddress(address),
            ))
        },
    }
}

async fn build_web3_instances(
    ctx: &MmArc,
    coin_ticker: String,
    mut eth_nodes: Vec<EthNode>,
) -> MmResult<Vec<Web3Instance>, EthActivationV2Error> {
    if eth_nodes.is_empty() {
        return MmError::err(EthActivationV2Error::AtLeastOneNodeRequired);
    }

    let mut rng = small_rng();
    eth_nodes.as_mut_slice().shuffle(&mut rng);
    drop_mutability!(eth_nodes);

    let event_handlers = rpc_event_handlers_for_eth_transport(ctx, coin_ticker.clone());

    let mut web3_instances = Vec::with_capacity(eth_nodes.len());
    for eth_node in eth_nodes {
        let uri: Uri = eth_node
            .url
            .parse()
            .map_err(|_| EthActivationV2Error::InvalidPayload(format!("{} could not be parsed.", eth_node.url)))?;

        let transport = create_transport(ctx, &uri, &eth_node, &event_handlers)?;
        let web3 = Web3::new(transport);
        let version = match web3.web3().client_version().await {
            Ok(v) => v,
            Err(e) => {
                error!("Couldn't get client version for url {}: {}", eth_node.url, e);
                continue;
            },
        };

        web3_instances.push(Web3Instance {
            web3,
            is_parity: version.contains("Parity") || version.contains("parity"),
        });
    }

    if web3_instances.is_empty() {
        return Err(
            EthActivationV2Error::UnreachableNodes("Failed to get client version for all nodes".to_string()).into(),
        );
    }

    Ok(web3_instances)
}

fn create_transport(
    ctx: &MmArc,
    uri: &Uri,
    eth_node: &EthNode,
    event_handlers: &[RpcTransportEventHandlerShared],
) -> MmResult<Web3Transport, EthActivationV2Error> {
    match uri.scheme_str() {
        Some("ws") | Some("wss") => Ok(create_websocket_transport(ctx, uri, eth_node, event_handlers)),
        Some("http") | Some("https") => Ok(create_http_transport(ctx, uri, eth_node, event_handlers)),
        _ => MmError::err(EthActivationV2Error::InvalidPayload(format!(
            "Invalid node address '{uri}'. Only http(s) and ws(s) nodes are supported"
        ))),
    }
}

fn create_websocket_transport(
    ctx: &MmArc,
    uri: &Uri,
    eth_node: &EthNode,
    event_handlers: &[RpcTransportEventHandlerShared],
) -> Web3Transport {
    const TMP_SOCKET_CONNECTION: Duration = Duration::from_secs(20);

    let node = WebsocketTransportNode { uri: uri.clone() };

    let mut websocket_transport = WebsocketTransport::with_event_handlers(node, event_handlers.to_owned());

    if eth_node.komodo_proxy {
        websocket_transport.proxy_sign_keypair = Some(P2PContext::fetch_from_mm_arc(ctx).keypair().clone());
    }

    // Temporarily start the connection loop (we close the connection once we have the client version below).
    // Ideally, it would be much better to not do this workaround, which requires a lot of refactoring or
    // dropping websocket support on parity nodes.
    let fut = websocket_transport
        .clone()
        .start_connection_loop(Some(Instant::now() + TMP_SOCKET_CONNECTION));
    let settings = AbortSettings::info_on_abort(format!("connection loop stopped for {:?}", uri));
    ctx.spawner().spawn_with_settings(fut, settings);

    Web3Transport::Websocket(websocket_transport)
}

fn create_http_transport(
    ctx: &MmArc,
    uri: &Uri,
    eth_node: &EthNode,
    event_handlers: &[RpcTransportEventHandlerShared],
) -> Web3Transport {
    let node = HttpTransportNode {
        uri: uri.clone(),
        komodo_proxy: eth_node.komodo_proxy,
    };

    let komodo_proxy = node.komodo_proxy;
    let mut http_transport = HttpTransport::with_event_handlers(node, event_handlers.to_owned());

    if komodo_proxy {
        http_transport.proxy_sign_keypair = Some(P2PContext::fetch_from_mm_arc(ctx).keypair().clone());
    }

    Web3Transport::from(http_transport)
}

#[cfg(target_arch = "wasm32")]
async fn build_metamask_transport(
    ctx: &MmArc,
    coin_ticker: String,
    chain_id: u64,
) -> MmResult<Vec<Web3Instance>, EthActivationV2Error> {
    let event_handlers = rpc_event_handlers_for_eth_transport(ctx, coin_ticker.clone());

    let eth_config = web3_transport::metamask_transport::MetamaskEthConfig { chain_id };
    let web3 = Web3::new(Web3Transport::new_metamask_with_event_handlers(
        eth_config,
        event_handlers,
    )?);

    // Check if MetaMask supports the given `chain_id`.
    // Please note that this request may take a long time.
    check_metamask_supports_chain_id(coin_ticker, &web3, chain_id).await?;

    // MetaMask doesn't use Parity nodes. So `MetamaskTransport` doesn't support `parity_nextNonce` RPC.
    // An example of the `web3_clientVersion` RPC - `MetaMask/v10.22.1`.
    let web3_instances = vec![Web3Instance { web3, is_parity: false }];

    Ok(web3_instances)
}

/// This method is based on the fact that `MetamaskTransport` tries to switch the `ChainId`
/// if the MetaMask is targeted to another ETH chain.
#[cfg(target_arch = "wasm32")]
async fn check_metamask_supports_chain_id(
    ticker: String,
    web3: &Web3<Web3Transport>,
    expected_chain_id: u64,
) -> MmResult<(), EthActivationV2Error> {
    use jsonrpc_core::ErrorCode;

    /// See the documentation:
    /// https://docs.metamask.io/guide/rpc-api.html#wallet-switchethereumchain
    const CHAIN_IS_NOT_REGISTERED_ERROR: ErrorCode = ErrorCode::ServerError(4902);

    match web3.eth().chain_id().await {
        Ok(chain_id) if chain_id == U256::from(expected_chain_id) => Ok(()),
        // The RPC client should have returned ChainId with which it has been created on [`Web3Transport::new_metamask_with_event_handlers`].
        Ok(unexpected_chain_id) => {
            let error = format!("Expected '{expected_chain_id}' ChainId, found '{unexpected_chain_id}'");
            MmError::err(EthActivationV2Error::InternalError(error))
        },
        Err(web3::Error::Rpc(rpc_err)) if rpc_err.code == CHAIN_IS_NOT_REGISTERED_ERROR => {
            let error = format!("Ethereum chain_id({expected_chain_id}) is not supported");
            MmError::err(EthActivationV2Error::ActivationFailed { ticker, error })
        },
        Err(other) => {
            let error = other.to_string();
            MmError::err(EthActivationV2Error::ActivationFailed { ticker, error })
        },
    }
}

#[cfg(target_arch = "wasm32")]
fn compress_public_key(uncompressed: H520) -> MmResult<H264, EthActivationV2Error> {
    let public_key = PublicKey::from_slice(uncompressed.as_bytes())
        .map_to_mm(|e| EthActivationV2Error::InternalError(e.to_string()))?;
    let compressed = public_key.serialize();
    Ok(H264::from(compressed))
}
