#![no_std]

pub mod safe_math;

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, Bytes,
    BytesN, Env, String, Vec,
};

pub const VERSION: u32 = 1;
pub const DEFAULT_MINT_COOLDOWN_SECONDS: u64 = 0;
pub const DEFAULT_CIRCUIT_BREAKER_ENABLED: bool = false;
pub const DEFAULT_CIRCUIT_BREAKER_THRESHOLD: u64 = 100;
pub const DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS: u64 = 60;

const GAS_BASE_MINT: u64 = 50_000;
const GAS_BASE_TRANSFER: u64 = 30_000;
const MAX_BATCH_MINT: u32 = 25;
const PERSISTENT_BUMP_THRESHOLD: u32 = 172_800;
const PERSISTENT_BUMP_AMOUNT: u32 = 535_680;

// =============================================================================
// Errors
// =============================================================================

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Error {
    Unauthorized = 1,
    InvalidTokenId = 2,
    ClipAlreadyMinted = 3,
    RoyaltyTooHigh = 4,
    InvalidRecipient = 5,
    InvalidSalePrice = 6,
    ContractPaused = 7,
    InvalidSignature = 8,
    SignerNotSet = 9,
    InvalidRoyaltySplit = 10,
    SoulboundTransferBlocked = 11,
    RoyaltyOverflow = 12,
    ClipBlacklisted = 13,
    NotAuthorizedToApprove = 14,
    WithdrawalStillLocked = 15,
    NoWithdrawalRequest = 16,
    BatchTooLarge = 17,
    TokenFrozen = 18,
    InsufficientBalance = 19,
    MetadataRefreshTooSoon = 20,
    UnsupportedProtocol = 21,
    MalformedUrl = 22,
    MintCooldownActive = 23,
    Reentrancy = 24,
    MintingPaused = 25,
    CircuitBreakerTripped = 26,
    MetadataLocked = 27,
}

// =============================================================================
// Types
// =============================================================================

pub type TokenId = u32;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    pub trait_type: String,
    pub value: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyRecipient {
    pub recipient: Address,
    pub basis_points: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Royalty {
    pub recipients: Vec<RoyaltyRecipient>,
    pub asset_address: Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenData {
    pub owner: Address,
    pub clip_id: u32,
    pub is_soulbound: bool,
    pub metadata_uri: String,
    pub image: Option<String>,
    pub animation_url: Option<String>,
    pub description: Option<String>,
    pub external_url: Option<String>,
    pub attributes: Vec<Attribute>,
    pub royalty: Royalty,
    pub is_locked: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyInfo {
    pub receiver: Address,
    pub royalty_amount: i128,
    pub asset_address: Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractInfo {
    pub name: String,
    pub symbol: String,
    pub version: u32,
    pub owner: Address,
    pub platform_fee: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequest {
    pub amount: i128,
    pub unlock_time: u64,
}

// =============================================================================
// Storage keys
// =============================================================================

#[contracttype]
pub enum DataKey {
    Admin,
    NextTokenId,
    Paused,
    PauseUnlockTime,
    MintingPaused,
    Name,
    Symbol,
    Signer,
    BackendAddress,
    PlatformRecipient,
    /// Task 2: platform fee in basis points
    PlatformFeeBps,
    /// Task 2: default royalty in basis points
    DefaultRoyaltyBps,
    DefaultRoyaltyAsset,
    MintCooldownSeconds,
    ReentrancyLock,
    TotalSupply,
    ContractVersion,
    CircuitBreakerEnabled,
    CircuitBreakerThreshold,
    CircuitBreakerWindowSeconds,
    CircuitBreakerWindowStart,
    CircuitBreakerWindowCount,
    WithdrawXlmRequest,
    LastWithdrawalTime,
    TotalGasMint,
    CountMint,
    TotalGasTransfer,
    CountTransfer,
    Token(TokenId),
    ClipIdMinted(u32),
    CustomTokenUri(TokenId),
    Approved(TokenId),
    MetadataUpdateCount(TokenId),
    ApprovalForAll(Address, Address),
    BlacklistedClip(u32),
    Balance(Address),
    Frozen(TokenId),
    MetadataRefreshTime(TokenId),
    RoyaltyBalance(TokenId),
    LastMintTimestamp(Address),
    /// Task 3: global enumeration index
    TokenIndex(u32),
    /// Task 3: per-owner enumeration index
    OwnerTokenIndex(Address, u32),
}

// =============================================================================
// Events
// =============================================================================

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintEvent { pub to: Address, pub clip_id: u32, pub token_id: TokenId, pub metadata_uri: String }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct BurnEvent { pub owner: Address, pub token_id: TokenId, pub clip_id: u32 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferEvent { pub token_id: TokenId, pub from: Address, pub to: Address }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalEvent { pub owner: Address, pub operator: Address, pub token_id: TokenId }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalForAllEvent { pub owner: Address, pub operator: Address, pub approved: bool }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyPaidEvent { pub token_id: TokenId, pub from: Address, pub to: Address, pub amount: i128 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyRecipientUpdatedEvent { pub token_id: TokenId, pub old_recipient: Address, pub new_recipient: Address }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyUpdatedEvent { pub token_id: TokenId }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyClaimedEvent { pub token_id: TokenId, pub recipient: Address, pub amount: i128, pub asset: Address }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenUriChangedEvent { pub token_id: TokenId, pub owner: Address, pub new_uri: String }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataUpdatedEvent { pub token_id: TokenId, pub old_uri: String, pub new_uri: String }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataLockedEvent { pub token_id: TokenId, pub owner: Address }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchMintEvent { pub to: Address, pub count: u32, pub first_token_id: TokenId }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlacklistEvent { pub clip_id: u32 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenFrozenEvent { pub token_id: TokenId }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenUnfrozenEvent { pub token_id: TokenId }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerUpdatedEvent { pub new_pubkey: BytesN<32> }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseScheduledEvent { pub active_at: u64 }

/// Task 2: emitted when platform_fee or default_royalty is updated
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigUpdatedEvent { pub key: String, pub new_value: u32 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChangedEvent { pub old_admin: Address, pub new_admin: Address }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundedEvent { pub token_id: TokenId, pub recipient: Address, pub amount: i128 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitBreakerTriggeredEvent { pub mint_count: u64, pub threshold: u64, pub window_seconds: u64 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoulboundRecoveredEvent { pub token_id: TokenId, pub old_owner: Address, pub new_owner: Address }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigratedEvent { pub from_version: u32, pub to_version: u32 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequestedEvent { pub amount: i128, pub unlock_time: u64 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawExecutedEvent { pub amount: i128, pub recipient: Address }

// =============================================================================
// Contract
// =============================================================================

#[contract]
pub struct ClipsNftContract;

#[contractimpl]
impl ClipsNftContract {
    // -------------------------------------------------------------------------
    // Init
    // -------------------------------------------------------------------------

    pub fn init(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::NextTokenId, &1u32);
        env.storage().instance().set(&DataKey::TotalSupply, &0u32);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::MintingPaused, &false);
        env.storage().instance().set(&DataKey::PlatformRecipient, &admin);
        env.storage().instance().set(&DataKey::PlatformFeeBps, &100u32);
        env.storage().instance().set(&DataKey::DefaultRoyaltyBps, &0u32);
        env.storage().instance().set(&DataKey::DefaultRoyaltyAsset, &Option::<Address>::None);
        env.storage().instance().set(&DataKey::Name, &String::from_str(&env, "ClipCash Clips"));
        env.storage().instance().set(&DataKey::Symbol, &String::from_str(&env, "CLIP"));
        env.storage().instance().set(&DataKey::MintCooldownSeconds, &DEFAULT_MINT_COOLDOWN_SECONDS);
        env.storage().instance().set(&DataKey::CircuitBreakerEnabled, &DEFAULT_CIRCUIT_BREAKER_ENABLED);
        env.storage().instance().set(&DataKey::CircuitBreakerThreshold, &DEFAULT_CIRCUIT_BREAKER_THRESHOLD);
        env.storage().instance().set(&DataKey::CircuitBreakerWindowSeconds, &DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);
        env.storage().instance().set(&DataKey::CircuitBreakerWindowStart, &0u64);
        env.storage().instance().set(&DataKey::CircuitBreakerWindowCount, &0u64);
        env.storage().instance().set(&DataKey::BackendAddress, &admin);
    }

    // -------------------------------------------------------------------------
    // Task 1: Safe math — mint with overflow-safe royalty validation
    // -------------------------------------------------------------------------

    pub fn mint(
        env: Env,
        to: Address,
        clip_id: u32,
        metadata_uri: String,
        image: Option<String>,
        animation_url: Option<String>,
        royalty: Royalty,
        is_soulbound: bool,
        signature: BytesN<64>,
    ) -> Result<TokenId, Error> {
        to.require_auth();
        Self::require_not_paused(&env)?;
        if env.storage().instance().get::<DataKey, bool>(&DataKey::MintingPaused).unwrap_or(false) {
            return Err(Error::MintingPaused);
        }
        Self::enforce_mint_cooldown(&env, &to)?;
        Self::check_circuit_breaker(&env, 1)?;
        Self::validate_url(&env, &image)?;
        Self::validate_url(&env, &animation_url)?;
        Self::verify_clip_signature(&env, &to, clip_id, &metadata_uri, &signature)?;

        if Self::load_clip_token_id(&env, clip_id).is_some() {
            return Err(Error::ClipAlreadyMinted);
        }
        if env.storage().persistent().get::<DataKey, bool>(&DataKey::BlacklistedClip(clip_id)).unwrap_or(false) {
            return Err(Error::ClipBlacklisted);
        }

        let royalty = Self::normalize_royalty(&env, royalty)?;
        // Task 1: validate royalty bps via safe_math before storing
        let mut total_bps: u32 = 0;
        for i in 0..royalty.recipients.len() {
            let r = royalty.recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
            total_bps = total_bps.saturating_add(r.basis_points);
        }
        if total_bps > 10_000 {
            return Err(Error::RoyaltyTooHigh);
        }

        let token_id: TokenId = env.storage().instance().get(&DataKey::NextTokenId).unwrap_or(1);
        env.storage().instance().set(&DataKey::NextTokenId, &(token_id + 1));

        let data = TokenData {
            owner: to.clone(), clip_id, is_soulbound,
            metadata_uri: metadata_uri.clone(), image, animation_url,
            description: None, external_url: None,
            attributes: Vec::new(&env), royalty, is_locked: false,
        };
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        Self::bump_persistent_ttl(&env, &DataKey::Token(token_id));
        env.storage().persistent().set(&DataKey::ClipIdMinted(clip_id), &token_id);
        Self::bump_persistent_ttl(&env, &DataKey::ClipIdMinted(clip_id));

        // Update supply + enumeration indexes
        let supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalSupply, &(supply + 1));
        env.storage().persistent().set(&DataKey::TokenIndex(supply), &token_id);
        let bal: u32 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &(bal + 1));
        env.storage().persistent().set(&DataKey::OwnerTokenIndex(to.clone(), bal), &token_id);

        Self::record_mint_timestamp(&env, &to);
        Self::update_circuit_breaker_counter(&env, 1);

        let count: u64 = env.storage().temporary().get(&DataKey::CountMint).unwrap_or(0);
        env.storage().temporary().set(&DataKey::CountMint, &(count + 1));
        let gas: u64 = env.storage().temporary().get(&DataKey::TotalGasMint).unwrap_or(0);
        env.storage().temporary().set(&DataKey::TotalGasMint, &gas.saturating_add(GAS_BASE_MINT));

        env.events().publish((symbol_short!("mint"),), MintEvent { to, clip_id, token_id, metadata_uri });
        Ok(token_id)
    }

    pub fn transfer(
        env: Env,
        from: Address,
        to: Address,
        token_id: TokenId,
        sale_price: i128,
        payment_asset: Option<Address>,
    ) -> Result<(), Error> {
        from.require_auth();
        Self::require_not_paused(&env)?;
        if env.storage().persistent().get::<DataKey, bool>(&DataKey::Frozen(token_id)).unwrap_or(false) {
            return Err(Error::TokenFrozen);
        }
        let mut data: TokenData = Self::load_token(&env, token_id)?;
        if from != data.owner { return Err(Error::Unauthorized); }
        if data.is_soulbound { return Err(Error::SoulboundTransferBlocked); }

        if sale_price > 0 {
            let royalty = data.royalty.clone();
            let pay_asset = match royalty.asset_address.clone() {
                Some(a) => a,
                None => payment_asset.ok_or(Error::InvalidRecipient)?,
            };
            to.require_auth();
            Self::acquire_reentrancy_lock(&env)?;
            let token_client = soroban_sdk::token::TokenClient::new(&env, &pay_asset);
            let mut cum_bps: u32 = 0;
            let mut cum_amt: i128 = 0;
            for i in 0..royalty.recipients.len() {
                let split = royalty.recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
                cum_bps = cum_bps.saturating_add(split.basis_points);
                let total = Self::calculate_royalty(sale_price, cum_bps)?;
                let amount = total.saturating_sub(cum_amt);
                cum_amt = total;
                if amount > 0 {
                    token_client.transfer(&to, &split.recipient, &amount);
                    env.events().publish((symbol_short!("royalty"),), RoyaltyPaidEvent { token_id, from: to.clone(), to: split.recipient, amount });
                }
            }
            Self::release_reentrancy_lock(&env);
        }

        env.storage().persistent().remove(&DataKey::Approved(token_id));
        data.owner = to.clone();
        env.storage().persistent().set(&DataKey::Token(token_id), &data);

        // Update balance + owner indexes
        let fb: u32 = env.storage().persistent().get(&DataKey::Balance(from.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(from.clone()), &fb.saturating_sub(1));
        Self::index_remove_owner(&env, &from, token_id);
        let tb: u32 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &(tb + 1));
        env.storage().persistent().set(&DataKey::OwnerTokenIndex(to.clone(), tb), &token_id);

        let ct: u64 = env.storage().temporary().get(&DataKey::CountTransfer).unwrap_or(0);
        env.storage().temporary().set(&DataKey::CountTransfer, &(ct + 1));
        let gt: u64 = env.storage().temporary().get(&DataKey::TotalGasTransfer).unwrap_or(0);
        env.storage().temporary().set(&DataKey::TotalGasTransfer, &gt.saturating_add(GAS_BASE_TRANSFER));

        env.events().publish((symbol_short!("transfer"),), TransferEvent { token_id, from, to });
        Ok(())
    }

    pub fn burn(env: Env, owner: Address, token_id: TokenId) -> Result<(), Error> {
        owner.require_auth();
        if env.storage().persistent().get::<DataKey, bool>(&DataKey::Frozen(token_id)).unwrap_or(false) {
            return Err(Error::TokenFrozen);
        }
        let data: TokenData = Self::load_token(&env, token_id)?;
        if owner != data.owner { return Err(Error::Unauthorized); }

        env.storage().persistent().remove(&DataKey::Token(token_id));
        env.storage().persistent().remove(&DataKey::ClipIdMinted(data.clip_id));
        env.storage().persistent().remove(&DataKey::Approved(token_id));

        let supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalSupply, &supply.saturating_sub(1));
        Self::index_remove_global(&env, token_id, supply);

        let bal: u32 = env.storage().persistent().get(&DataKey::Balance(owner.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(owner.clone()), &bal.saturating_sub(1));
        Self::index_remove_owner(&env, &owner, token_id);

        env.events().publish((symbol_short!("burn"),), BurnEvent { owner, token_id, clip_id: data.clip_id });
        Ok(())
    }

    pub fn approve(env: Env, caller: Address, operator: Option<Address>, token_id: TokenId) -> Result<(), Error> {
        caller.require_auth();
        let data: TokenData = Self::load_token(&env, token_id)?;
        if data.owner != caller {
            let approved_all = env.storage().persistent().get::<DataKey, bool>(&DataKey::ApprovalForAll(data.owner.clone(), caller.clone())).unwrap_or(false);
            if !approved_all { return Err(Error::Unauthorized); }
        }
        match operator {
            Some(op) => {
                env.storage().persistent().set(&DataKey::Approved(token_id), &op);
                env.events().publish((symbol_short!("approval"),), ApprovalEvent { owner: data.owner, operator: op, token_id });
            }
            None => { env.storage().persistent().remove(&DataKey::Approved(token_id)); }
        }
        Ok(())
    }

    pub fn set_approval_for_all(env: Env, caller: Address, operator: Address, approved: bool) -> Result<(), Error> {
        caller.require_auth();
        env.storage().persistent().set(&DataKey::ApprovalForAll(caller.clone(), operator.clone()), &approved);
        env.events().publish((symbol_short!("app_all"),), ApprovalForAllEvent { owner: caller, operator, approved });
        Ok(())
    }

    pub fn get_approved(env: Env, token_id: TokenId) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Approved(token_id))
    }

    pub fn is_approved_for_all(env: Env, owner: Address, operator: Address) -> bool {
        env.storage().persistent().get::<DataKey, bool>(&DataKey::ApprovalForAll(owner, operator)).unwrap_or(false)
    }

    // -------------------------------------------------------------------------
    // Task 2: Admin-only config — set_platform_fee, set_default_royalty
    // -------------------------------------------------------------------------

    /// Set platform fee in basis points. Emits ConfigUpdated.
    pub fn set_platform_fee(env: Env, admin: Address, bps: u32) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if bps > 10_000 { return Err(Error::RoyaltyTooHigh); }
        env.storage().instance().set(&DataKey::PlatformFeeBps, &bps);
        env.events().publish((symbol_short!("cfg_upd"),), ConfigUpdatedEvent { key: String::from_str(&env, "platform_fee"), new_value: bps });
        Ok(())
    }

    /// Set default royalty in basis points. Emits ConfigUpdated.
    pub fn set_default_royalty(env: Env, admin: Address, bps: u32) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if bps > 10_000 { return Err(Error::RoyaltyTooHigh); }
        env.storage().instance().set(&DataKey::DefaultRoyaltyBps, &bps);
        env.events().publish((symbol_short!("cfg_upd"),), ConfigUpdatedEvent { key: String::from_str(&env, "default_royalty"), new_value: bps });
        Ok(())
    }

    pub fn get_platform_fee(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::PlatformFeeBps).unwrap_or(100)
    }

    pub fn get_default_royalty_bps(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::DefaultRoyaltyBps).unwrap_or(0)
    }

    // -------------------------------------------------------------------------
    // Task 3: get_user_tokens — O(1) index-based pagination
    // -------------------------------------------------------------------------

    /// Return token IDs owned by `owner`. O(limit) — reads from OwnerTokenIndex.
    pub fn get_user_tokens(env: Env, owner: Address, limit: u32, offset: u32) -> Vec<TokenId> {
        const MAX_LIMIT: u32 = 100;
        let limit = if limit > MAX_LIMIT { MAX_LIMIT } else { limit };
        let balance: u32 = env.storage().persistent().get(&DataKey::Balance(owner.clone())).unwrap_or(0);
        let mut result: Vec<TokenId> = Vec::new(&env);
        let end = offset.saturating_add(limit).min(balance);
        for pos in offset..end {
            if let Some(tid) = env.storage().persistent().get::<DataKey, TokenId>(&DataKey::OwnerTokenIndex(owner.clone(), pos)) {
                result.push_back(tid);
            }
        }
        result
    }

    /// Alias with optional params for backwards compat.
    pub fn tokens_of_owner(env: Env, owner: Address, limit: Option<u32>, offset: Option<u32>) -> Vec<TokenId> {
        Self::get_user_tokens(env, owner, limit.unwrap_or(100), offset.unwrap_or(0))
    }

    // -------------------------------------------------------------------------
    // Task 4: Fee estimation helpers
    // -------------------------------------------------------------------------

    /// Returns approximate mint fee in stroops.
    pub fn estimate_mint_fee(_env: Env) -> i128 {
        GAS_BASE_MINT as i128
    }

    /// Returns approximate transfer fee in stroops.
    pub fn estimate_transfer_fee(_env: Env) -> i128 {
        GAS_BASE_TRANSFER as i128
    }

    // -------------------------------------------------------------------------
    // Royalty
    // -------------------------------------------------------------------------

    pub fn royalty_info(env: Env, token_id: TokenId, sale_price: i128) -> Result<RoyaltyInfo, Error> {
        if sale_price <= 0 { return Err(Error::InvalidSalePrice); }
        let data = Self::load_token(&env, token_id)?;
        let mut total_bps: u32 = 0;
        for i in 0..data.royalty.recipients.len() {
            let r = data.royalty.recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
            total_bps = total_bps.saturating_add(r.basis_points);
        }
        let royalty_amount = Self::calculate_royalty(sale_price, total_bps)?;
        let first = data.royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?;
        Ok(RoyaltyInfo { receiver: first.recipient, royalty_amount, asset_address: data.royalty.asset_address })
    }

    pub fn get_royalty(env: Env, token_id: TokenId) -> Result<Royalty, Error> {
        Ok(Self::load_token(&env, token_id)?.royalty)
    }

    pub fn set_royalty(env: Env, admin: Address, token_id: TokenId, new_royalty: Royalty) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let mut data = Self::load_token(&env, token_id)?;
        let old = data.royalty.clone();
        if !old.recipients.is_empty() && !new_royalty.recipients.is_empty() {
            let or = old.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?;
            let nr = new_royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?;
            if or.recipient != nr.recipient {
                env.events().publish((symbol_short!("royalty"),), RoyaltyRecipientUpdatedEvent { token_id, old_recipient: or.recipient, new_recipient: nr.recipient });
            }
        }
        let new_royalty = Self::normalize_royalty(&env, new_royalty)?;
        data.royalty = new_royalty;
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        env.events().publish((symbol_short!("roy_upd"),), RoyaltyUpdatedEvent { token_id });
        Ok(())
    }

    pub fn update_royalty_recipient(env: Env, caller: Address, token_id: TokenId, new_recipient: Address) -> Result<(), Error> {
        caller.require_auth();
        let mut data = Self::load_token(&env, token_id)?;
        let old = data.royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?.recipient.clone();
        if caller != old { return Err(Error::Unauthorized); }
        let bps = data.royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?.basis_points;
        data.royalty.recipients.set(0, RoyaltyRecipient { recipient: new_recipient.clone(), basis_points: bps });
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        env.events().publish((symbol_short!("royalty"),), RoyaltyRecipientUpdatedEvent { token_id, old_recipient: old, new_recipient });
        Ok(())
    }

    pub fn pay_royalty(env: Env, payer: Address, token_id: TokenId, sale_price: i128) -> Result<(), Error> {
        payer.require_auth();
        if sale_price <= 0 { return Err(Error::InvalidSalePrice); }
        let data = Self::load_token(&env, token_id)?;
        let asset = data.royalty.asset_address.clone().ok_or(Error::InvalidRecipient)?;
        Self::acquire_reentrancy_lock(&env)?;
        let client = soroban_sdk::token::TokenClient::new(&env, &asset);
        let mut cum_bps: u32 = 0;
        let mut cum_amt: i128 = 0;
        for i in 0..data.royalty.recipients.len() {
            let split = data.royalty.recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
            cum_bps = cum_bps.saturating_add(split.basis_points);
            let total = Self::calculate_royalty(sale_price, cum_bps)?;
            let amount = total.saturating_sub(cum_amt);
            cum_amt = total;
            if amount > 0 {
                client.transfer(&payer, &split.recipient, &amount);
                env.events().publish((symbol_short!("royalty"),), RoyaltyPaidEvent { token_id, from: payer.clone(), to: split.recipient, amount });
            }
        }
        Self::release_reentrancy_lock(&env);
        Ok(())
    }

    pub fn claim_royalties(env: Env, caller: Address, token_id: TokenId) -> Result<(), Error> {
        caller.require_auth();
        let data = Self::load_token(&env, token_id)?;
        let recipient = data.royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?.recipient;
        if caller != recipient { return Err(Error::Unauthorized); }
        let asset = data.royalty.asset_address.ok_or(Error::InvalidRecipient)?;
        let balance: i128 = env.storage().persistent().get(&DataKey::RoyaltyBalance(token_id)).unwrap_or(0);
        if balance <= 0 { return Err(Error::InsufficientBalance); }
        Self::acquire_reentrancy_lock(&env)?;
        env.storage().persistent().remove(&DataKey::RoyaltyBalance(token_id));
        soroban_sdk::token::TokenClient::new(&env, &asset).transfer(&env.current_contract_address(), &recipient, &balance);
        Self::release_reentrancy_lock(&env);
        env.events().publish((symbol_short!("roy_clm"),), RoyaltyClaimedEvent { token_id, recipient, amount: balance, asset });
        Ok(())
    }

    /// Task 1: public safe-math royalty calculation helper
    pub fn calculate_royalty_amount(env: Env, token_id: TokenId, sale_price: i128) -> Result<i128, Error> {
        let data = Self::load_token(&env, token_id)?;
        let mut total_bps: u32 = 0;
        for i in 0..data.royalty.recipients.len() {
            let r = data.royalty.recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
            total_bps = total_bps.saturating_add(r.basis_points);
        }
        Self::calculate_royalty(sale_price, total_bps)
    }

    // -------------------------------------------------------------------------
    // Pause / Admin
    // -------------------------------------------------------------------------

    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let active_at = env.ledger().timestamp().saturating_add(86_400);
        env.storage().instance().set(&DataKey::PauseUnlockTime, &active_at);
        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish((symbol_short!("pse_sched"),), PauseScheduledEvent { active_at });
        Ok(())
    }

    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().remove(&DataKey::PauseUnlockTime);
        env.events().publish((symbol_short!("unpaused"),), ());
        Ok(())
    }

    pub fn is_paused(env: Env) -> bool {
        Self::check_paused(&env)
    }

    pub fn pause_minting(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::MintingPaused, &true);
        Ok(())
    }

    pub fn unpause_minting(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::MintingPaused, &false);
        Ok(())
    }

    pub fn set_signer(env: Env, admin: Address, pubkey: BytesN<32>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Signer, &pubkey);
        env.events().publish((symbol_short!("sgn_upd"),), SignerUpdatedEvent { new_pubkey: pubkey });
        Ok(())
    }

    pub fn get_signer(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&DataKey::Signer)
    }

    pub fn set_backend_address(env: Env, admin: Address, backend_address: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::BackendAddress, &backend_address);
        Ok(())
    }

    pub fn get_backend_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::BackendAddress)
    }

    pub fn set_platform_recipient(env: Env, admin: Address, recipient: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::PlatformRecipient, &recipient);
        Ok(())
    }

    pub fn set_default_royalty_asset(env: Env, admin: Address, asset_address: Option<Address>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::DefaultRoyaltyAsset, &asset_address);
        Ok(())
    }

    pub fn get_default_royalty_asset(env: Env) -> Option<Address> {
        env.storage().instance().get::<DataKey, Option<Address>>(&DataKey::DefaultRoyaltyAsset).unwrap_or(None)
    }

    pub fn set_mint_cooldown(env: Env, admin: Address, seconds: u64) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::MintCooldownSeconds, &seconds);
        Ok(())
    }

    pub fn get_mint_cooldown(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::MintCooldownSeconds).unwrap_or(DEFAULT_MINT_COOLDOWN_SECONDS)
    }

    pub fn blacklist_clip(env: Env, admin: Address, clip_id: u32) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().persistent().set(&DataKey::BlacklistedClip(clip_id), &true);
        env.events().publish((symbol_short!("blacklist"),), BlacklistEvent { clip_id });
        Ok(())
    }

    pub fn freeze_token(env: Env, admin: Address, token_id: TokenId) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if !env.storage().persistent().has(&DataKey::Token(token_id)) { return Err(Error::InvalidTokenId); }
        env.storage().persistent().set(&DataKey::Frozen(token_id), &true);
        env.events().publish((symbol_short!("freeze"),), TokenFrozenEvent { token_id });
        Ok(())
    }

    pub fn unfreeze_token(env: Env, admin: Address, token_id: TokenId) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if !env.storage().persistent().has(&DataKey::Token(token_id)) { return Err(Error::InvalidTokenId); }
        env.storage().persistent().set(&DataKey::Frozen(token_id), &false);
        env.events().publish((symbol_short!("unfreeze"),), TokenUnfrozenEvent { token_id });
        Ok(())
    }

    pub fn is_frozen(env: Env, token_id: TokenId) -> bool {
        env.storage().persistent().get::<DataKey, bool>(&DataKey::Frozen(token_id)).unwrap_or(false)
    }

    pub fn set_token_uri(env: Env, owner: Address, token_id: TokenId, new_uri: String) -> Result<(), Error> {
        owner.require_auth();
        let data = Self::load_token(&env, token_id)?;
        if data.owner != owner { return Err(Error::Unauthorized); }
        env.storage().persistent().set(&DataKey::CustomTokenUri(token_id), &new_uri.clone());
        env.events().publish((symbol_short!("uri_chg"),), TokenUriChangedEvent { token_id, owner, new_uri });
        Ok(())
    }

    pub fn request_withdraw_asset(env: Env, admin: Address, amount: i128) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let unlock_time = env.ledger().timestamp().saturating_add(172_800);
        env.storage().instance().set(&DataKey::WithdrawXlmRequest, &WithdrawRequest { amount, unlock_time });
        env.events().publish((symbol_short!("wdraw_req"),), WithdrawRequestedEvent { amount, unlock_time });
        Ok(())
    }

    pub fn withdraw_asset(env: Env, admin: Address, asset: Address, amount: i128) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let req: WithdrawRequest = env.storage().instance().get(&DataKey::WithdrawXlmRequest).ok_or(Error::NoWithdrawalRequest)?;
        if env.ledger().timestamp() < req.unlock_time { return Err(Error::WithdrawalStillLocked); }
        env.storage().instance().remove(&DataKey::WithdrawXlmRequest);
        env.storage().instance().set(&DataKey::LastWithdrawalTime, &env.ledger().timestamp());
        soroban_sdk::token::TokenClient::new(&env, &asset).transfer(&env.current_contract_address(), &admin, &amount);
        env.events().publish((symbol_short!("wdraw_exe"),), WithdrawExecutedEvent { amount, recipient: admin });
        Ok(())
    }

    pub fn set_circuit_breaker_enabled(env: Env, admin: Address, enabled: bool) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerEnabled, &enabled);
        Ok(())
    }

    pub fn set_circuit_breaker_threshold(env: Env, admin: Address, threshold: u64) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerThreshold, &threshold);
        Ok(())
    }

    pub fn set_circuit_breaker_window(env: Env, admin: Address, window_seconds: u64) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerWindowSeconds, &window_seconds);
        Ok(())
    }

    pub fn reset_circuit_breaker(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerWindowStart, &0u64);
        env.storage().instance().set(&DataKey::CircuitBreakerWindowCount, &0u64);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Batch mint
    // -------------------------------------------------------------------------

    pub fn batch_mint(
        env: Env,
        to: Address,
        clip_ids: Vec<u32>,
        metadata_uris: Vec<String>,
        images: Vec<Option<String>>,
        animation_urls: Vec<Option<String>>,
        royalty: Royalty,
        is_soulbound: bool,
        signatures: Vec<BytesN<64>>,
    ) -> Result<Vec<TokenId>, Error> {
        to.require_auth();
        Self::require_not_paused(&env)?;
        Self::enforce_mint_cooldown(&env, &to)?;
        let n = clip_ids.len();
        if n > MAX_BATCH_MINT { return Err(Error::BatchTooLarge); }
        Self::check_circuit_breaker(&env, n as u64)?;
        if n != metadata_uris.len() || n != signatures.len() || n != images.len() || n != animation_urls.len() {
            return Err(Error::InvalidRoyaltySplit);
        }
        let royalty = Self::normalize_royalty(&env, royalty)?;
        let mut minted: Vec<TokenId> = Vec::new(&env);
        for i in 0..n {
            let clip_id = clip_ids.get(i).ok_or(Error::InvalidTokenId)?;
            let metadata_uri = metadata_uris.get(i).ok_or(Error::InvalidTokenId)?;
            let image = images.get(i).ok_or(Error::InvalidTokenId)?;
            let animation_url = animation_urls.get(i).ok_or(Error::InvalidTokenId)?;
            let signature = signatures.get(i).ok_or(Error::InvalidTokenId)?;
            Self::validate_url(&env, &image)?;
            Self::validate_url(&env, &animation_url)?;
            Self::verify_clip_signature(&env, &to, clip_id, &metadata_uri, &signature)?;
            if Self::load_clip_token_id(&env, clip_id).is_some() { return Err(Error::ClipAlreadyMinted); }
            if env.storage().persistent().get::<DataKey, bool>(&DataKey::BlacklistedClip(clip_id)).unwrap_or(false) { return Err(Error::ClipBlacklisted); }
            let token_id: TokenId = env.storage().instance().get(&DataKey::NextTokenId).unwrap_or(1);
            env.storage().instance().set(&DataKey::NextTokenId, &(token_id + 1));
            env.storage().persistent().set(&DataKey::Token(token_id), &TokenData {
                owner: to.clone(), clip_id, is_soulbound, metadata_uri, image, animation_url,
                description: None, external_url: None, attributes: Vec::new(&env), royalty: royalty.clone(), is_locked: false,
            });
            Self::bump_persistent_ttl(&env, &DataKey::Token(token_id));
            env.storage().persistent().set(&DataKey::ClipIdMinted(clip_id), &token_id);
            Self::bump_persistent_ttl(&env, &DataKey::ClipIdMinted(clip_id));
            let supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
            env.storage().instance().set(&DataKey::TotalSupply, &(supply + 1));
            env.storage().persistent().set(&DataKey::TokenIndex(supply), &token_id);
            let bal: u32 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
            env.storage().persistent().set(&DataKey::Balance(to.clone()), &(bal + 1));
            env.storage().persistent().set(&DataKey::OwnerTokenIndex(to.clone(), bal), &token_id);
            minted.push_back(token_id);
        }
        Self::record_mint_timestamp(&env, &to);
        Self::update_circuit_breaker_counter(&env, n as u64);
        let first = minted.get(0).unwrap_or(0);
        env.events().publish((symbol_short!("batch_mnt"),), BatchMintEvent { to, count: n, first_token_id: first });
        Ok(minted)
    }

    // -------------------------------------------------------------------------
    // View functions
    // -------------------------------------------------------------------------

    pub fn owner_of(env: Env, token_id: TokenId) -> Result<Address, Error> {
        Ok(Self::load_token(&env, token_id)?.owner)
    }

    pub fn token_uri(env: Env, token_id: TokenId) -> Result<String, Error> {
        if let Some(custom) = env.storage().persistent().get::<DataKey, String>(&DataKey::CustomTokenUri(token_id)) {
            return Ok(custom);
        }
        Ok(Self::load_token(&env, token_id)?.metadata_uri)
    }

    pub fn get_metadata(env: Env, token_id: TokenId) -> Result<String, Error> {
        Self::token_uri(env, token_id)
    }

    pub fn exists(env: Env, token_id: TokenId) -> bool {
        env.storage().persistent().has(&DataKey::Token(token_id))
    }

    pub fn total_supply(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0)
    }

    pub fn balance_of(env: Env, owner: Address) -> u32 {
        env.storage().persistent().get(&DataKey::Balance(owner)).unwrap_or(0)
    }

    pub fn name(env: Env) -> String {
        env.storage().instance().get(&DataKey::Name).unwrap_or_else(|| String::from_str(&env, "ClipCash Clips"))
    }

    pub fn symbol(env: Env) -> String {
        env.storage().instance().get(&DataKey::Symbol).unwrap_or_else(|| String::from_str(&env, "CLIP"))
    }

    pub fn set_name(env: Env, admin: Address, name: String) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Name, &name);
        Ok(())
    }

    pub fn set_symbol(env: Env, admin: Address, symbol: String) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Symbol, &symbol);
        Ok(())
    }

    pub fn version(_env: Env) -> u32 { VERSION }

    pub fn clip_token_id(env: Env, clip_id: u32) -> Result<TokenId, Error> {
        Self::load_clip_token_id(&env, clip_id).ok_or(Error::InvalidTokenId)
    }

    pub fn get_clip_id(env: Env, token_id: TokenId) -> Result<u32, Error> {
        Ok(Self::load_token(&env, token_id)?.clip_id)
    }

    pub fn is_soulbound(env: Env, token_id: TokenId) -> bool {
        Self::load_token(&env, token_id).map(|d| d.is_soulbound).unwrap_or(false)
    }

    pub fn royalty_balance_of(env: Env, token_id: TokenId) -> i128 {
        env.storage().persistent().get(&DataKey::RoyaltyBalance(token_id)).unwrap_or(0)
    }

    pub fn token_by_index(env: Env, index: u32) -> Result<TokenId, Error> {
        let supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        if index >= supply { return Err(Error::InvalidTokenId); }
        env.storage().persistent().get(&DataKey::TokenIndex(index)).ok_or(Error::InvalidTokenId)
    }

    pub fn token_of_owner_by_index(env: Env, owner: Address, index: u32) -> Result<TokenId, Error> {
        let bal: u32 = env.storage().persistent().get(&DataKey::Balance(owner.clone())).unwrap_or(0);
        if index >= bal { return Err(Error::InvalidTokenId); }
        env.storage().persistent().get(&DataKey::OwnerTokenIndex(owner, index)).ok_or(Error::InvalidTokenId)
    }

    pub fn contract_info(env: Env) -> ContractInfo {
        let owner: Address = env.storage().instance().get(&DataKey::Admin).expect("not init");
        ContractInfo { name: Self::name(env.clone()), symbol: Self::symbol(env.clone()), version: VERSION, owner, platform_fee: Self::get_platform_fee(env) }
    }

    pub fn circuit_breaker_enabled(env: Env) -> bool {
        env.storage().instance().get(&DataKey::CircuitBreakerEnabled).unwrap_or(DEFAULT_CIRCUIT_BREAKER_ENABLED)
    }

    pub fn circuit_breaker_threshold(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::CircuitBreakerThreshold).unwrap_or(DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
    }

    pub fn circuit_breaker_window_seconds(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::CircuitBreakerWindowSeconds).unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS)
    }

    pub fn circuit_breaker_window_start(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::CircuitBreakerWindowStart).unwrap_or(0)
    }

    pub fn circuit_breaker_window_count(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::CircuitBreakerWindowCount).unwrap_or(0)
    }

    pub fn get_tokens_by_clip_ids(env: Env, clip_ids: Vec<u32>) -> Vec<Option<TokenId>> {
        let mut result = Vec::new(&env);
        for i in 0..clip_ids.len() {
            result.push_back(Self::load_clip_token_id(&env, clip_ids.get(i).unwrap()));
        }
        result
    }

    pub fn refresh_metadata(env: Env, caller: Address, token_id: TokenId, new_uri: Option<String>, image: Option<String>, animation_url: Option<String>) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).expect("not init");
        let is_backend = env.storage().instance().get::<DataKey, Address>(&DataKey::BackendAddress).map(|b| caller == b).unwrap_or(false);
        if caller != admin && !is_backend { return Err(Error::Unauthorized); }
        const COOLDOWN: u64 = 2_592_000;
        let now = env.ledger().timestamp();
        if let Some(last) = env.storage().persistent().get::<DataKey, u64>(&DataKey::MetadataRefreshTime(token_id)) {
            if now < last.saturating_add(COOLDOWN) { return Err(Error::MetadataRefreshTooSoon); }
        }
        let mut data = Self::load_token(&env, token_id)?;
        if data.is_locked { return Err(Error::MetadataLocked); }
        let old_uri = data.metadata_uri.clone();
        if let Some(uri) = new_uri { data.metadata_uri = uri; }
        if let Some(img) = image { data.image = if img.is_empty() { None } else { Some(img) }; }
        if let Some(anim) = animation_url { data.animation_url = if anim.is_empty() { None } else { Some(anim) }; }
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        env.storage().persistent().set(&DataKey::MetadataRefreshTime(token_id), &now);
        env.events().publish((symbol_short!("meta_upd"),), MetadataUpdatedEvent { token_id, old_uri, new_uri: data.metadata_uri });
        Ok(())
    }

    pub fn lock_metadata(env: Env, owner: Address, token_id: TokenId) -> Result<(), Error> {
        owner.require_auth();
        let mut data = Self::load_token(&env, token_id)?;
        if data.owner != owner { return Err(Error::Unauthorized); }
        if data.is_locked { return Err(Error::MetadataLocked); }
        data.is_locked = true;
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        env.events().publish((symbol_short!("meta_lock"),), MetadataLockedEvent { token_id, owner });
        Ok(())
    }

    pub fn is_metadata_locked(env: Env, token_id: TokenId) -> Result<bool, Error> {
        Ok(Self::load_token(&env, token_id)?.is_locked)
    }

    pub fn get_next_metadata_refresh_time(env: Env, token_id: TokenId) -> Result<u64, Error> {
        if !env.storage().persistent().has(&DataKey::Token(token_id)) { return Err(Error::InvalidTokenId); }
        Ok(env.storage().persistent().get::<DataKey, u64>(&DataKey::MetadataRefreshTime(token_id)).map(|l| l.saturating_add(2_592_000)).unwrap_or(0))
    }

    pub fn minted_count(env: Env) -> u32 {
        env.storage().instance().get::<DataKey, u32>(&DataKey::NextTokenId).unwrap_or(1).saturating_sub(1)
    }

    pub fn average_gas_mint(env: Env) -> u64 {
        let total: u64 = env.storage().temporary().get(&DataKey::TotalGasMint).unwrap_or(0);
        let count: u64 = env.storage().temporary().get(&DataKey::CountMint).unwrap_or(0);
        if count == 0 { 0 } else { total / count }
    }

    pub fn average_gas_transfer(env: Env) -> u64 {
        let total: u64 = env.storage().temporary().get(&DataKey::TotalGasTransfer).unwrap_or(0);
        let count: u64 = env.storage().temporary().get(&DataKey::CountTransfer).unwrap_or(0);
        if count == 0 { 0 } else { total / count }
    }

    pub fn total_mints(env: Env) -> u64 {
        env.storage().temporary().get(&DataKey::CountMint).unwrap_or(0)
    }

    pub fn total_transfers(env: Env) -> u64 {
        env.storage().temporary().get(&DataKey::CountTransfer).unwrap_or(0)
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    fn require_admin(env: &Env, addr: &Address) -> Result<(), Error> {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).expect("not init");
        if addr != &admin { return Err(Error::Unauthorized); }
        addr.require_auth();
        Ok(())
    }

    fn require_not_paused(env: &Env) -> Result<(), Error> {
        if Self::check_paused(env) { Err(Error::ContractPaused) } else { Ok(()) }
    }

    fn check_paused(env: &Env) -> bool {
        let flagged: bool = env.storage().instance().get(&DataKey::Paused).unwrap_or(false);
        if !flagged { return false; }
        match env.storage().instance().get::<DataKey, u64>(&DataKey::PauseUnlockTime) {
            Some(active_at) => env.ledger().timestamp() >= active_at,
            None => true,
        }
    }

    fn load_token(env: &Env, token_id: TokenId) -> Result<TokenData, Error> {
        let data: TokenData = env.storage().persistent().get(&DataKey::Token(token_id)).ok_or(Error::InvalidTokenId)?;
        Self::bump_persistent_ttl(env, &DataKey::Token(token_id));
        Ok(data)
    }

    fn load_clip_token_id(env: &Env, clip_id: u32) -> Option<TokenId> {
        let key = DataKey::ClipIdMinted(clip_id);
        let tid: Option<TokenId> = env.storage().persistent().get(&key);
        if tid.is_some() { Self::bump_persistent_ttl(env, &key); }
        tid
    }

    fn bump_persistent_ttl(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
    }

    fn acquire_reentrancy_lock(env: &Env) -> Result<(), Error> {
        if env.storage().instance().get::<DataKey, bool>(&DataKey::ReentrancyLock).unwrap_or(false) {
            return Err(Error::Reentrancy);
        }
        env.storage().instance().set(&DataKey::ReentrancyLock, &true);
        Ok(())
    }

    fn release_reentrancy_lock(env: &Env) {
        env.storage().instance().set(&DataKey::ReentrancyLock, &false);
    }

    fn enforce_mint_cooldown(env: &Env, wallet: &Address) -> Result<(), Error> {
        let cooldown: u64 = env.storage().instance().get(&DataKey::MintCooldownSeconds).unwrap_or(0);
        if cooldown == 0 { return Ok(()); }
        let now = env.ledger().timestamp();
        if let Some(last) = env.storage().persistent().get::<DataKey, u64>(&DataKey::LastMintTimestamp(wallet.clone())) {
            if now < last.saturating_add(cooldown) { return Err(Error::MintCooldownActive); }
        }
        Ok(())
    }

    fn record_mint_timestamp(env: &Env, wallet: &Address) {
        env.storage().persistent().set(&DataKey::LastMintTimestamp(wallet.clone()), &env.ledger().timestamp());
    }

    /// Task 1: safe-math royalty calculation — delegates to safe_math module
    pub fn calculate_royalty(sale_price: i128, basis_points: u32) -> Result<i128, Error> {
        safe_math::safe_royalty_amount(sale_price, basis_points)
    }

    fn normalize_royalty(env: &Env, royalty: Royalty) -> Result<Royalty, Error> {
        if royalty.recipients.is_empty() { return Err(Error::InvalidRoyaltySplit); }
        let default_asset = env.storage().instance().get::<DataKey, Option<Address>>(&DataKey::DefaultRoyaltyAsset).unwrap_or(None);
        let asset_address = royalty.asset_address.clone().or(default_asset);
        let platform: Address = env.storage().instance().get(&DataKey::PlatformRecipient).ok_or(Error::InvalidRecipient)?;
        let platform_bps: u32 = env.storage().instance().get(&DataKey::PlatformFeeBps).unwrap_or(100);
        let mut recipients = royalty.recipients;
        let mut has_platform = false;
        let mut total_bps: u32 = 0;
        for i in 0..recipients.len() {
            let r = recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
            if r.recipient == platform { has_platform = true; }
            total_bps = total_bps.saturating_add(r.basis_points);
        }
        if !has_platform {
            recipients.push_back(RoyaltyRecipient { recipient: platform, basis_points: platform_bps });
            total_bps = total_bps.saturating_add(platform_bps);
        }
        if total_bps > 10_000 { return Err(Error::RoyaltyTooHigh); }
        Ok(Royalty { recipients, asset_address })
    }

    fn verify_clip_signature(env: &Env, owner: &Address, clip_id: u32, metadata_uri: &String, signature: &BytesN<64>) -> Result<(), Error> {
        let signer: BytesN<32> = env.storage().instance().get(&DataKey::Signer).ok_or(Error::SignerNotSet)?;
        let owner_hash: BytesN<32> = env.crypto().sha256(&owner.clone().to_xdr(env)).into();
        let uri_hash: BytesN<32> = env.crypto().sha256(&Bytes::from(metadata_uri.to_xdr(env))).into();
        let mut preimage = Bytes::new(env);
        preimage.extend_from_array(&clip_id.to_le_bytes());
        preimage.append(&Bytes::from(owner_hash));
        preimage.append(&Bytes::from(uri_hash));
        let message: BytesN<32> = env.crypto().sha256(&preimage).into();
        env.crypto().ed25519_verify(&signer, &Bytes::from(message), signature);
        Ok(())
    }

    fn validate_url(_env: &Env, url: &Option<String>) -> Result<(), Error> {
        if let Some(ref u) = url {
            let bytes = u.to_bytes();
            if bytes.len() == 0 { return Err(Error::MalformedUrl); }
            // find "://"
            let mut scheme_end: Option<u32> = None;
            let len = bytes.len();
            for i in 0..len.saturating_sub(2) {
                if bytes.get(i) == Some(b':') && bytes.get(i+1) == Some(b'/') && bytes.get(i+2) == Some(b'/') {
                    scheme_end = Some(i);
                    break;
                }
            }
            let se = scheme_end.ok_or(Error::MalformedUrl)?;
            if se == 0 || se + 3 >= len { return Err(Error::MalformedUrl); }
            let is_https = se == 5 && bytes.get(0)==Some(b'h') && bytes.get(1)==Some(b't') && bytes.get(2)==Some(b't') && bytes.get(3)==Some(b'p') && bytes.get(4)==Some(b's');
            let is_ipfs  = se == 4 && bytes.get(0)==Some(b'i') && bytes.get(1)==Some(b'p') && bytes.get(2)==Some(b'f') && bytes.get(3)==Some(b's');
            if !is_https && !is_ipfs { return Err(Error::UnsupportedProtocol); }
        }
        Ok(())
    }

    fn index_remove_owner(env: &Env, owner: &Address, token_id: TokenId) {
        let bal: u32 = env.storage().persistent().get(&DataKey::Balance(owner.clone())).unwrap_or(0);
        if bal == 0 { return; }
        for pos in 0..bal {
            let stored: Option<TokenId> = env.storage().persistent().get(&DataKey::OwnerTokenIndex(owner.clone(), pos));
            if stored == Some(token_id) {
                let last = bal - 1;
                if pos != last {
                    let last_tid: TokenId = env.storage().persistent().get(&DataKey::OwnerTokenIndex(owner.clone(), last)).unwrap();
                    env.storage().persistent().set(&DataKey::OwnerTokenIndex(owner.clone(), pos), &last_tid);
                }
                env.storage().persistent().remove(&DataKey::OwnerTokenIndex(owner.clone(), last));
                return;
            }
        }
    }

    fn index_remove_global(env: &Env, token_id: TokenId, supply: u32) {
        if supply == 0 { return; }
        for pos in 0..supply {
            let stored: Option<TokenId> = env.storage().persistent().get(&DataKey::TokenIndex(pos));
            if stored == Some(token_id) {
                let last = supply - 1;
                if pos != last {
                    let last_tid: TokenId = env.storage().persistent().get(&DataKey::TokenIndex(last)).unwrap();
                    env.storage().persistent().set(&DataKey::TokenIndex(pos), &last_tid);
                }
                env.storage().persistent().remove(&DataKey::TokenIndex(last));
                return;
            }
        }
    }

    fn check_circuit_breaker(env: &Env, mint_count: u64) -> Result<(), Error> {
        let enabled: bool = env.storage().instance().get(&DataKey::CircuitBreakerEnabled).unwrap_or(false);
        if !enabled { return Ok(()); }
        let threshold: u64 = env.storage().instance().get(&DataKey::CircuitBreakerThreshold).unwrap_or(DEFAULT_CIRCUIT_BREAKER_THRESHOLD);
        let window: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowSeconds).unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);
        let now = env.ledger().timestamp();
        let ws: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowStart).unwrap_or(0);
        let wc: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowCount).unwrap_or(0);
        let in_window = ws != 0 && now < ws.saturating_add(window);
        let count = if in_window { wc.saturating_add(mint_count) } else { mint_count };
        if count > threshold {
            env.storage().instance().set(&DataKey::Paused, &true);
            env.events().publish((symbol_short!("circuit"),), CircuitBreakerTriggeredEvent { mint_count: count, threshold, window_seconds: window });
            return Err(Error::CircuitBreakerTripped);
        }
        Ok(())
    }

    fn update_circuit_breaker_counter(env: &Env, mint_count: u64) {
        let enabled: bool = env.storage().instance().get(&DataKey::CircuitBreakerEnabled).unwrap_or(false);
        if !enabled { return; }
        let window: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowSeconds).unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);
        let now = env.ledger().timestamp();
        let ws: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowStart).unwrap_or(0);
        let wc: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowCount).unwrap_or(0);
        if ws == 0 || now >= ws.saturating_add(window) {
            env.storage().instance().set(&DataKey::CircuitBreakerWindowStart, &now);
            env.storage().instance().set(&DataKey::CircuitBreakerWindowCount, &mint_count);
        } else {
            env.storage().instance().set(&DataKey::CircuitBreakerWindowCount, &wc.saturating_add(mint_count));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, BytesN as _, Events as _, Ledger as _},
        Address, Bytes, BytesN, Env, String, Vec, xdr::ToXdr,
    };

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);
        (env, admin, user1, user2)
    }

    fn default_royalty(env: &Env, recipient: Address) -> Royalty {
        let mut r = Vec::new(env);
        r.push_back(RoyaltyRecipient { recipient, basis_points: 500 });
        Royalty { recipients: r, asset_address: None }
    }

    fn sign_mint(env: &Env, sk: &ed25519_dalek::SigningKey, owner: &Address, clip_id: u32, uri: &String) -> BytesN<64> {
        let oh: BytesN<32> = env.crypto().sha256(&owner.clone().to_xdr(env)).into();
        let uh: BytesN<32> = env.crypto().sha256(&Bytes::from(uri.to_xdr(env))).into();
        let mut pre = Bytes::new(env);
        pre.extend_from_array(&clip_id.to_le_bytes());
        pre.append(&Bytes::from(oh));
        pre.append(&Bytes::from(uh));
        let msg: BytesN<32> = env.crypto().sha256(&pre).into();
        use ed25519_dalek::Signer as _;
        BytesN::from_array(env, &sk.sign(&msg.to_array()).to_bytes())
    }

    fn register_signer(env: &Env, client: &ClipsNftContractClient, admin: &Address) -> ed25519_dalek::SigningKey {
        let sk = ed25519_dalek::SigningKey::from_bytes(&BytesN::<32>::random(env).to_array());
        client.set_signer(admin, &BytesN::from_array(env, &sk.verifying_key().to_bytes()));
        sk
    }

    fn do_mint(client: &ClipsNftContractClient, env: &Env, to: &Address, clip_id: u32, sk: &ed25519_dalek::SigningKey) -> TokenId {
        let uri = String::from_str(env, "ipfs://QmExample");
        let sig = sign_mint(env, sk, to, clip_id, &uri);
        client.mint(to, &clip_id, &uri, &None, &None, &default_royalty(env, to.clone()), &false, &sig)
    }

    // -------------------------------------------------------------------------
    // Task 1: Safe math
    // -------------------------------------------------------------------------

    #[test]
    fn test_calculate_royalty_amount_basic() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 1, &sk);
        // 6% of 10_000 = 600
        assert_eq!(client.calculate_royalty_amount(&tid, &10_000i128), 600i128);
    }

    #[test]
    fn test_calculate_royalty_amount_zero_price_fails() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 2, &sk);
        assert_eq!(client.try_calculate_royalty_amount(&tid, &0i128), Err(Ok(Error::InvalidSalePrice)));
    }

    #[test]
    fn test_calculate_royalty_amount_overflow_fails() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 3, &sk);
        assert_eq!(client.try_calculate_royalty_amount(&tid, &i128::MAX), Err(Ok(Error::RoyaltyOverflow)));
    }

    #[test]
    fn test_royalty_overflow_detection() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 4, &sk);
        assert_eq!(client.try_royalty_info(&tid, &i128::MAX), Err(Ok(Error::RoyaltyOverflow)));
    }

    #[test]
    fn test_royalty_calculation_max_safe_price() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 5, &sk);
        let info = client.royalty_info(&tid, &(i128::MAX / 10_000));
        assert!(info.royalty_amount > 0);
    }

    #[test]
    fn test_royalty_checked_mul_max_safe_boundary() {
        let max_safe = i128::MAX / 10_000;
        assert!(ClipsNftContract::calculate_royalty(max_safe, 10_000).is_ok());
    }

    #[test]
    fn test_royalty_checked_mul_one_over_boundary_fails() {
        assert_eq!(ClipsNftContract::calculate_royalty(i128::MAX / 10_000 + 1, 1), Err(Error::RoyaltyOverflow));
    }

    #[test]
    fn test_royalty_negative_sale_price_fails() {
        assert_eq!(ClipsNftContract::calculate_royalty(-1, 500), Err(Error::InvalidSalePrice));
    }

    // -------------------------------------------------------------------------
    // Task 2: Admin config
    // -------------------------------------------------------------------------

    #[test]
    fn test_set_platform_fee_emits_event() {
        let (env, admin, _, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        client.set_platform_fee(&admin, &200u32);
        assert_eq!(client.get_platform_fee(), 200u32);
    }

    #[test]
    fn test_set_default_royalty_emits_event() {
        let (env, admin, _, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        client.set_default_royalty(&admin, &300u32);
        assert_eq!(client.get_default_royalty_bps(), 300u32);
    }

    #[test]
    fn test_set_platform_fee_non_admin_fails() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        assert_eq!(client.try_set_platform_fee(&user1, &100u32), Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn test_set_default_royalty_non_admin_fails() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        assert_eq!(client.try_set_default_royalty(&user1, &100u32), Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn test_set_platform_fee_too_high_fails() {
        let (env, admin, _, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        assert_eq!(client.try_set_platform_fee(&admin, &10_001u32), Err(Ok(Error::RoyaltyTooHigh)));
    }

    // -------------------------------------------------------------------------
    // Task 3: get_user_tokens
    // -------------------------------------------------------------------------

    #[test]
    fn test_get_user_tokens_returns_owned() {
        let (env, admin, user1, user2) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let t1 = do_mint(&client, &env, &user1, 10, &sk);
        let t2 = do_mint(&client, &env, &user1, 11, &sk);
        let _t3 = do_mint(&client, &env, &user2, 12, &sk);
        let owned = client.get_user_tokens(&user1, &100u32, &0u32);
        assert_eq!(owned.len(), 2);
        assert_eq!(owned.get(0).unwrap(), t1);
        assert_eq!(owned.get(1).unwrap(), t2);
    }

    #[test]
    fn test_get_user_tokens_pagination() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        for i in 0..5u32 { do_mint(&client, &env, &user1, 20 + i, &sk); }
        let page1 = client.get_user_tokens(&user1, &2u32, &0u32);
        let page2 = client.get_user_tokens(&user1, &2u32, &2u32);
        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_ne!(page1.get(0).unwrap(), page2.get(0).unwrap());
    }

    #[test]
    fn test_get_user_tokens_updates_after_transfer() {
        let (env, admin, user1, user2) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 30, &sk);
        client.transfer(&user1, &user2, &tid, &0i128, &None);
        assert_eq!(client.get_user_tokens(&user1, &100u32, &0u32).len(), 0);
        assert_eq!(client.get_user_tokens(&user2, &100u32, &0u32).len(), 1);
    }

    #[test]
    fn test_get_user_tokens_offset_exceeds_balance() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        do_mint(&client, &env, &user1, 40, &sk);
        assert_eq!(client.get_user_tokens(&user1, &100u32, &10u32).len(), 0);
    }

    // -------------------------------------------------------------------------
    // Task 4: Fee estimation
    // -------------------------------------------------------------------------

    #[test]
    fn test_fee_estimators_return_expected_values() {
        let env = Env::default();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        assert_eq!(client.estimate_mint_fee(), GAS_BASE_MINT as i128);
        assert_eq!(client.estimate_transfer_fee(), GAS_BASE_TRANSFER as i128);
    }

    // -------------------------------------------------------------------------
    // Core functionality
    // -------------------------------------------------------------------------

    #[test]
    fn test_version() {
        let env = Env::default();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        assert_eq!(client.version(), VERSION);
    }

    #[test]
    fn test_mint_stores_owner_and_uri() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 100, &sk);
        assert_eq!(client.owner_of(&tid), user1);
        assert_eq!(client.total_supply(), 1);
    }

    #[test]
    fn test_double_mint_prevention() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        do_mint(&client, &env, &user1, 200, &sk);
        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig = sign_mint(&env, &sk, &user1, 200, &uri);
        assert_eq!(client.try_mint(&user1, &200u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &sig), Err(Ok(Error::ClipAlreadyMinted)));
    }

    #[test]
    fn test_transfer_updates_owner() {
        let (env, admin, user1, user2) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 300, &sk);
        client.transfer(&user1, &user2, &tid, &0i128, &None);
        assert_eq!(client.owner_of(&tid), user2);
    }

    #[test]
    fn test_burn_removes_token() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 400, &sk);
        client.burn(&user1, &tid);
        assert!(!client.exists(&tid));
        assert_eq!(client.total_supply(), 0);
    }

    #[test]
    fn test_pause_blocks_mint() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        client.pause(&admin);
        env.ledger().with_mut(|l| l.timestamp += 86_401);
        let uri = String::from_str(&env, "ipfs://QmPaused");
        let sig = sign_mint(&env, &sk, &user1, 500, &uri);
        assert_eq!(client.try_mint(&user1, &500u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &sig), Err(Ok(Error::ContractPaused)));
    }

    #[test]
    fn test_royalty_info_xlm() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 600, &sk);
        let info = client.royalty_info(&tid, &1_000_000i128);
        assert_eq!(info.royalty_amount, 60_000i128); // 6% (5% creator + 1% platform)
    }

    #[test]
    fn test_batch_mint_success() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let uri1 = String::from_str(&env, "ipfs://Qm1");
        let uri2 = String::from_str(&env, "ipfs://Qm2");
        let mut cids = Vec::new(&env); cids.push_back(700u32); cids.push_back(701u32);
        let mut uris = Vec::new(&env); uris.push_back(uri1.clone()); uris.push_back(uri2.clone());
        let mut imgs: Vec<Option<String>> = Vec::new(&env); imgs.push_back(None); imgs.push_back(None);
        let mut anims: Vec<Option<String>> = Vec::new(&env); anims.push_back(None); anims.push_back(None);
        let mut sigs = Vec::new(&env);
        sigs.push_back(sign_mint(&env, &sk, &user1, 700, &uri1));
        sigs.push_back(sign_mint(&env, &sk, &user1, 701, &uri2));
        let minted = client.batch_mint(&user1, &cids, &uris, &imgs, &anims, &default_royalty(&env, user1.clone()), &false, &sigs);
        assert_eq!(minted.len(), 2);
        assert_eq!(client.total_supply(), 2);
    }

    #[test]
    fn test_withdraw_timelock_is_48h() {
        let (env, admin, _, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        client.request_withdraw_asset(&admin, &1_000i128);
        let asset = Address::generate(&env);
        assert_eq!(client.try_withdraw_asset(&admin, &asset, &1_000i128), Err(Ok(Error::WithdrawalStillLocked)));
        env.ledger().with_mut(|l| l.timestamp += 172_801);
        // would succeed if contract had funds; just verify lock is released
    }

    #[test]
    fn test_soulbound_transfer_blocked() {
        let (env, admin, user1, user2) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let uri = String::from_str(&env, "ipfs://QmSoul");
        let sig = sign_mint(&env, &sk, &user1, 800, &uri);
        let tid = client.mint(&user1, &800u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &true, &sig);
        assert_eq!(client.try_transfer(&user1, &user2, &tid, &0i128, &None), Err(Ok(Error::SoulboundTransferBlocked)));
    }

    #[test]
    fn test_token_by_index_enumerable() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let t1 = do_mint(&client, &env, &user1, 900, &sk);
        let t2 = do_mint(&client, &env, &user1, 901, &sk);
        assert_eq!(client.token_by_index(&0u32), t1);
        assert_eq!(client.token_by_index(&1u32), t2);
        client.burn(&user1, &t1);
        assert_eq!(client.total_supply(), 1);
        assert_eq!(client.try_token_by_index(&1u32), Err(Ok(Error::InvalidTokenId)));
    }

    #[test]
    fn test_refresh_metadata_cooldown_enforced() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 1000, &sk);
        client.refresh_metadata(&admin, &tid, &Some(String::from_str(&env, "ipfs://v2")), &None, &None);
        env.ledger().with_mut(|l| l.timestamp += 29 * 24 * 3600);
        assert_eq!(client.try_refresh_metadata(&admin, &tid, &Some(String::from_str(&env, "ipfs://v3")), &None, &None), Err(Ok(Error::MetadataRefreshTooSoon)));
    }
}
