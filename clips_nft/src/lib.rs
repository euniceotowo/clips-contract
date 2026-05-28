//! ClipCash NFT — Soroban Smart Contract
//!
//! Enables minting video clips as NFTs on the Stellar network with built-in
//! royalty support for content creators. Royalties can be paid in XLM or any
//! SEP-0041 custom Stellar asset.
//!
//! # Clip verification
//!
//! Before a clip can be minted the backend must sign a verification payload
//! with its Ed25519 private key. The contract verifies the signature on-chain
//! using `env.crypto().ed25519_verify()`.
//!
//! ## Payload format
//!
//! ```text
//! payload = SHA-256( clip_id_le_bytes || SHA-256(owner_xdr) || SHA-256(metadata_uri_bytes) )
//! ```
//!
//! # Storage layout
//!
//! | Tier       | Keys                                              |
//! |------------|---------------------------------------------------|
//! | instance   | Admin, NextTokenId, Paused, Signer, Name, Symbol, PlatformRecipient |
//! | persistent | Token(id), ClipIdMinted(clip_id), Approved(id), ApprovalForAll(owner,op), BlacklistedClip(clip_id), Balance(owner) |
//!
//! # Privileged entrypoints (admin-only)
//!
//! ## Storage tiers used
//! - `instance`   – cheap, loaded once per tx, shared across all calls in the tx.
//!   Used for: Admin, NextTokenId, Paused, Signer.
//! - `persistent` – per-entry fee, survives ledger expiry extension.
//!   Used for: TokenData (owner+clip_id packed), Metadata, Royalty,
//!   ClipIdMinted (dedup guard), Balance (owner balance checkpoint).

#![no_std]

pub mod safe_math;

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, Bytes,
    BytesN, Env, String, Vec,
};

/// Contract version — bump on every breaking change.
pub const VERSION: u32 = 1;
pub const DEFAULT_MINT_COOLDOWN_SECONDS: u64 = 0;
pub const DEFAULT_CIRCUIT_BREAKER_ENABLED: bool = false;
pub const DEFAULT_CIRCUIT_BREAKER_THRESHOLD: u64 = 100;
pub const DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS: u64 = 60;

// =============================================================================
// Errors
// =============================================================================

/// All error codes returned by the contract.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Error {
    /// Caller is not authorized for this operation.
    Unauthorized = 1,
    /// Token ID does not exist.
    InvalidTokenId = 2,
    /// Clip has already been minted.
    ClipAlreadyMinted = 3,
    /// Total royalty basis points exceed 10 000 (100 %).
    RoyaltyTooHigh = 4,
    /// Royalty recipient address is invalid or missing.
    InvalidRecipient = 5,
    /// Sale price must be greater than zero.
    InvalidSalePrice = 6,
    /// Contract is paused — minting and transfers are blocked.
    ContractPaused = 7,
    /// Backend Ed25519 signature over the mint payload is invalid.
    InvalidSignature = 8,
    /// No backend signer public key has been registered yet.
    SignerNotSet = 9,
    /// Royalty split configuration is invalid.
    InvalidRoyaltySplit = 10,
    /// Token is soulbound (non-transferable).
    SoulboundTransferBlocked = 11,
    /// Royalty calculation would overflow i128.
    RoyaltyOverflow = 12,
    /// Clip ID has been blacklisted by the admin.
    ClipBlacklisted = 13,
    /// Caller is not the owner or an approved operator.
    NotAuthorizedToApprove = 14,
    /// Withdrawal is still locked (24h safety delay)
    WithdrawalStillLocked = 15,
    /// No active withdrawal request found
    NoWithdrawalRequest = 16,
    /// Batch mint request exceeds configured gas-safe limit
    BatchTooLarge = 17,
    /// Token is frozen and cannot be transferred or burned.
    TokenFrozen = 18,
    /// Insufficient balance for this operation.
    InsufficientBalance = 19,
    /// Metadata was refreshed too recently (30-day cooldown not elapsed).
    MetadataRefreshTooSoon = 20,
    /// URL protocol is not supported. Allowed: "https://" and "ipfs://".
    UnsupportedProtocol = 21,
    /// URL format is malformed.
    MalformedUrl = 22,
    /// Mint attempted before wallet cooldown elapsed.
    MintCooldownActive = 23,
    /// Reentrant call detected while a guarded entrypoint is executing.
    Reentrancy = 24,
    /// Minting is explicitly paused by the admin.
    MintingPaused = 25,
    /// Circuit breaker triggered due to anomalous mint activity.
    CircuitBreakerTripped = 25,
}

// =============================================================================
// Types
// =============================================================================

/// Opaque token identifier (auto-incremented u32).
pub type TokenId = u32;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    pub trait_type: String,
    pub value: String,
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
    /// When `true` the metadata is permanently frozen and can never be changed again.
    pub is_locked: bool,
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

impl Royalty {
    /// Compute the total royalty amount for a sale price using all recipients.
    ///
    /// This is the canonical internal helper used across royalty view and
    /// payment paths.
    fn calculate_royalty(&self, sale_price: i128) -> Result<i128, Error> {
        if sale_price <= 0 {
            return Err(Error::InvalidSalePrice);
        }

        let mut total_bps: u32 = 0;
        for idx in 0..self.recipients.len() {
            let split = self.recipients.get(idx).ok_or(Error::InvalidRoyaltySplit)?;
            total_bps = total_bps.saturating_add(split.basis_points);
        }

        ClipsNftContract::calculate_royalty(sale_price, total_bps)
    }
}

/// Royalty payment info returned by [`ClipsNftContract::royalty_info`].
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

// =============================================================================
// Storage keys
// =============================================================================

#[contracttype]
pub enum DataKey {
    Admin,
    NextTokenId,
    Paused,
    PauseReason,
    Name,
    Symbol,
    Token(TokenId),
    ClipIdMinted(u32),
    CustomTokenUri(TokenId),
    Signer,
    /// Backend address authorized to refresh metadata (instance).
    BackendAddress,
    /// Platform address that always receives the default 1 % royalty cut (instance).
    PlatformRecipient,
    Approved(TokenId),
    MetadataUpdateCount(TokenId),
    ApprovalForAll(Address, Address),
    BlacklistedClip(u32),
    WithdrawXlmRequest,
    LastWithdrawalTime,
    Balance(Address),
    TotalSupply,
    /// Gas tracking fields (temporary — metrics only, not critical state)
    TotalGasMint,
    CountMint,
    TotalGasTransfer,
    CountTransfer,
    Frozen(TokenId),
    MetadataRefreshTime(TokenId),
    PauseUnlockTime,
    PlatformFeeBps,
    DefaultRoyaltyBps,
    /// Default royalty asset contract for new mints when token royalty asset is omitted.
    DefaultRoyaltyAsset,
    /// Accumulated royalty balance per token (persistent).
    RoyaltyBalance(TokenId),
    LastMintTimestamp(Address),
    MintCooldownSeconds,
    ReentrancyLock,
    /// Circuit breaker enabled flag (instance).
    CircuitBreakerEnabled,
    /// Circuit breaker: max mints allowed in time window (instance).
    CircuitBreakerThreshold,
    /// Circuit breaker: time window duration in seconds (instance).
    CircuitBreakerWindowSeconds,
    /// Circuit breaker: start timestamp of current window (instance).
    CircuitBreakerWindowStart,
    /// Circuit breaker: mint count in current window (instance).
    CircuitBreakerWindowCount,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequest {
    pub amount: i128,
    pub unlock_time: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequestedEvent {
    pub amount: i128,
    pub unlock_time: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawExecutedEvent {
    pub amount: i128,
    pub recipient: Address,
}

// =============================================================================
// Events
// =============================================================================

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintEvent {
    pub to: Address,
    pub clip_id: u32,
    pub token_id: TokenId,
    pub metadata_uri: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BurnEvent {
    pub owner: Address,
    pub token_id: TokenId,
    pub clip_id: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferEvent {
    pub token_id: TokenId,
    pub from: Address,
    pub to: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlacklistEvent {
    pub clip_id: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalEvent {
    pub owner: Address,
    pub operator: Address,
    pub token_id: TokenId,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalForAllEvent {
    pub owner: Address,
    pub operator: Address,
    pub approved: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyPaidEvent {
    pub token_id: TokenId,
    pub from: Address,
    pub to: Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyRecipientUpdatedEvent {
    pub token_id: TokenId,
    pub old_recipient: Address,
    pub new_recipient: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenUriChangedEvent {
    pub token_id: TokenId,
    pub owner: Address,
    pub new_uri: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeEvent {
    pub new_wasm_hash: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchMintEvent {
    pub to: Address,
    pub count: u32,
    pub first_token_id: TokenId,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataUpdatedEvent {
    pub token_id: TokenId,
    pub old_uri: String,
    pub new_uri: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenFrozenEvent {
    pub token_id: TokenId,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenUnfrozenEvent {
    pub token_id: TokenId,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerUpdatedEvent {
    pub new_pubkey: BytesN<32>,
}

/// Emitted when the platform recipient address is updated by the admin.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformRecipientUpdatedEvent {
    pub new_recipient: Address,
}

/// Emitted when a token's royalty configuration is updated by the admin.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyUpdatedEvent {
    pub token_id: TokenId,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseScheduledEvent {
    pub active_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionUpdatedEvent {
    pub field: String,
    pub new_value: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigUpdatedEvent {
    pub key: String,
    pub new_value: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyClaimedEvent {
    pub token_id: TokenId,
    pub recipient: Address,
    pub amount: i128,
    pub asset: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChangedEvent {
    pub old_admin: Address,
    pub new_admin: Address,
}

/// Emitted when an NFT is burned and optional unclaimed royalties are refunded.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundedEvent {
    pub token_id: TokenId,
    pub recipient: Address,
    pub amount: i128,
}
/// Emitted when the circuit breaker is triggered automatically.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitBreakerTriggeredEvent {
    pub mint_count: u64,
    pub threshold: u64,
    pub window_seconds: u64,
}

/// Emitted when a soulbound token is recovered to a new owner via platform signature.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoulboundRecoveredEvent {
    pub token_id: TokenId,
    pub old_owner: Address,
    pub new_owner: Address,
}


/// Emerging Soroban NFT standard interface (ERC-721 adapted).
pub trait NftStandard {
    fn balance_of(env: Env, owner: Address) -> u32;
    fn owner_of(env: Env, token_id: TokenId) -> Result<Address, Error>;
    fn transfer(env: Env, from: Address, to: Address, token_id: TokenId) -> Result<(), Error>;
    /// Transfers `token_id` from `from` to `to`.
    fn transfer(
        env: Env,
        from: Address,
        to: Address,
        token_id: TokenId,
        sale_price: i128,
        payment_asset: Option<Address>,
    ) -> Result<(), Error>;
    /// Approves `operator` to manage `token_id` (or clears approval when `None`).
    fn approve(env: Env, caller: Address, operator: Option<Address>, token_id: TokenId) -> Result<(), Error>;
    fn get_approved(env: Env, token_id: TokenId) -> Option<Address>;
    fn set_approval_for_all(env: Env, caller: Address, operator: Address, approved: bool) -> Result<(), Error>;
    fn is_approved_for_all(env: Env, owner: Address, operator: Address) -> bool;
    fn total_supply(env: Env) -> u32;
    fn token_uri(env: Env, token_id: TokenId) -> Result<String, Error>;
    fn name(env: Env) -> String;
    fn symbol(env: Env) -> String;
    /// Revokes approval for a specific token ID.
    fn revoke_approval(env: Env, token_id: TokenId) -> Result<(), Error>;
    /// Revokes approval for an operator managing all caller tokens.
    fn revoke_all_approvals(env: Env, operator: Address) -> Result<(), Error>;
    /// Destroys a token and handles optional remaining royalty refund matching criteria.
    fn burn(env: Env, token_id: TokenId, refund_royalty: bool) -> Result<(), Error>;
}

// =============================================================================
// Contract Implementation
// =============================================================================

/// ClipCash NFT contract.
#[contract]
pub struct ClipsNftContract;

/// Synthetic gas constants for fee estimation (approximations).
///
/// These are fixed estimates used for tracking and fee estimation purposes.
/// They do not reflect actual gas costs but provide consistent values for
/// contract analytics and user-facing fee estimates.
const GAS_BASE_MINT: u64 = 50_000;
const GAS_BASE_TRANSFER: u64 = 30_000;
const MAX_BATCH_MINT: u32 = 25;
const PERSISTENT_BUMP_THRESHOLD: u32 = 172_800;
const PERSISTENT_BUMP_AMOUNT: u32 = 535_680;

#[contractimpl]
impl NftStandard for ClipsNftContract {
    /// Returns how many tokens `owner` holds.
    ///
    /// # Arguments
    /// * `admin` — Address that becomes the contract administrator.
    pub fn init(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::NextTokenId, &1u32);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::MintingPaused, &false);
        env.storage().instance().set(&DataKey::PlatformRecipient, &admin);
        env.storage().instance().set(&DataKey::DefaultRoyaltyAsset, &Option::<Address>::None);
        env.storage()
            .instance()
            .set(&DataKey::Name, &String::from_str(&env, "ClipCash Clips"));
        env.storage()
            .instance()
            .set(&DataKey::Symbol, &String::from_str(&env, "CLIP"));
        env.storage()
            .persistent()
            .get(&DataKey::Balance(owner))
            .unwrap_or(0u32)
            .instance()
            .set(&DataKey::MintCooldownSeconds, &DEFAULT_MINT_COOLDOWN_SECONDS);
        // Initialize circuit breaker with default values
        env.storage()
            .instance()
            .set(&DataKey::CircuitBreakerEnabled, &DEFAULT_CIRCUIT_BREAKER_ENABLED);
        env.storage()
            .instance()
            .set(&DataKey::CircuitBreakerThreshold, &DEFAULT_CIRCUIT_BREAKER_THRESHOLD);
        env.storage()
            .instance()
            .set(&DataKey::CircuitBreakerWindowSeconds, &DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);
        env.storage()
            .instance()
            .set(&DataKey::CircuitBreakerWindowStart, &0u64);
        env.storage()
            .instance()
            .set(&DataKey::CircuitBreakerWindowCount, &0u64);
        // Initialize backend address to admin by default
        env.storage()
            .instance()
            .set(&DataKey::BackendAddress, &admin);
        // Signer is not set at init — call set_signer before minting.
    }

    /// Mints a token and increments the receiver balance map.
    ///
    /// Closes #194 - Check if specific minting pause flag is active
    pub fn mint(
        env: Env,
        to: Address,
        clip_id: u32,
        metadata_uri: String,
        royalty_recipients: Vec<RoyaltyRecipient>,
        asset_address: Option<Address>,
        is_soulbound: bool,
    ) -> Result<TokenId, Error> {
        if Self::check_paused(&env) {
            return Err(Error::ContractPaused);
        }

        if Self::is_minting_paused(&env) {
            return Err(Error::MintingPaused);
        }

        if env.storage().persistent().has(&DataKey::ClipIdMinted(clip_id)) {
            return Err(Error::ClipAlreadyMinted);
        }

        if env.storage().persistent().has(&DataKey::BlacklistedClip(clip_id)) {
            return Err(Error::ClipBlacklisted);
        }

        let token_id: u32 = env.storage().instance().get(&DataKey::NextTokenId).unwrap_or(1);
        env.storage().instance().set(&DataKey::NextTokenId, &(token_id + 1));

        let royalty = Royalty {
            recipients: royalty_recipients,
            asset_address,
        };

        let token_data = TokenData {
            owner: to.clone(),
            clip_id,
            is_soulbound,
            metadata_uri: metadata_uri.clone(),
            image: None,
            animation_url: None,
            description: None,
            external_url: None,
            attributes: Vec::new(&env),
            royalty,
        };

        env.storage().persistent().set(&DataKey::Token(token_id), &token_data);
        env.storage().persistent().set(&DataKey::ClipIdMinted(clip_id), &token_id);

        let current_bal = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0u32);
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &(current_bal + 1));

        env.events().publish(
            (symbol_short!("mint"),),
            MintEvent {
                to,
                clip_id,
                token_id,
                metadata_uri,
            },
        );

        Ok(token_id)
    }

    /// Pause minting operations only. Existing tokens can still be transferred.
    ///
    /// Closes #194
    pub fn pause_minting(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::MintingPaused, &true);
        env.events().publish((symbol_short!("p_mint"),), ());
        Ok(())
    }

    /// Unpause minting operations.
    ///
    /// Closes #194
    pub fn unpause_minting(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::MintingPaused, &false);
        env.events().publish((symbol_short!("up_mint"),), ());
        Ok(())
    }

    /// Returns `true` if minting operations are currently paused.
    pub fn is_minting_paused(env: &Env) -> bool {
        env.storage().instance().get(&DataKey::MintingPaused).unwrap_or(false)
    }

    pub fn set_signer(env: Env, admin: Address, pubkey: BytesN<32>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Signer, &pubkey);
        env.events().publish((symbol_short!("sgn_upd"),), SignerUpdatedEvent { new_pubkey: pubkey });
        Ok(())
    }

    fn owner_of(env: Env, token_id: TokenId) -> Result<Address, Error> {
        let token_data: TokenData = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .ok_or(Error::InvalidTokenId)?;
        Ok(token_data.owner)
    }

    /// Set the backend address authorized to refresh metadata.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// # Arguments
    /// * `admin`          — Must be the contract admin.
    /// * `backend_address` — Address authorized to call refresh_metadata.
    pub fn set_backend_address(env: Env, admin: Address, backend_address: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::BackendAddress, &backend_address);
        Ok(())
    }

    /// Return the currently registered backend address, if any.
    pub fn get_backend_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::BackendAddress)
    }

    /// Transfer contract admin rights to a new address.
    ///
    /// ⚠️ **Access Control: current admin only.**
    ///
    /// Emits: `"adm_chg"` [`AdminChangedEvent`].
    ///
    /// # Arguments
    /// * `current_admin` — Must be the current contract admin.
    /// * `new_admin`      — Address that will become the new admin.
    ///
    /// # Errors
    /// * [`Error::Unauthorized`] — `current_admin` is not the stored admin.
    ///
    /// Closes #199 - Map-based Balance Synchronization
    fn transfer(env: Env, from: Address, to: Address, token_id: TokenId) -> Result<(), Error> {
        if Self::is_paused(&env) {
            return Err(Error::ContractPaused);
        }

        let token_key = DataKey::Token(token_id);
        let mut token_data: TokenData = env
            .storage()
            .persistent()
            .get(&token_key)
            .ok_or(Error::InvalidTokenId)?;

    /// Upgrade the contract to a new WASM implementation.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// Replaces the current contract code with the new WASM hash while
    /// preserving all instance and persistent storage.
    ///
    /// After calling this, invoke [`ClipsNftContract::migrate`] on the new
    /// code to run any data-migration logic and bump the stored VERSION.
    ///
    /// # Arguments
    /// * `admin`          — Must be the contract admin.
    /// * `new_wasm_hash` — 32-byte SHA-256 hash of the new WASM blob.
    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        env.events().publish((symbol_short!("upgrade"),), UpgradeEvent { new_wasm_hash });
        Ok(())
    }

    /// Run post-upgrade data migration.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// Must be called once after [`upgrade`] to:
    /// 1. Verify the stored schema version matches what this binary expects.
    /// 2. Apply any storage migrations needed for the new version.
    /// 3. Bump the on-chain `ContractVersion` to `VERSION`.
    ///
    /// The function is idempotent for the same target version — calling it
    /// twice is safe (second call returns `Ok(())` without re-running migrations).
    ///
    /// # Arguments
    /// * `admin` — Must be the contract admin.
    ///
    /// # Errors
    /// * [`Error::Unauthorized`] — caller is not the admin.
    pub fn migrate(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;

        let stored_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::ContractVersion)
            .unwrap_or(0);

        // Already at target version — nothing to do.
        if stored_version >= VERSION {
            return Ok(());
        }

        // ---------------------------------------------------------------
        // Version-gated migration steps.
        // Add a new `if stored_version < N` block for each future version.
        // ---------------------------------------------------------------

        // v0 → v1: seed TotalSupply from NextTokenId if it was never written
        // (contracts deployed before TotalSupply was introduced stored 0).
        if stored_version < 1 {
            let has_total_supply = env
                .storage()
                .instance()
                .has(&DataKey::TotalSupply);

            if !has_total_supply {
                let next_id: u32 = env
                    .storage()
                    .instance()
                    .get(&DataKey::NextTokenId)
                    .unwrap_or(1);
                // total_supply = NextTokenId - 1 (token IDs start at 1).
                let derived = next_id.saturating_sub(1);
                env.storage()
                    .instance()
                    .set(&DataKey::TotalSupply, &derived);
            }
        }

        // Stamp the new version so this block is never re-entered.
        env.storage()
            .instance()
            .set(&DataKey::ContractVersion, &VERSION);

        env.events().publish(
            (symbol_short!("migrated"),),
            MigratedEvent {
                from_version: stored_version,
                to_version: VERSION,
            },
        );

        Ok(())
    }

    /// Returns the on-chain contract schema version (set by [`migrate`]).
    pub fn contract_version(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ContractVersion)
            .unwrap_or(0)
    }

    // -------------------------------------------------------------------------
    // Pausable  ⚠️ PRIVILEGED — admin only
    // -------------------------------------------------------------------------

    /// Schedule a contract pause with a 24-hour timelock.
    ///
    /// the pause becomes active 24 hours after this call. Until then, `mint`
    /// and `transfer` continue to work, giving users advance warning.
    /// Calling `pause` again while a pause is already scheduled or active
    /// resets the 24-hour window from the current time.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// Emits: `"pause_sched"` [`PauseScheduledEvent`] with the activation timestamp.
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let active_at = env.ledger().timestamp().saturating_add(86_400);
        env.storage().instance().set(&DataKey::PauseUnlockTime, &active_at);
        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish((symbol_short!("pse_sched"),), PauseScheduledEvent { active_at });
        Ok(())
    }

        if Self::is_frozen(env.clone(), token_id) {
            return Err(Error::TokenFrozen);
        }

        // Verify authorization (owner, approved operator, or operator for all)
        if from != from {
            let is_approved = env
                .storage()
                .persistent()
                .get(&DataKey::Approved(token_id))
                .map(|addr: Address| addr == from)
                .unwrap_or(false);

            let is_approved_all = env
                .storage()
                .persistent()
                .get(&DataKey::ApprovalForAll(from.clone(), from.clone()))
                .unwrap_or(false);

            if !is_approved && !is_approved_all {
                return Err(Error::Unauthorized);
            }
        }

        // Change owner checkpoint and clear specific token approval mapping values
        token_data.owner = to.clone();
        env.storage().persistent().set(&token_key, &token_data);
        env.storage().persistent().remove(&DataKey::Approved(token_id));

        // Synchronize Balance state map counters atomically
        let from_balance = Self::balance_of(env.clone(), from.clone());
        if from_balance > 0 {
            env.storage().persistent().set(&DataKey::Balance(from.clone()), &(from_balance - 1));
        }

        let to_balance = Self::balance_of(env.clone(), to.clone());
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &(to_balance + 1));

        env.events().publish(
            (symbol_short!("transfer"),),
            TransferEvent {
                token_id,
                from,
                to,
            },
        );

        Ok(())
    }

    fn approve(env: Env, caller: Address, operator: Option<Address>, token_id: TokenId) -> Result<(), Error> {
        let token_data: TokenData = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .ok_or(Error::InvalidTokenId)?;

        if token_data.owner != caller {
            let is_approved_all = env
                .storage()
                .persistent()
                .get(&DataKey::ApprovalForAll(token_data.owner.clone(), caller.clone()))
                .unwrap_or(false);
            if !is_approved_all {
                return Err(Error::Unauthorized);
            }
        }

        caller.require_auth();

        let approval_key = DataKey::Approved(token_id);
        if let Some(op) = operator {
            env.storage().persistent().set(&approval_key, &op);
            env.events().publish(
                (symbol_short!("approval"),),
                ApprovalEvent {
                    owner: token_data.owner,
                    operator: op,
                    token_id,
                },
            );
        } else {
            env.storage().persistent().remove(&approval_key);
        }

        Ok(())
    }

    fn get_approved(env: Env, token_id: TokenId) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Approved(token_id))
    }

    fn set_approval_for_all(env: Env, caller: Address, operator: Address, approved: bool) -> Result<(), Error> {
        caller.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::ApprovalForAll(caller.clone(), operator.clone()), &approved);

        env.events().publish(
            (symbol_short!("app_all"),),
            ApprovalForAllEvent {
                owner: caller,
                operator,
                approved,
            },
        );
        Ok(())
    }

    fn is_approved_for_all(env: Env, owner: Address, operator: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ApprovalForAll(owner, operator))
            .unwrap_or(false)
    }

    fn total_supply(env: Env) -> u32 {
        let next_id: u32 = env.storage().instance().get(&DataKey::NextTokenId).unwrap_or(1);
        next_id.saturating_sub(1)
    }

    fn token_uri(env: Env, token_id: TokenId) -> Result<String, Error> {
        if !env.storage().persistent().has(&DataKey::Token(token_id)) {
            return Err(Error::InvalidTokenId);
        }
        if let Some(custom_uri) = env.storage().persistent().get(&DataKey::CustomTokenUri(token_id)) {
            Ok(custom_uri)
        } else {
            let token_data: TokenData = env.storage().persistent().get(&DataKey::Token(token_id)).unwrap();
            Ok(token_data.metadata_uri)
        }
    }

    fn name(env: Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::Name)
            .unwrap_or_else(|| String::from_str(&env, ""))
    }

    fn symbol(env: Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::Symbol)
            .unwrap_or_else(|| String::from_str(&env, ""))
    }
    // -------------------------------------------------------------------------
    // Approval Revocations
    // -------------------------------------------------------------------------

    /// Revokes marketplace or operator approval for a specific token ID.
    pub fn revoke_approval(env: Env, token_id: TokenId) -> Result<(), Error> {
        let token_data: TokenData = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .ok_or(Error::InvalidTokenId)?;
    /// Mint a new NFT for a video clip.
    ///
    /// Requires a valid Ed25519 `signature` from the registered backend signer
    /// over the canonical mint payload:
    ///
    /// ```text
    /// payload = SHA-256(
    ///     clip_id_le_4_bytes
    ///     || SHA-256(XDR(owner))        // 32 bytes
    ///     || SHA-256(UTF-8(metadata_uri)) // 32 bytes
    /// )
    /// ```
    ///
    /// Storage writes: 2 persistent (TokenData, ClipIdMinted), 1 instance (NextTokenId).
    ///
    /// Emits: `"mint"` [`MintEvent`].
    ///
    /// # Arguments
    /// * `to`           — Address that will own the NFT (must match the signed payload).
    /// * `clip_id`      — Unique off-chain clip identifier (must match the signed payload).
    /// * `metadata_uri` — IPFS or Arweave URI (must match the signed payload).
    /// * `royalty`      — Royalty configuration for secondary sales.
    /// * `is_soulbound` — When `true` the token cannot be transferred.
    /// * `signature`    — 64-byte Ed25519 signature from the registered backend signer.
    ///
    /// # Errors
    /// * [`Error::ContractPaused`] — contract is paused.
    /// * [`Error::SignerNotSet`]   — no signer registered.
    /// * [`Error::InvalidSignature`] — signature verification failed.
    /// * [`Error::ClipAlreadyMinted`] — clip already has a token.
    /// * [`Error::ClipBlacklisted`] — clip ID is blacklisted.
    /// * [`Error::RoyaltyTooHigh`] — total basis points exceed 10 000.
    /// Mint a new NFT token.
    ///
    /// # Arguments
    /// * `to` — Recipient address (must authorize the call).
    /// * `clip_id` — Off-chain clip identifier.
    /// * `metadata_uri` — Metadata URI (IPFS or Arweave).
    /// * `image` — Static thumbnail URL (optional). Must start with "https://" or "ipfs://".
    ///   Recommended formats: PNG, JPEG, GIF (static), SVG. Max 100 MB.
    /// * `animation_url` — Animated preview URL (optional). Must start with "https://" or "ipfs://".
    ///   Recommended formats: GIF, MP4 (H.264), WEBM, GLB/GLTF (for 3D), HTML (for interactive). Max 100 MB.
    ///   Takes precedence for playback; `image` is used as the fallback thumbnail.
    /// * `royalty` — Royalty configuration for secondary sales.
    /// * `is_soulbound` — When `true`, the token cannot be transferred.
    /// * `signature` — Backend Ed25519 signature over the mint payload.
    ///
    /// # Errors
    /// * [`Error::ContractPaused`] — contract is paused.
    /// * [`Error::ClipAlreadyMinted`] — this clip_id has already been minted.
    /// * [`Error::ClipBlacklisted`] — this clip_id has been blacklisted.
    /// * [`Error::InvalidSignature`] — backend signature is invalid.
    /// * [`Error::SignerNotSet`] — no backend signer has been registered.
    /// * [`Error::UnsupportedProtocol`] — URL protocol is not `https://` or `ipfs://`.
    /// * [`Error::MalformedUrl`] — URL format is malformed.
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
        Self::enforce_mint_cooldown(&env, &to)?;
        Self::check_circuit_breaker(&env, 1)?;

        // Validate URLs before any state reads/writes.
        Self::validate_url(&env, &image)?;
        Self::validate_url(&env, &animation_url)?;

        token_data.owner.require_auth();

        let approval_key = DataKey::Approved(token_id);
        if env.storage().persistent().has(&approval_key) {
            env.storage().persistent().remove(&approval_key);
            env.events().publish(
                (symbol_short!("approval"),),
                ApprovalEvent {
                    owner: token_data.owner,
                    operator: env.current_contract_address(),
                    token_id,
                },
            );
        }
        Ok(())
    }

    fn revoke_all_approvals(env: Env, operator: Address) -> Result<(), Error> {
        operator.require_auth();
        let approval_all_key = DataKey::ApprovalForAll(env.current_contract_address(), operator.clone());
        if env.storage().persistent().has(&approval_all_key) {
            env.storage().persistent().remove(&approval_all_key);
            env.events().publish(
                (symbol_short!("app_all"),),
                ApprovalForAllEvent {
                    owner: env.current_contract_address(),
                    operator,
                    approved: false,
                },
            );
        }
        Ok(())
    }

    /// Burns an NFT and decrements the target owner balance checkpoint state securely.
    ///
    /// Closes #199 - Balance Synchronization for burn
    fn burn(env: Env, token_id: TokenId, refund_royalty: bool) -> Result<(), Error> {
        let token_key = DataKey::Token(token_id);
        let token_data: TokenData = env
            .storage()
            .instance()
            .get(&DataKey::NextTokenId)
            .unwrap_or(1);

        // 4 persistent writes
        env.storage().persistent().set(
            &DataKey::Token(token_id),
            &TokenData {
                owner: to.clone(),
                clip_id,
                is_soulbound,
                metadata_uri: metadata_uri.clone(),
                image: image.clone(),
                animation_url: animation_url.clone(),
                description: None,
                external_url: None,
                attributes: Vec::new(&env),
                royalty,
                is_locked: false,
            },
        );
        Self::bump_persistent_ttl(&env, &DataKey::Token(token_id));
        env.storage()
            .persistent()
            .get(&token_key)
            .ok_or(Error::InvalidTokenId)?;

        token_data.owner.require_auth();

        if Self::is_frozen(env.clone(), token_id) {
            return Err(Error::TokenFrozen);
        }

        if refund_royalty {
            let royalty_key = DataKey::RoyaltyBalance(token_id);
            if env.storage().persistent().has(&royalty_key) {
                let accumulated_amount: i128 = env.storage().persistent().get(&royalty_key).unwrap_or(0);
                if accumulated_amount > 0 {
                    if let Some(first_recipient) = token_data.royalty.recipients.get(0) {
                        let target_creator = first_recipient.recipient;
                        if let Some(ref asset_addr) = token_data.royalty.asset_address {
                            let client = soroban_sdk::token::TokenClient::new(&env, asset_addr);
                            client.transfer(&env.current_contract_address(), &target_creator, &accumulated_amount);
                        }
                        env.events().publish(
                            (symbol_short!("refunded"),),
                            RefundedEvent {
                                token_id,
                                recipient: target_creator,
                                amount: accumulated_amount,
                            },
                        );
                    }
                }
                env.storage().persistent().remove(&royalty_key);
            }
        }

        // Maintain O(1) enumeration indexes (must come after supply/balance increments).
        Self::index_add_global(&env, token_id);
        Self::index_add_owner(&env, &to, token_id);

        env.events().publish(
            (symbol_short!("mint"),),
            MintEvent { to: to.clone(), clip_id, token_id, metadata_uri },
        );

        env.events().publish(
            (symbol_short!("burn"),),
            BurnEvent {
                owner: token_data.owner,
                token_id,
                clip_id: token_data.clip_id,
            },
        );

        Ok(())
        // Gas tracking — Closes #169
        let count_mint: u64 = env.storage().temporary().get(&DataKey::CountMint).unwrap_or(0);
        env.storage().temporary().set(&DataKey::CountMint, &(count_mint + 1));
        let total_gas_mint: u64 = env.storage().temporary().get(&DataKey::TotalGasMint).unwrap_or(0);
        env.storage().temporary().set(&DataKey::TotalGasMint, &total_gas_mint.saturating_add(GAS_BASE_MINT));
        Self::record_mint_timestamp(&env, &to);

        // Update circuit breaker counter after successful mint
        Self::update_circuit_breaker_counter(&env, 1);

        Ok(token_id)
    }
}

    /// Mint using a backend-provided signature instead of a wallet-signed tx.
    ///
    /// This entrypoint does NOT require the recipient to `require_auth()`.
    /// The backend signature must include a nonce to prevent replay attacks.
    pub fn mint_with_signature(
        env: Env,
        to: Address,
        clip_id: u32,
        metadata_uri: String,
        image: Option<String>,
        animation_url: Option<String>,
        royalty: Royalty,
        is_soulbound: bool,
        signature: BytesN<64>,
        nonce: u64,
    ) -> Result<TokenId, Error> {
        // No `to.require_auth()` — caller may be any relayer.
        Self::require_not_paused(&env)?;
        Self::check_circuit_breaker(&env, 1)?;

        // Validate URLs before state changes.
        Self::validate_url(&env, &image, Error::InvalidImageUrl)?;
        Self::validate_url(&env, &animation_url, Error::InvalidAnimationUrl)?;

        // Verify backend signature and obtain message hash.
        let message_hash = Self::verify_clip_signature_with_nonce(&env, &to, clip_id, &metadata_uri, nonce, &signature)?;

        // Dedup check — one persistent read.
        if Self::load_clip_token_id(&env, clip_id).is_some() {
            return Err(Error::ClipAlreadyMinted);
        }

        if env
            .storage()
            .persistent()
            .get(&DataKey::BlacklistedClip(clip_id))
            .unwrap_or(false)
        {
            return Err(Error::ClipBlacklisted);
        }

        let royalty = Self::normalize_royalty(&env, royalty)?;

        let token_id: TokenId = env
            .storage()
            .instance()
            .get(&DataKey::NextTokenId)
            .unwrap_or(1);

        // 4 persistent writes
        env.storage().persistent().set(
            &DataKey::Token(token_id),
            &TokenData {
                owner: to.clone(),
                clip_id,
                is_soulbound,
                metadata_uri: metadata_uri.clone(),
                image: image.clone(),
                animation_url: animation_url.clone(),
                description: None,
                external_url: None,
                attributes: Vec::new(&env),
                royalty,
            },
        );
        Self::bump_persistent_ttl(&env, &DataKey::Token(token_id));
        env.storage()
            .persistent()
            .set(&DataKey::ClipIdMinted(clip_id), &token_id);
        Self::bump_persistent_ttl(&env, &DataKey::ClipIdMinted(clip_id));

        // 1 instance write.
        env.storage()
            .instance()
            .set(&DataKey::NextTokenId, &(token_id + 1));

        // Update total supply
        let total_supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalSupply, &(total_supply + 1));

        // Update balance
        let balance: u32 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &(balance + 1));

        // Mark signature message hash as used to prevent replay.
        Self::mark_signature_used(&env, &message_hash);

        env.events().publish(
            (symbol_short!("mint"),),
            MintEvent { to: to.clone(), clip_id, token_id, metadata_uri },
        );

        env.events().publish(
            (symbol_short!("transfer"),),
            TransferEvent {
                token_id,
                from: env.current_contract_address(),
                to: to.clone(),
            },
        );

        // Gas tracking
        let count_mint: u64 = env.storage().instance().get(&DataKey::CountMint).unwrap_or(0);
        env.storage().instance().set(&DataKey::CountMint, &(count_mint + 1));
        let total_gas_mint: u64 = env.storage().instance().get(&DataKey::TotalGasMint).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalGasMint, &total_gas_mint.saturating_add(GAS_BASE_MINT));
        Self::record_mint_timestamp(&env, &to);

        // Update circuit breaker
        Self::update_circuit_breaker_counter(&env, 1);

        Ok(token_id)
    }

    // -------------------------------------------------------------------------
    // Approvals
    // -------------------------------------------------------------------------

    /// Approve an operator to transfer a specific token on behalf of the owner.
    ///
    /// Pass `operator = None` to revoke any existing approval.
    ///
    /// Emits: `"approve"` [`ApprovalEvent`] (only when setting, not revoking).
    ///
    /// # Arguments
    /// * `caller`   — Must be the token owner or an approved-for-all operator.
    /// * `operator` — Address to approve, or `None` to clear.
    /// * `token_id` — Token to approve.
    ///
    /// # Errors
    /// * [`Error::ContractPaused`]         — contract is paused.
    /// * [`Error::InvalidTokenId`]         — token does not exist.
    /// * [`Error::NotAuthorizedToApprove`] — caller is not owner or approved-for-all.
    pub fn approve(
        env: Env,
        caller: Address,
        operator: Option<Address>,
        token_id: TokenId,
    ) -> Result<(), Error> {
        caller.require_auth();
        Self::require_not_paused(&env)?;

        let owner = Self::owner_of(env.clone(), token_id)?;

        token_data.owner.require_auth();

        let approval_key = DataKey::Approved(token_id);
        if env.storage().persistent().has(&approval_key) {
            env.storage().persistent().remove(&approval_key);
            
            env.events().publish(
                (symbol_short!("approval"),),
                ApprovalEvent {
                    owner: token_data.owner,
                    operator: env.current_contract_address(),
                    token_id,
                },
            );
        }
        Ok(())
    }

    /// Revokes general operator permissions for an operator managing the caller's items.
    pub fn revoke_all_approvals(env: Env, operator: Address) -> Result<(), Error> {
        operator.require_auth();

        let approval_all_key = DataKey::ApprovalForAll(env.current_contract_address(), operator.clone());
        if env.storage().persistent().has(&approval_all_key) {
            env.storage().persistent().remove(&approval_all_key);

            env.events().publish(
                (symbol_short!("app_all"),),
                ApprovalForAllEvent {
                    owner: env.current_contract_address(),
                    operator,
                    approved: false,
                },
            );
        }
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Core NFT operations
    // -------------------------------------------------------------------------

    /// Destroys an NFT and optionally claims outstanding accrued royalties back to the creator.
    ///
    /// Closes #136
    pub fn burn(env: Env, token_id: TokenId, refund_royalty: bool) -> Result<(), Error> {
        let token_key = DataKey::Token(token_id);
        let token_data: TokenData = env
    /// # Errors
    /// * [`Error::ContractPaused`]          — contract is paused.
    /// * [`Error::InvalidTokenId`]          — token does not exist.
    /// * [`Error::Unauthorized`]            — `from` is not the owner.
    /// * [`Error::SoulboundTransferBlocked`] — token is soulbound.
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

        if Self::is_frozen(env.clone(), token_id) {
            return Err(Error::TokenFrozen);
        }

        let mut data: TokenData = env
            .storage()
            .persistent()
            .get(&token_key)
            .ok_or(Error::InvalidTokenId)?;

        token_data.owner.require_auth();
        if from != data.owner {
            return Err(Error::Unauthorized);
        }

        let approval_key = DataKey::Approved(token_id);
        if env.storage().persistent().has(&approval_key) {
            env.storage().persistent().remove(&approval_key);
            
            env.events().publish(
                (symbol_short!("approval"),),
                ApprovalEvent {
                    owner: token_data.owner,
                    operator: env.current_contract_address(),
                    token_id,
                },
            );
        }

        // Handle royalty payment if sale_price is greater than zero
        if sale_price > 0 {
            let royalty = data.royalty.clone();
            let pay_asset = match royalty.asset_address {
                Some(ref asset) => asset.clone(),
                None => payment_asset.clone().ok_or(Error::InvalidRecipient)?,
            };

            // Buyer (to) must authorize the royalty payment
            to.require_auth();

            Self::acquire_reentrancy_lock(&env)?;

            // Calculate total royalty
            let mut cumulative_bps: u32 = 0;
            let mut cumulative_royalty: i128 = 0;
            for idx in 0..royalty.recipients.len() {
                let split = royalty.recipients.get(idx).ok_or(Error::InvalidRoyaltySplit)?;
                cumulative_bps = cumulative_bps.saturating_add(split.basis_points);
                let total_so_far = Self::calculate_royalty(sale_price, cumulative_bps)?;
                cumulative_royalty = total_so_far;
            }

            // Effects: update royalty balance
            if cumulative_royalty > 0 {
                let prev: i128 = env
                    .storage()
                    .persistent()
                    .get(&DataKey::RoyaltyBalance(token_id))
                    .unwrap_or(0);
                env.storage()
                    .persistent()
                    .set(&DataKey::RoyaltyBalance(token_id), &(prev.saturating_add(cumulative_royalty)));
            }

            // Interactions: perform transfers
            let token_client = soroban_sdk::token::TokenClient::new(&env, &pay_asset);
            let mut current_bps: u32 = 0;
            let mut current_royalty: i128 = 0;

            for idx in 0..royalty.recipients.len() {
                let split = royalty.recipients.get(idx).ok_or(Error::InvalidRoyaltySplit)?;

                current_bps = current_bps.saturating_add(split.basis_points);
                let total_so_far = Self::calculate_royalty(sale_price, current_bps)?;
                let amount = total_so_far.saturating_sub(current_royalty);
                current_royalty = total_so_far;

                if amount == 0 {
                    continue;
                }

                token_client.transfer(&to, &split.recipient, &amount);
                env.events().publish(
                    (symbol_short!("royalty"),),
                    RoyaltyPaidEvent {
                        token_id,
                        from: to.clone(),
                        to: split.recipient.clone(),
                        amount,
                    },
                );
            }

            Self::release_reentrancy_lock(&env);
        }

        // Clear per-token approval on transfer.
        env.storage().persistent().remove(&DataKey::Approved(token_id));

        data.owner = to.clone();
        env.storage().persistent().set(&DataKey::Token(token_id), &data);

        // Update balances
        let from_balance: u32 = env.storage().persistent().get(&DataKey::Balance(from.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(from.clone()), &from_balance.saturating_sub(1));
        
        let to_balance: u32 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &(to_balance + 1));

        // Update O(1) owner enumeration indexes (after balance changes).
        Self::index_remove_owner(&env, &from, token_id);
        Self::index_add_owner(&env, &to, token_id);

        env.events().publish(
            (symbol_short!("transfer"),),
            TransferEvent { token_id, from, to },
        );

        // Gas tracking — Closes #169
        let count_transfer: u64 = env.storage().temporary().get(&DataKey::CountTransfer).unwrap_or(0);
        env.storage().temporary().set(&DataKey::CountTransfer, &(count_transfer + 1));
        let total_gas_transfer: u64 = env.storage().temporary().get(&DataKey::TotalGasTransfer).unwrap_or(0);
        env.storage().temporary().set(&DataKey::TotalGasTransfer, &total_gas_transfer.saturating_add(GAS_BASE_TRANSFER));

        Ok(())
    }

    /// Mints a token and increments the receiver balance map.
    ///
    /// Closes #199 - Balance Synchronization for mint
    pub fn mint(
        env: Env,
        to: Address,
        clip_id: u32,
        metadata_uri: String,
        royalty_recipients: Vec<RoyaltyRecipient>,
        asset_address: Option<Address>,
        is_soulbound: bool,
    ) -> Result<TokenId, Error> {
        if Self::check_paused(&env) {
            return Err(Error::ContractPaused);
        }

        // Handle optional royalty recovery tracking back to the primary creator asset configuration rules
        if refund_royalty {
            let royalty_key = DataKey::RoyaltyBalance(token_id);
            if env.storage().persistent().has(&royalty_key) {
                let accumulated_amount: i128 = env.storage().persistent().get(&royalty_key).unwrap_or(0);
                
                if accumulated_amount > 0 {
                    // Extract original primary creator/receiver info if existing
                    if let Some(first_recipient) = token_data.royalty.recipients.get(0) {
                        let target_creator = first_recipient.recipient;
                        
                        // Transfer out using specified contract token type structure defaults
                        if let Some(ref asset_addr) = token_data.royalty.asset_address {
                            let client = soroban_sdk::token::TokenClient::new(&env, asset_addr);
                            client.transfer(&env.current_contract_address(), &target_creator, &accumulated_amount);
                        }
                        
                        env.events().publish(
                            (symbol_short!("refunded"),),
                            RefundedEvent {
                                token_id,
                                recipient: target_creator,
                                amount: accumulated_amount,
                            },
                        );
                    }
                }
                env.storage().persistent().remove(&royalty_key);
            }
        }

        // Clean up remaining storage keys mapped to this token context
        env.storage().persistent().remove(&token_key);
        env.storage().persistent().remove(&DataKey::ClipIdMinted(token_data.clip_id));
        env.storage().persistent().remove(&DataKey::Approved(token_id));
        env.storage().persistent().remove(&DataKey::CustomTokenUri(token_id));
        env.storage().persistent().remove(&DataKey::MetadataUpdateCount(token_id));
        env.storage().persistent().remove(&DataKey::MetadataRefreshTime(token_id));

        // Update O(1) owner enumeration indexes (after balance changes).
        Self::index_remove_owner(&env, &from, token_id);
        Self::index_add_owner(&env, &to, token_id);

        env.events().publish(
            (symbol_short!("burn"),),
            BurnEvent {
                owner: token_data.owner,
                token_id,
                clip_id: token_data.clip_id,
            },
        );

        Ok(())
    }

    /// Internal checker helper functions mapped by your setup layers
    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).ok_or(Error::Unauthorized)?;
        if admin != &stored_admin {
            return Err(Error::Unauthorized);
        }
        admin.require_auth();
        Ok(())
    }

    fn check_paused(env: &Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }

    fn exists(env: Env, token_id: TokenId) -> bool {
        env.storage().persistent().has(&DataKey::Token(token_id))
    }

    fn acquire_reentrancy_lock(env: &Env) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::ReentrancyLock) {
            return Err(Error::Reentrancy);
    /// Set circuit breaker enabled status.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// When enabled, the circuit breaker will automatically pause the contract
    /// if mint operations exceed the configured threshold within the time window.
    ///
    /// # Arguments
    /// * `admin`   — Must be the contract admin.
    /// * `enabled` — Whether to enable the circuit breaker.
    pub fn set_circuit_breaker_enabled(env: Env, admin: Address, enabled: bool) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerEnabled, &enabled);
        Ok(())
    }

    /// Set circuit breaker threshold (max mints allowed in time window).
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// # Arguments
    /// * `admin`     — Must be the contract admin.
    /// * `threshold` — Maximum number of mints allowed in the time window.
    pub fn set_circuit_breaker_threshold(env: Env, admin: Address, threshold: u64) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerThreshold, &threshold);
        Ok(())
    }

    /// Set circuit breaker time window duration in seconds.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// # Arguments
    /// * `admin`          — Must be the contract admin.
    /// * `window_seconds` — Duration of the time window in seconds.
    pub fn set_circuit_breaker_window(env: Env, admin: Address, window_seconds: u64) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerWindowSeconds, &window_seconds);
        Ok(())
    }

    /// Reset circuit breaker window and counter.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// Emits: `"cfg_upd"` [`ConfigUpdatedEvent`] with key `"default_royalty"`.
    pub fn set_default_royalty(env: Env, admin: Address, bps: u32) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().remove(&DataKey::PauseUnlockTime);
        env.events().publish((symbol_short!("unpaused"),), ());
        Ok(())
    }

    pub fn is_paused(env: &Env) -> bool {
        Self::check_paused(env)
    }

    /// Set the collection-wide default royalty asset for future mints.
    ///
    /// `Some(address)` sets the default SEP-0041 token.
    /// `None` clears it.
    pub fn set_default_royalty_asset(
        env: Env,
        admin: Address,
        asset_address: Option<Address>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::DefaultRoyaltyAsset, &asset_address);
        Ok(())
    }

    /// Get the current collection-wide default royalty asset.
    pub fn get_default_royalty_asset(env: Env) -> Option<Address> {
        env.storage()
            .instance()
            .get::<DataKey, Option<Address>>(&DataKey::DefaultRoyaltyAsset)
            .unwrap_or(None)
    }

    /// Set wallet mint cooldown in seconds.
    ///
    /// # Arguments
    /// * `admin` — Must be the contract admin.
    pub fn reset_circuit_breaker(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerWindowStart, &0u64);
        env.storage().instance().set(&DataKey::CircuitBreakerWindowCount, &0u64);
        Ok(())
    }

    /// Update metadata URI for a token. Only the token owner can update it.
    /// Limited to once per NFT to prevent abuse.
    ///
    /// # Arguments
    /// * `owner`    - Must be the current token owner
    /// * `token_id` - Token to update
    /// * `new_uri`  - New metadata URI
    pub fn update_metadata(
        env: Env,
        owner: Address,
        token_id: TokenId,
        new_uri: String,
    ) -> Result<(), Error> {
        owner.require_auth();
        let data = Self::load_token(&env, token_id)?;
        if data.owner != owner {
            return Err(Error::Unauthorized);
        }
        env.storage().persistent().set(&DataKey::Frozen(token_id), &true);
        env.events().publish((symbol_short!("freeze"),), TokenFrozenEvent { token_id });
        Ok(())
    }

        if data.is_locked {
            return Err(Error::MetadataLocked);
        }

        // Check if metadata has already been updated
        let update_count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::MetadataUpdateCount(token_id))
            .unwrap_or(0);

        if update_count >= 1 {
            return Err(Error::Unauthorized); // Already updated once
        }
        env.storage().instance().set(&DataKey::ReentrancyLock, &true);
        Ok(())
    }

    fn release_reentrancy_lock(env: &Env) {
        env.storage().instance().remove(&DataKey::ReentrancyLock);
    }

    /// Permanently lock a token's metadata so it can never be changed again.
    ///
    /// Only the current token owner may call this. The lock is irreversible.
    ///
    /// Emits: `"meta_lock"` [`MetadataLockedEvent`].
    ///
    /// # Errors
    /// * [`Error::Unauthorized`]   — caller is not the token owner.
    /// * [`Error::InvalidTokenId`] — token does not exist.
    /// * [`Error::MetadataLocked`] — token metadata is already locked.
    pub fn lock_metadata(env: Env, owner: Address, token_id: TokenId) -> Result<(), Error> {
        owner.require_auth();
        let mut data = Self::load_token(&env, token_id)?;
        if data.owner != owner {
            return Err(Error::Unauthorized);
        }
        if data.is_locked {
            return Err(Error::MetadataLocked);
        }
        data.is_locked = true;
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        env.events().publish(
            (symbol_short!("meta_lock"),),
            MetadataLockedEvent { token_id, owner },
        );
        Ok(())
    }

    /// Returns `true` if the token's metadata has been permanently locked.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — token does not exist.
    pub fn is_metadata_locked(env: Env, token_id: TokenId) -> Result<bool, Error> {
        let data = Self::load_token(&env, token_id)?;
        Ok(data.is_locked)
    }

    /// Push updated metadata from the backend (e.g. after virality score changes).
    ///
    /// Callable by the contract admin **or** the registered backend address.
    /// Limited to once per 30 days per token to prevent abuse.
    ///
    /// Emits: `"mint"` [`MintEvent`].
    ///
    /// # Arguments
    /// * `caller`   — Must be the admin or the registered backend address.
    /// * `token_id` — Token whose metadata URI is being refreshed.
    /// * `new_uri`  — New metadata URI.
    ///
    /// # Errors
    /// * [`Error::Unauthorized`]           — caller is neither admin nor backend address.
    /// * [`Error::InvalidTokenId`]         — token does not exist.
    /// * [`Error::MetadataRefreshTooSoon`] — 30-day cooldown has not elapsed.
    /// Refresh token metadata (admin or backend address only, 30-day cooldown).
    ///
    /// # Arguments
    /// * `caller` — Must be the admin or registered backend address.
    /// * `token_id` — Token to update.
    /// * `new_uri` — New metadata URI (optional). Pass `None` to leave unchanged.
    /// * `image` — New static thumbnail URL (optional). Must start with "https://" or "ipfs://".
    ///   Pass `None` to leave unchanged. Pass `Some("")` to clear the field.
    /// * `animation_url` — New animated preview URL (optional). Must start with "https://" or "ipfs://".
    ///   Pass `None` to leave unchanged. Pass `Some("")` to clear the field.
    ///
    /// # Errors
    /// * [`Error::Unauthorized`] — caller is not admin or backend address.
    /// * [`Error::InvalidTokenId`] — token does not exist.
    /// * [`Error::MetadataRefreshTooSoon`] — 30-day cooldown not elapsed.
    /// * [`Error::UnsupportedProtocol`] — URL protocol is not `https://` or `ipfs://`.
    /// * [`Error::MalformedUrl`] — URL format is malformed.
    pub fn refresh_metadata(
        env: Env,
        caller: Address,
        token_id: TokenId,
        new_uri: Option<String>,
        image: Option<String>,
        animation_url: Option<String>,
    ) -> Result<(), Error> {
        caller.require_auth();

        // Allow admin or the registered backend address.
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Admin not initialized");

        let is_admin = caller == admin;
        
        // Check if caller is the registered backend address
        let is_backend = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::BackendAddress)
            .map(|backend_addr| caller == backend_addr)
            .unwrap_or(false);

        if !is_admin && !is_backend {
            return Err(Error::Unauthorized);
        }

        // 30-day cooldown check (30 * 24 * 3600 = 2_592_000 seconds).
        const COOLDOWN: u64 = 2_592_000;
        let now = env.ledger().timestamp();
        if let Some(last_refresh) = env
            .storage()
            .persistent()
            .get::<DataKey, u64>(&DataKey::MetadataRefreshTime(token_id))
        {
            if now < last_refresh.saturating_add(COOLDOWN) {
                return Err(Error::MetadataRefreshTooSoon);
            }
        }

        // Reject if metadata is permanently locked.
        {
            let data = Self::load_token(&env, token_id)?;
            if data.is_locked {
                return Err(Error::MetadataLocked);
            }
        }

        // Validate URLs if provided and not empty strings.
        let validated_image = match &image {
            Some(s) if s.is_empty() => Some(None), // Clear field
            Some(s) => {
                Self::validate_url(&env, &Some(s.clone()))?;
                Some(Some(s.clone()))
            }
            None => None, // Leave unchanged
        };

        let validated_animation_url = match &animation_url {
            Some(s) if s.is_empty() => Some(None), // Clear field
            Some(s) => {
                Self::validate_url(&env, &Some(s.clone()))?;
                Some(Some(s.clone()))
            }
            None => None, // Leave unchanged
        };

        let mut data = Self::load_token(&env, token_id)?;
        let old_uri = data.metadata_uri.clone();
        
        // Update fields only if new values are provided.
        if let Some(uri) = new_uri {
            data.metadata_uri = uri.clone();
        }
        if let Some(img) = validated_image {
            data.image = img;
        }
        if let Some(anim) = validated_animation_url {
            data.animation_url = anim;
        }

        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        env.storage()
            .persistent()
            .set(&DataKey::MetadataRefreshTime(token_id), &now);

        env.events().publish(
            (symbol_short!("meta_upd"),),
            MetadataUpdatedEvent { token_id, old_uri, new_uri: data.metadata_uri },
        );

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Soulbound: Social Recovery Hook
    // -------------------------------------------------------------------------

    /// Recover a soulbound token to a new owner via a trusted platform signature.
    ///
    /// When the owner's account is compromised, the platform backend signs a
    /// recovery payload authorizing the transfer of the soulbound token to a
    /// new address. This bypasses the normal soulbound transfer restriction.
    ///
    /// ## Payload format
    ///
    /// ```text
    /// new_owner_hash = SHA-256(XDR(new_owner))
    /// message        = SHA-256( "recover" || token_id_le_4_bytes || new_owner_hash )
    /// ```
    ///
    /// The `"recover"` domain separator prevents cross-purpose signature replay
    /// (e.g., a mint signature cannot be reused as a recovery signature).
    ///
    /// Emits: `"sb_recov"` [`SoulboundRecoveredEvent`].
    ///
    /// # Arguments
    /// * `signature` — 64-byte Ed25519 signature from the registered backend signer.
    /// * `new_owner` — Address that will become the new owner of the token.
    /// * `token_id`  — ID of the soulbound token to recover.
    ///
    /// # Errors
    /// * [`Error::ContractPaused`]           — contract is paused.
    /// * [`Error::TokenFrozen`]              — token is frozen.
    /// * [`Error::InvalidTokenId`]           — token does not exist.
    /// * [`Error::SoulboundTransferBlocked`] — token is not soulbound.
    /// * [`Error::SignerNotSet`]             — no backend signer registered.
    /// * [`Error::InvalidSignature`]         — signature verification failed.
    pub fn recover_soulbound(
        env: Env,
        signature: BytesN<64>,
        new_owner: Address,
        token_id: TokenId,
    ) -> Result<(), Error> {
        new_owner.require_auth();
        Self::require_not_paused(&env)?;

        if Self::is_frozen(env.clone(), token_id) {
            return Err(Error::TokenFrozen);
        }

        let mut data = Self::load_token(&env, token_id)?;

        // Only soulbound tokens can be recovered via this mechanism.
        if !data.is_soulbound {
            return Err(Error::SoulboundTransferBlocked);
        }

        // Verify the platform signature over the recovery payload.
        Self::verify_recovery_signature(&env, &new_owner, token_id, &signature)?;

        let old_owner = data.owner.clone();

        // Clear per-token approval on recovery.
        env.storage()
            .persistent()
            .remove(&DataKey::Approved(token_id));

        // Update ownership.
        data.owner = new_owner.clone();
        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &data);

        // Update balances.
        let old_balance: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(old_owner.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(old_owner.clone()), &old_balance.saturating_sub(1));

        let new_balance: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(new_owner.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(new_owner.clone()), &(new_balance + 1));

        env.events().publish(
            (symbol_short!("sb_recov"),),
            SoulboundRecoveredEvent {
                token_id,
                old_owner,
                new_owner,
            },
        );

        Ok(())
    }
}

#[contractimpl]
impl ClipsNftContract {
    // -------------------------------------------------------------------------
    // View functions
    // -------------------------------------------------------------------------

    fn check_paused(env: &Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }

    /// Returns an approximate fee for transfer transactions in stroops.
    pub fn estimate_transfer_fee(_env: Env) -> i128 {
        GAS_BASE_TRANSFER as i128
    }

    /// Returns key contract metadata and configuration.
    pub fn contract_info(env: Env) -> ContractInfo {
        let owner: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Admin not initialized");
        ContractInfo {
            name: Self::name(env.clone()),
            symbol: Self::symbol(env.clone()),
            version: Self::version(env.clone()),
            owner,
            platform_fee: Self::get_platform_fee(env),
        }
    }

    /// Returns the collection name (default: `"ClipCash Clips"`).
    pub fn name(env: Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::Name)
            .unwrap_or_else(|| String::from_str(&env, "ClipCash Clips"))
    }

    /// Returns the collection symbol (default: `"CLIP"`).
    pub fn symbol(env: Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::Symbol)
            .unwrap_or_else(|| String::from_str(&env, "CLIP"))
    }

    /// Returns the original clip ID for a given token ID.
    ///
    /// `clip_id` is stored in `TokenData` at mint time, linking the on-chain
    /// token back to the ClipCash backend database. Used in royalty and
    /// ownership checks.
    ///
    /// Closes #75
    pub fn get_clip_id(env: Env, token_id: TokenId) -> Result<u32, Error> {
        Ok(Self::load_token(&env, token_id)?.clip_id)
    }

    /// Returns the owner of a given token ID.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — token does not exist.
    pub fn owner_of(env: Env, token_id: TokenId) -> Result<Address, Error> {
        Ok(Self::load_token(&env, token_id)?.owner)
    }

    /// Returns the metadata URI for a given token ID.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — token does not exist.
    pub fn token_uri(env: Env, token_id: TokenId) -> Result<String, Error> {
        Ok(Self::load_token(&env, token_id)?.metadata_uri)
    }

    /// Alias for [`token_uri`], kept for backwards compatibility.
    pub fn get_metadata(env: Env, token_id: TokenId) -> Result<String, Error> {
        Ok(Self::load_token(&env, token_id)?.metadata_uri)
    }

    /// Returns OpenSea-compatible JSON metadata for a given token ID.
    ///
    /// Serializes the token's metadata following the OpenSea metadata standard:
    /// https://docs.opensea.io/docs/metadata-standards
    ///
    /// The JSON output includes:
    /// - "metadata_uri": The base metadata URI
    /// - "image": Static thumbnail URL (only if set)
    /// - "animation_url": Animated preview URL (only if set)
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — token does not exist.
    pub fn get_metadata_json(env: Env, token_id: TokenId) -> Result<String, Error> {
        let data = Self::load_token(&env, token_id)?;

        let mut json = Bytes::from_slice(&env, b"{\"metadata_uri\":\"");
        Self::append_string_bytes(&env, &mut json, &data.metadata_uri);
        Self::append_literal_bytes(&env, &mut json, b"\"");

        if let Some(ref img) = data.image {
            Self::append_literal_bytes(&env, &mut json, b",\"image\":\"");
            Self::append_string_bytes(&env, &mut json, img);
            Self::append_literal_bytes(&env, &mut json, b"\"");
        }

        if let Some(ref anim) = data.animation_url {
            Self::append_literal_bytes(&env, &mut json, b",\"animation_url\":\"");
            Self::append_string_bytes(&env, &mut json, anim);
            Self::append_literal_bytes(&env, &mut json, b"\"");
        }

        if let Some(ref desc) = data.description {
            Self::append_literal_bytes(&env, &mut json, b",\"description\":\"");
            Self::append_string_bytes(&env, &mut json, desc);
            Self::append_literal_bytes(&env, &mut json, b"\"");
        }

        if let Some(ref url) = data.external_url {
            Self::append_literal_bytes(&env, &mut json, b",\"external_url\":\"");
            Self::append_string_bytes(&env, &mut json, url);
            Self::append_literal_bytes(&env, &mut json, b"\"");
        }

        Self::append_literal_bytes(&env, &mut json, b",\"attributes\":[");
        for i in 0..data.attributes.len() {
            if i > 0 {
                Self::append_literal_bytes(&env, &mut json, b",");
            }
            let attribute = data.attributes.get(i).ok_or(Error::InvalidTokenId)?;
            Self::append_literal_bytes(&env, &mut json, b"{\"trait_type\":\"");
            Self::append_string_bytes(&env, &mut json, &attribute.trait_type);
            Self::append_literal_bytes(&env, &mut json, b"\",\"value\":\"");
            Self::append_string_bytes(&env, &mut json, &attribute.value);
            Self::append_literal_bytes(&env, &mut json, b"\"}");
        }
        Self::append_literal_bytes(&env, &mut json, b"]}");
        Ok(json.to_string())
    }

    /// Look up the on-chain token ID for a given `clip_id`.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — no token exists for this clip.
    pub fn clip_token_id(env: Env, clip_id: u32) -> Result<TokenId, Error> {
        Self::load_clip_token_id(&env, clip_id).ok_or(Error::InvalidTokenId)
    }

    /// Look up the on-chain token IDs for multiple clip IDs.
    /// Returns None for clip IDs that have not been minted.
    pub fn get_tokens_by_clip_ids(env: Env, clip_ids: Vec<u32>) -> Vec<Option<TokenId>> {
        let mut result = Vec::new(&env);
        for i in 0..clip_ids.len() {
            let clip_id = clip_ids.get(i).unwrap();
            result.push_back(Self::load_clip_token_id(&env, clip_id));
        }
        result
    }

    /// Returns the stored [`Royalty`] struct for a token.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — token does not exist.
    pub fn get_royalty(env: Env, token_id: TokenId) -> Result<Royalty, Error> {
        Ok(Self::load_token(&env, token_id)?.royalty)
    }

    /// Returns the total number of tokens minted (not adjusted for burns).
    ///
    /// Derived from `NextTokenId - 1` — no separate counter needed.
    pub fn total_supply(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0)
    }

    /// Returns the total number of clips minted so far (all-time).
    pub fn minted_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get::<DataKey, u32>(&DataKey::NextTokenId)
            .unwrap_or(1)
            .saturating_sub(1)
    }

    /// Returns `true` if the token is soulbound (non-transferable).
    pub fn is_soulbound(env: Env, token_id: TokenId) -> bool {
        Self::load_token(&env, token_id)
            .map(|d| d.is_soulbound)
            .unwrap_or(false)
    }

    /// Returns the accrued royalty balance for `token_id` (in asset smallest units).
    /// Returns `0` if no balance is recorded or the token does not exist.
    pub fn royalty_balance_of(env: Env, token_id: TokenId) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::RoyaltyBalance(token_id))
            .unwrap_or(0)
    }

    /// Returns the average gas cost for mint operations.
    /// Returns 0 if no mints have been performed.
    pub fn average_gas_mint(env: Env) -> u64 {
        let total_gas: u64 = env
            .storage()
            .temporary()
            .get(&DataKey::TotalGasMint)
            .unwrap_or(0);
        let count: u64 = env
            .storage()
            .temporary()
            .get(&DataKey::CountMint)
            .unwrap_or(0);
        
        if count == 0 {
            0
        } else {
            total_gas / count
        }
    }

    /// Returns the average gas cost for transfer operations.
    /// Returns 0 if no transfers have been performed.
    pub fn average_gas_transfer(env: Env) -> u64 {
        let total_gas: u64 = env
            .storage()
            .temporary()
            .get(&DataKey::TotalGasTransfer)
            .unwrap_or(0);
        let count: u64 = env
            .storage()
            .temporary()
            .get(&DataKey::CountTransfer)
            .unwrap_or(0);
        
        if count == 0 {
            0
        } else {
            total_gas / count
        }
    }

    /// Returns the total number of mint operations performed.
    pub fn total_mints(env: Env) -> u64 {
        env.storage()
            .temporary()
            .get(&DataKey::CountMint)
            .unwrap_or(0)
    }

    /// Returns the total number of transfer operations performed.
    pub fn total_transfers(env: Env) -> u64 {
        env.storage()
            .temporary()
            .get(&DataKey::CountTransfer)
            .unwrap_or(0)
    }

    /// Returns whether the circuit breaker is enabled.
    pub fn circuit_breaker_enabled(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::CircuitBreakerEnabled)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_ENABLED)
    }

    /// Returns the circuit breaker threshold (max mints per window).
    pub fn circuit_breaker_threshold(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::CircuitBreakerThreshold)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
    }

    /// Returns the circuit breaker time window duration in seconds.
    pub fn circuit_breaker_window_seconds(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowSeconds)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS)
    }

    /// Returns the current circuit breaker window start timestamp.
    pub fn circuit_breaker_window_start(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowStart)
            .unwrap_or(0)
    }

    /// Returns the current circuit breaker window mint count.
    pub fn circuit_breaker_window_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowCount)
            .unwrap_or(0)
    }

    /// Returns the number of tokens owned by `owner`.
    /// Compliant with emerging Soroban NFT standard view functions.
    pub fn balance_of(env: Env, owner: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(owner))
            .unwrap_or(0)
    }

    /// Returns the token ID at the given global index (0-based).
    ///
    /// O(1) — reads directly from the `TokenIndex` persistent map maintained
    /// by mint and burn. No iteration over burned slots.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — `index` ≥ `total_supply`.
    pub fn token_by_index(env: Env, index: u32) -> Result<TokenId, Error> {
        let supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        if index >= supply {
            return Err(Error::InvalidTokenId);
        }
        env.storage()
            .persistent()
            .get(&DataKey::TokenIndex(index))
            .ok_or(Error::InvalidTokenId)
    }

    /// Returns the N-th token owned by `owner` (0-indexed).
    ///
    /// O(1) — reads directly from the `OwnerTokenIndex` persistent map
    /// maintained by mint, burn, and transfer. No iteration required.
    ///
    /// # Arguments
    /// * `owner` — Address to query.
    /// * `index` — 0-based position among the owner's tokens.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — `index` ≥ `balance_of(owner)`.
    pub fn token_of_owner_by_index(env: Env, owner: Address, index: u32) -> Result<TokenId, Error> {
        let balance: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(owner.clone()))
            .unwrap_or(0);
        if index >= balance {
            return Err(Error::InvalidTokenId);
        }
        env.storage()
            .persistent()
            .get(&DataKey::OwnerTokenIndex(owner, index))
            .ok_or(Error::InvalidTokenId)
    }

    /// Returns the earliest ledger timestamp at which `token_id` is eligible
    /// for its next metadata refresh (i.e. `last_refresh + 30 days`).
    ///
    /// Returns `0` if the token has never been refreshed (eligible immediately).
    ///
    /// # Arguments
    /// * `token_id` — Token to query.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — token does not exist.
    ///
    /// Closes #172
    pub fn get_next_metadata_refresh_time(env: Env, token_id: TokenId) -> Result<u64, Error> {
        if !Self::exists(env.clone(), token_id) {
            return Err(Error::InvalidTokenId);
        }
        const COOLDOWN: u64 = 2_592_000; // 30 days in seconds
        let next_time = env
            .storage()
            .persistent()
            .get::<DataKey, u64>(&DataKey::MetadataRefreshTime(token_id))
            .map(|last| last.saturating_add(COOLDOWN))
            .unwrap_or(0);
        Ok(next_time)
    }

    // -------------------------------------------------------------------------
    // Royalty extension (EIP-2981 style)
    // -------------------------------------------------------------------------

    /// Returns the royalty receiver, total amount, and payment asset for a sale.
    ///
    /// Formula: `royalty_amount = sale_price × total_basis_points / 10_000`
    ///
    /// Uses overflow-safe arithmetic; returns [`Error::RoyaltyOverflow`] when
    /// `sale_price > i128::MAX / 10_000`.
    ///
    /// # Arguments
    /// * `token_id`   — Token being sold.
    /// * `sale_price` — Sale price in the asset's smallest unit (must be > 0).
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`]    — token does not exist.
    /// * [`Error::InvalidSalePrice`]  — `sale_price` ≤ 0.
    /// * [`Error::RoyaltyOverflow`]   — arithmetic would overflow.
    /// * [`Error::InvalidRoyaltySplit`] — royalty recipients list is empty.
    pub fn royalty_info(
        env: Env,
        token_id: TokenId,
        sale_price: i128,
    ) -> Result<RoyaltyInfo, Error> {
        let royalty = Self::load_token(&env, token_id)?.royalty;
        let total_royalty_amount = royalty.calculate_royalty(sale_price)?;
        let first = royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?;

        Ok(RoyaltyInfo {
            receiver: first.recipient,
            royalty_amount: total_royalty_amount,
            asset_address: royalty.asset_address,
        })
    }

    /// Pay royalties for a token sale using the SEP-0041 asset in the royalty config.
    ///
    /// Iterates over all recipients and transfers each share via the token client.
    /// Also accrues the total royalty amount to `RoyaltyBalance(token_id)` so
    /// recipients can track lifetime earnings and claim via [`claim_royalties`].
    /// For XLM royalties (`asset_address = None`) the marketplace must handle
    /// the transfer directly — this function returns [`Error::InvalidRecipient`].
    ///
    /// Emits: `"royalty"` [`RoyaltyPaidEvent`] per recipient paid.
    ///
    /// # Arguments
    /// * `payer`      — Address making the payment (must authorize).
    /// * `token_id`   — Token being sold.
    /// * `sale_price` — Sale price in the asset's smallest unit (must be > 0).
    ///
    /// # Errors
    /// * [`Error::InvalidSalePrice`]  — `sale_price` ≤ 0.
    /// * [`Error::InvalidTokenId`]    — token does not exist.
    /// * [`Error::InvalidRecipient`]  — no SEP-0041 asset configured (XLM royalty).
    /// * [`Error::InvalidRoyaltySplit`] — recipients list is empty.
    /// * [`Error::RoyaltyOverflow`]   — arithmetic would overflow.
    pub fn pay_royalty(
        env: Env,
        payer: Address,
        token_id: TokenId,
        sale_price: i128,
    ) -> Result<(), Error> {
        payer.require_auth();
        Self::acquire_reentrancy_lock(&env)?;
        let result = Self::pay_royalty_internal(&env, &payer, token_id, sale_price);
        Self::release_reentrancy_lock(&env);
        result
    }

    /// Internal royalty payout logic (caller must hold reentrancy lock).
    /// Follows check-effects-interactions pattern: updates storage before external transfers.
    fn pay_royalty_internal(
        env: &Env,
        payer: &Address,
        token_id: TokenId,
        sale_price: i128,
    ) -> Result<(), Error> {
        if sale_price <= 0 {
            return Err(Error::InvalidSalePrice);
        }

        let royalty = Self::load_token(env, token_id)?.royalty;
        let asset_address = royalty.asset_address.clone().ok_or(Error::InvalidRecipient)?;

        // First, calculate total royalty amount (check phase)
        let mut cumulative_bps: u32 = 0;
        let mut cumulative_royalty: i128 = 0;

        for idx in 0..royalty.recipients.len() {
            let split = royalty.recipients.get(idx).ok_or(Error::InvalidRoyaltySplit)?;
            cumulative_bps = cumulative_bps.saturating_add(split.basis_points);
            let total_so_far = Self::calculate_royalty(sale_price, cumulative_bps)?;
            cumulative_royalty = total_so_far;
        }

        // Update storage before external transfers (effects phase)
        // This ensures state changes are committed before any external calls
        if cumulative_royalty > 0 {
            let prev: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::RoyaltyBalance(token_id))
                .unwrap_or(0);
            env.storage()
                .persistent()
                .set(&DataKey::RoyaltyBalance(token_id), &(prev.saturating_add(cumulative_royalty)));
        }

        // Now perform external transfers (interactions phase)
        let token_client = soroban_sdk::token::TokenClient::new(env, &asset_address);
        let mut cumulative_bps: u32 = 0;
        let mut cumulative_royalty: i128 = 0;

        for idx in 0..royalty.recipients.len() {
            let split = royalty.recipients.get(idx).ok_or(Error::InvalidRoyaltySplit)?;

            cumulative_bps = cumulative_bps.saturating_add(split.basis_points);
            let total_so_far = Self::calculate_royalty(sale_price, cumulative_bps)?;
            let amount = total_so_far.saturating_sub(cumulative_royalty);
            cumulative_royalty = total_so_far;

            if amount == 0 {
                continue;
            }

            token_client.transfer(payer, &split.recipient, &amount);
            env.events().publish(
                (symbol_short!("royalty"),),
                RoyaltyPaidEvent {
                    token_id,
                    from: payer.clone(),
                    to: split.recipient,
                    amount,
                },
            );
        }

        Ok(())
    }

    /// Claim accumulated royalties for a token.
    ///
    /// Transfers the full `RoyaltyBalance` for `token_id` to the primary royalty
    /// recipient using the SEP-0041 asset configured in the royalty. Clears the
    /// balance atomically (check-effects-interactions) to prevent double-claiming.
    ///
    /// Only the primary royalty recipient (index 0) may call this.
    ///
    /// Emits: `"roy_claim"` [`RoyaltyClaimedEvent`].
    ///
    /// # Arguments
    /// * `caller`   — Must be the primary royalty recipient.
    /// * `token_id` — Token whose royalties are being claimed.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`]    — token does not exist.
    /// * [`Error::Unauthorized`]      — caller is not the primary recipient.
    /// * [`Error::InvalidRecipient`]  — no SEP-0041 asset configured.
    /// * [`Error::InsufficientBalance`] — no royalties to claim.
    pub fn claim_royalties(env: Env, caller: Address, token_id: TokenId) -> Result<(), Error> {
        caller.require_auth();
        Self::acquire_reentrancy_lock(&env)?;
        let result = Self::claim_royalties_internal(&env, &caller, token_id);
        Self::release_reentrancy_lock(&env);
        result
    }

    /// Internal royalty claim logic (caller must hold reentrancy lock).
    fn claim_royalties_internal(
        env: &Env,
        caller: &Address,
        token_id: TokenId,
    ) -> Result<(), Error> {
        let royalty = Self::load_token(env, token_id)?.royalty;
        let recipient = royalty
            .recipients
            .get(0)
            .ok_or(Error::InvalidRoyaltySplit)?
            .recipient;

        if caller != &recipient {
            return Err(Error::Unauthorized);
        }

        let asset_address = royalty.asset_address.ok_or(Error::InvalidRecipient)?;

        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::RoyaltyBalance(token_id))
            .unwrap_or(0);

        if balance <= 0 {
            return Err(Error::InsufficientBalance);
        }

        // Clear balance before transfer (check-effects-interactions).
        env.storage()
            .persistent()
            .remove(&DataKey::RoyaltyBalance(token_id));

        soroban_sdk::token::TokenClient::new(env, &asset_address)
            .transfer(&env.current_contract_address(), &recipient, &balance);

        env.events().publish(
            (symbol_short!("roy_clm"),),
            RoyaltyClaimedEvent {
                token_id,
                recipient,
                amount: balance,
                asset: asset_address,
            },
        );

        Ok(())
    }

    /// Update the royalty configuration for a token.
    /// Access Control: Admin only.
    /// Emits RoyaltyRecipientUpdated event when the primary recipient changes.
    pub fn set_royalty(
        env: Env,
        admin: Address,
        token_id: TokenId,
        new_royalty: Royalty,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;

        // 1 persistent read
        let mut data = Self::load_token(&env, token_id)?;
        let old_royalty = data.royalty.clone();

        // Emit event if primary recipient changed (compare before normalization)
        if !old_royalty.recipients.is_empty() && !new_royalty.recipients.is_empty() {
            let old_recipient = old_royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?;
            let new_recipient = new_royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?;
            
            if old_recipient.recipient != new_recipient.recipient {
                env.events().publish(
                    (symbol_short!("royalty"),),
                    RoyaltyRecipientUpdatedEvent {
                        token_id,
                        old_recipient: old_recipient.recipient,
                        new_recipient: new_recipient.recipient,
                    },
                );
            }
        }

        let new_royalty = Self::normalize_royalty(&env, new_royalty)?;

        data.royalty = new_royalty;
        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &data);

        env.events().publish(
            (symbol_short!("roy_upd"),),
            RoyaltyUpdatedEvent { token_id },
        );

        Ok(())
    }

    /// Burn (destroy) an NFT. Only the current owner may burn.
    ///
    /// Storage removes (persistent): TokenData, ClipIdMinted = **2** (Optimized from 4)
    pub fn burn(env: Env, owner: Address, token_id: TokenId) -> Result<(), Error> {
        owner.require_auth();

        if Self::is_frozen(env.clone(), token_id) {
            return Err(Error::TokenFrozen);
        }

        // 1 persistent read — also gives us clip_id for dedup cleanup
        let data: TokenData = Self::load_token(&env, token_id)?;

        if owner != data.owner {
            return Err(Error::Unauthorized);
        }

        // 2 persistent removes
        env.storage().persistent().remove(&DataKey::Token(token_id));
        env.storage()
            .persistent()
            .remove(&DataKey::ClipIdMinted(data.clip_id));

        // Update total supply
        let total_supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalSupply, &total_supply.saturating_sub(1));

        // Update balance
        let balance: u32 = env.storage().persistent().get(&DataKey::Balance(owner.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(owner.clone()), &balance.saturating_sub(1));

        // Remove from O(1) enumeration indexes (must come after supply/balance decrements).
        Self::index_remove_global(&env, token_id);
        Self::index_remove_owner(&env, &owner, token_id);

        env.events().publish(
            (symbol_short!("burn"),),
            BurnEvent {
                owner: owner.clone(),
                token_id,
                clip_id: data.clip_id,
            },
        );

        // Emit standard Transfer event for ERC-721 compliance
        env.events().publish(
            (symbol_short!("transfer"),),
            TransferEvent {
                token_id,
                from: owner.clone(),
                to: env.current_contract_address(),
            },
        );

        Ok(())
    }

    /// Burn (destroy) multiple NFTs. Only the current owner may burn the tokens.
    ///
    /// Loops through `token_ids` and burns each token if owned by `owner`.
    /// All burns happen in a single transaction.
    ///
    /// Storage removes (persistent): For each token - TokenData, ClipIdMinted
    ///
    /// Emits: `"burn"` [`BurnEvent`] per token burned.
    ///
    /// # Arguments
    /// * `owner`   - Owner of the tokens (must authorize and match token ownership)
    /// * `token_ids` - List of token IDs to burn
    ///
    /// # Errors
    /// * [`Error::TokenFrozen`]   — any token is frozen.
    /// * [`Error::Unauthorized`]  — owner mismatch for any token.
    /// * [`Error::InvalidTokenId`] — any token does not exist.
    pub fn batch_burn(env: Env, owner: Address, token_ids: Vec<TokenId>) -> Result<(), Error> {
        owner.require_auth();

        // Process each token
        for i in 0..token_ids.len() {
            let token_id = token_ids.get(i).unwrap();

            // Validate token is not frozen
            if Self::is_frozen(env.clone(), token_id) {
                return Err(Error::TokenFrozen);
            }

            // Load token data and verify ownership
            let data: TokenData = Self::load_token(&env, token_id)?;
            if owner != data.owner {
                return Err(Error::Unauthorized);
            }

            // Burn the token (2 persistent removes)
            env.storage().persistent().remove(&DataKey::Token(token_id));
            env.storage()
                .persistent()
                .remove(&DataKey::ClipIdMinted(data.clip_id));

            // Update total supply
            let total_supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
            env.storage().instance().set(&DataKey::TotalSupply, &total_supply.saturating_sub(1));

            // Update balance
            let balance: u32 = env.storage().persistent().get(&DataKey::Balance(owner.clone())).unwrap_or(0);
            env.storage().persistent().set(&DataKey::Balance(owner.clone()), &balance.saturating_sub(1));

            // Emit Burn event
            env.events().publish(
                (symbol_short!("burn"),),
                BurnEvent {
                    owner: owner.clone(),
                    token_id,
                    clip_id: data.clip_id,
                },
            );

            // Emit standard Transfer event for ERC-721 compliance (to zero address)
            env.events().publish(
                (symbol_short!("transfer"),),
                TransferEvent {
                    token_id,
                    from: owner.clone(),
                    to: env.current_contract_address(),
                },
            );
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Task 1: Update royalty recipient
    // -------------------------------------------------------------------------

    /// Allow the current royalty recipient to update their address.
    ///
    /// Only the current primary royalty recipient (index 0) may call this.
    /// Emits `RoyaltyRecipientUpdated` event.
    ///
    /// # Arguments
    /// * `caller`        - Must be the current primary royalty recipient
    /// * `token_id`      - Token whose royalty recipient is being updated
    /// * `new_recipient` - New recipient address
    pub fn update_royalty_recipient(
        env: Env,
        caller: Address,
        token_id: TokenId,
        new_recipient: Address,
    ) -> Result<(), Error> {
        caller.require_auth();

        let mut data = Self::load_token(&env, token_id)?;
        let old_recipient = data
            .royalty
            .recipients
            .get(0)
            .ok_or(Error::InvalidRoyaltySplit)?
            .recipient
            .clone();

        if caller != old_recipient {
            return Err(Error::Unauthorized);
        }

        // Replace recipient at index 0, keep basis_points unchanged
        let bps = data
            .royalty
            .recipients
            .get(0)
            .ok_or(Error::InvalidRoyaltySplit)?
            .basis_points;

        data.royalty.recipients.set(
            0,
            RoyaltyRecipient {
                recipient: new_recipient.clone(),
                basis_points: bps,
            },
        );

        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &data);

        env.events().publish(
            (symbol_short!("royalty"),),
            RoyaltyRecipientUpdatedEvent {
                token_id,
                old_recipient,
                new_recipient,
            },
        );

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Task 1 (Issue #124): tokens_of_owner view
    // -------------------------------------------------------------------------

    /// Return token IDs owned by `owner` with pagination support.
    ///
    /// This function enables frontends to display NFTs owned by a user with pagination.
    /// It iterates over minted token IDs (1..=next_token_id-1) and collects those
    /// whose owner matches.
    ///
    /// ## Storage Optimization
    /// - Linear iteration per token to check ownership (unavoidable for general query)
    /// - Single instance read for NextTokenId
    /// - Persistent reads only for tokens that might belong to owner
    ///
    /// ## Gas Protection
    /// - Result is capped at MAX_RESULTS (1000) entries to prevent gas explosion
    /// - When result reaches 1000, iteration stops even if more tokens exist
    /// - Pagination allows fetching large collections in batches
    ///
    /// # Arguments
    /// * `owner` - Address to query
    /// * `limit` - Maximum number of results to return (optional, defaults to 1000)
    /// * `offset` - Number of results to skip (optional, defaults to 0)
    ///
    /// # Returns
    /// Vec of token IDs owned by the address, respecting limit and offset
    pub fn tokens_of_owner(
        env: Env,
        owner: Address,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Vec<TokenId> {
        const MAX_RESULTS: u32 = 1000;
        let limit = limit.unwrap_or(MAX_RESULTS).min(MAX_RESULTS);
        let offset = offset.unwrap_or(0);
        let next_id: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(owner.clone()))
            .unwrap_or(0);

        let count = if balance > MAX_RESULTS { MAX_RESULTS } else { balance };
        let mut result: Vec<TokenId> = Vec::new(&env);
        let mut count: u32 = 0;
        let mut skipped: u32 = 0;

        let mut token_id: u32 = 1;
        while token_id < next_id && count < limit {
            if let Some(data) = env
                .storage()
                .persistent()
                .get::<DataKey, TokenId>(&DataKey::OwnerTokenIndex(owner.clone(), pos))
            {
                if data.owner == owner {
                    if skipped < offset {
                        skipped += 1;
                    } else {
                        result.push_back(token_id);
                        count += 1;
                    }
                }
            }
        }
        result
    }

    /// Return a paginated list of token IDs owned by `owner`.
    ///
    /// O(limit) — reads directly from the per-owner index, no scan over
    /// burned or unrelated tokens.
    ///
    /// # Arguments
    /// * `owner`  — Address to query.
    /// * `limit`  — Max tokens to return (capped at 100).
    /// * `offset` — Number of tokens to skip (0-based page offset).
    pub fn get_user_tokens(env: Env, owner: Address, limit: u32, offset: u32) -> Vec<TokenId> {
        const MAX_LIMIT: u32 = 100;
        let limit = if limit > MAX_LIMIT { MAX_LIMIT } else { limit };

        let balance: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(owner.clone()))
            .unwrap_or(0);

        let mut result: Vec<TokenId> = Vec::new(&env);
        let end = offset.saturating_add(limit).min(balance);
        for pos in offset..end {
            if let Some(token_id) = env
                .storage()
                .persistent()
                .get::<DataKey, TokenId>(&DataKey::OwnerTokenIndex(owner.clone(), pos))
            {
                result.push_back(token_id);
            }
        }
        result
    }

    // -------------------------------------------------------------------------
    // Task 2: Batch minting
    // -------------------------------------------------------------------------

    /// Mint multiple clips in a single transaction.
    ///
    /// Loops through `clip_ids` and `metadata_uris` in lockstep, minting each
    /// with the provided `royalty` and `signatures`. Emits a single
    /// `BatchMint` event on success.
    ///
    /// # Arguments
    /// * `to`            - Owner of all minted tokens
    /// * `clip_ids`      - List of clip IDs to mint
    /// * `metadata_uris` - Corresponding metadata URIs
    /// * `images`        - Corresponding static thumbnail URLs (optional for each)
    /// * `animation_urls` - Corresponding animated preview URLs (optional for each)
    /// * `royalty`       - Royalty config applied to all tokens
    /// * `is_soulbound`  - Whether all tokens are soulbound
    /// * `signatures`    - Per-clip backend signatures
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
        Self::check_circuit_breaker(&env, n as u64)?;

        if n != metadata_uris.len() || n != signatures.len() || n != images.len() || n != animation_urls.len() {
            return Err(Error::InvalidRoyaltySplit); // mismatched input lengths
        }
        if n > MAX_BATCH_MINT {
            return Err(Error::BatchTooLarge);
        }

        let royalty = Self::normalize_royalty(&env, royalty)?;
        let mut minted: Vec<TokenId> = Vec::new(&env);

        for i in 0..n {
            let clip_id = clip_ids.get(i).ok_or(Error::InvalidTokenId)?;
            let metadata_uri = metadata_uris.get(i).ok_or(Error::InvalidTokenId)?;
            let image = images.get(i).ok_or(Error::InvalidTokenId)?;
            let animation_url = animation_urls.get(i).ok_or(Error::InvalidTokenId)?;
            let signature = signatures.get(i).ok_or(Error::InvalidTokenId)?;

            // Validate URLs
            Self::validate_url(&env, &image)?;
            Self::validate_url(&env, &animation_url)?;

            Self::verify_clip_signature(&env, &to, clip_id, &metadata_uri, &signature)?;

            if Self::load_clip_token_id(&env, clip_id).is_some() {
                return Err(Error::ClipAlreadyMinted);
            }

            if env
                .storage()
                .persistent()
                .get(&DataKey::BlacklistedClip(clip_id))
                .unwrap_or(false)
            {
                return Err(Error::ClipBlacklisted);
            }

            let token_id: TokenId = env
                .storage()
                .instance()
                .get(&DataKey::NextTokenId)
                .unwrap_or(1);

            env.storage().persistent().set(
                &DataKey::Token(token_id),
                &TokenData {
                    owner: to.clone(),
                    clip_id,
                    is_soulbound,
                    metadata_uri,
                    image,
                    animation_url,
                    description: None,
                    external_url: None,
                    attributes: Vec::new(&env),
                    royalty: royalty.clone(),
                    is_locked: false,
                },
            );
            Self::bump_persistent_ttl(&env, &DataKey::Token(token_id));
            env.storage()
                .persistent()
                .set(&DataKey::ClipIdMinted(clip_id), &token_id);
            Self::bump_persistent_ttl(&env, &DataKey::ClipIdMinted(clip_id));
            env.storage()
                .instance()
                .set(&DataKey::NextTokenId, &(token_id + 1));

            // Update total supply
            let total_supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
            env.storage().instance().set(&DataKey::TotalSupply, &(total_supply + 1));

            // Update balance
            let balance: u32 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
            env.storage().persistent().set(&DataKey::Balance(to.clone()), &(balance + 1));

            minted.push_back(token_id);
        }

        env.events().publish(
            (symbol_short!("batch_mnt"),),
            BatchMintEvent {
                to: to.clone(),
                count: n,
                first_token_id: minted.get(0).unwrap_or(0),
            },
        );

        // Gas tracking — Closes #169
        let count_mint: u64 = env.storage().temporary().get(&DataKey::CountMint).unwrap_or(0);
        env.storage().temporary().set(&DataKey::CountMint, &(count_mint + n as u64));
        let total_gas_mint: u64 = env.storage().temporary().get(&DataKey::TotalGasMint).unwrap_or(0);
        env.storage().temporary().set(&DataKey::TotalGasMint, &total_gas_mint.saturating_add(GAS_BASE_MINT.saturating_mul(n as u64)));
        Self::record_mint_timestamp(&env, &to);

        // Update circuit breaker counter after successful batch mint
        Self::update_circuit_breaker_counter(&env, n as u64);

        Ok(minted)
    }

    // -------------------------------------------------------------------------
    // Task 4: Public royalty fee calculation helper
    // -------------------------------------------------------------------------

    /// Calculate the royalty amount for a given sale price using the token's
    /// stored royalty configuration (sum of all recipient basis points).
    ///
    /// Returns `InvalidSalePrice` if `sale_price <= 0`.
    /// Returns `RoyaltyOverflow` if `sale_price` is too large.
    ///
    /// # Arguments
    /// * `token_id`   - Token to look up royalty config for
    /// * `sale_price` - Sale price in the token's royalty asset denomination
    pub fn calculate_royalty_amount(
        env: Env,
        token_id: TokenId,
        sale_price: i128,
    ) -> Result<i128, Error> {
        let royalty = Self::load_token(&env, token_id)?.royalty;
        royalty.calculate_royalty(sale_price)
    }

    // -------------------------------------------------------------------------
    // Circuit breaker internal helpers
    // -------------------------------------------------------------------------

    /// Check if the circuit breaker should trigger based on mint activity.
    /// If enabled and the threshold is exceeded within the time window,
    /// automatically pause the contract.
    fn check_circuit_breaker(env: &Env, mint_count: u64) -> Result<(), Error> {
        let enabled: bool = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerEnabled)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_ENABLED);
        
        if !enabled {
            return Ok(());
        }

        let threshold: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerThreshold)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_THRESHOLD);
        
        let window_seconds: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowSeconds)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);

        let now = env.ledger().timestamp();
        let window_start: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowStart)
            .unwrap_or(0);
        
        let current_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowCount)
            .unwrap_or(0);

        // Check if we need to reset the window (time elapsed)
        if window_start == 0 || now >= window_start.saturating_add(window_seconds) {
            // Window expired or not started - check if this batch alone would exceed threshold
            if mint_count > threshold {
                Self::trigger_circuit_breaker(env, mint_count, threshold, window_seconds)?;
            }
        } else {
            // Within current window, check if adding this batch would exceed threshold
            let new_count = current_count.saturating_add(mint_count);
            if new_count > threshold {
                Self::trigger_circuit_breaker(env, new_count, threshold, window_seconds)?;
            }
        }

        Ok(())
    }

    /// Update the circuit breaker counter after a successful mint.
    fn update_circuit_breaker_counter(env: &Env, mint_count: u64) {
        let enabled: bool = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerEnabled)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_ENABLED);
        
        if !enabled {
            return;
        }

        let window_seconds: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowSeconds)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);

        let now = env.ledger().timestamp();
        let window_start: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowStart)
            .unwrap_or(0);
        
        let current_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowCount)
            .unwrap_or(0);

        // Check if we need to reset the window (time elapsed)
        if window_start == 0 || now >= window_start.saturating_add(window_seconds) {
            // Window expired or not started, reset counter
            env.storage()
                .instance()
                .set(&DataKey::CircuitBreakerWindowStart, &now);
            env.storage()
                .instance()
                .set(&DataKey::CircuitBreakerWindowCount, &mint_count);
        } else {
            // Within current window, increment counter
            env.storage()
                .instance()
                .set(&DataKey::CircuitBreakerWindowCount, &current_count.saturating_add(mint_count));
        }
    }

    /// Trigger the circuit breaker by pausing the contract.
    fn trigger_circuit_breaker(env: &Env, mint_count: u64, threshold: u64, window_seconds: u64) -> Result<(), Error> {
        // Set pause flag immediately (no timelock for automatic circuit breaker)
        env.storage().instance().set(&DataKey::Paused, &true);
        
        // Emit event
        env.events().publish(
            (symbol_short!("circuit"),),
            CircuitBreakerTriggeredEvent {
                mint_count,
                threshold,
                window_seconds,
            },
        );

        Err(Error::CircuitBreakerTripped)
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Rejects minting when `wallet` is still inside the configured cooldown window.
    fn enforce_mint_cooldown(env: &Env, wallet: &Address) -> Result<(), Error> {
        let cooldown = Self::get_mint_cooldown(env.clone());
        if cooldown == 0 {
            return Ok(());
        }
        let now = env.ledger().timestamp();
        let key = DataKey::LastMintTimestamp(wallet.clone());
        if let Some(last_mint) = env.storage().persistent().get::<DataKey, u64>(&key) {
            if now < last_mint.saturating_add(cooldown) {
                return Err(Error::MintCooldownActive);
            }
        }
        Ok(())
    }

    /// Persists the ledger timestamp of the latest successful mint for `wallet`.
    fn record_mint_timestamp(env: &Env, wallet: &Address) {
        env.storage()
            .persistent()
            .set(&DataKey::LastMintTimestamp(wallet.clone()), &env.ledger().timestamp());
    }

    /// Load and return `TokenData`, or `InvalidTokenId` if not found.
    fn load_token(env: &Env, token_id: TokenId) -> Result<TokenData, Error> {
        let data: TokenData = env.storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .ok_or(Error::InvalidTokenId)?;
        Self::bump_persistent_ttl(env, &DataKey::Token(token_id));
        Ok(data)
    }

    /// Returns the token ID minted for `clip_id`, if any, bumping TTL when present.
    fn load_clip_token_id(env: &Env, clip_id: u32) -> Option<TokenId> {
        let key = DataKey::ClipIdMinted(clip_id);
        let token_id: Option<TokenId> = env.storage().persistent().get(&key);
        if token_id.is_some() {
            Self::bump_persistent_ttl(env, &key);
        }
        token_id
    }

    /// Extends persistent entry TTL to reduce archive risk on hot keys.
    fn bump_persistent_ttl(env: &Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
    }

    /// Acquire the contract reentrancy lock before external token calls.
    fn acquire_reentrancy_lock(env: &Env) -> Result<(), Error> {
        let locked: bool = env
            .storage()
            .instance()
            .get(&DataKey::ReentrancyLock)
            .unwrap_or(false);
        if locked {
            return Err(Error::Reentrancy);
        }
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &true);
        Ok(())
    }

    /// Release the contract reentrancy lock after external token calls complete.
    fn release_reentrancy_lock(env: &Env) {
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &false);
    }

    /// Verify the backend Ed25519 signature over the canonical mint payload.
    ///
    /// Payload:
    /// ```text
    /// owner_hash = SHA-256(XDR(owner))
    /// uri_hash   = SHA-256(UTF-8(metadata_uri))
    /// message    = SHA-256( clip_id_le4 || owner_hash || uri_hash )
    /// ```
    /// Traps (panics) on invalid signature via `env.crypto().ed25519_verify`.
    fn verify_clip_signature(
        env: &Env,
        owner: &Address,
        clip_id: u32,
        metadata_uri: &String,
        signature: &BytesN<64>,
    ) -> Result<(), Error> {
        let signer: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::Signer)
            .ok_or(Error::SignerNotSet)?;

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

    /// Verify the backend Ed25519 signature over the recovery payload.
    ///
    /// Payload:
    /// ```text
    /// new_owner_hash = SHA-256(XDR(new_owner))
    /// message        = SHA-256( "recover" || token_id_le4 || new_owner_hash )
    /// ```
    ///
    /// The `"recover"` domain separator prevents cross-purpose replay attacks.
    fn verify_recovery_signature(
        env: &Env,
        new_owner: &Address,
        token_id: TokenId,
        signature: &BytesN<64>,
    ) -> Result<(), Error> {
        let signer: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::Signer)
            .ok_or(Error::SignerNotSet)?;

        let new_owner_hash: BytesN<32> = env
            .crypto()
            .sha256(&new_owner.clone().to_xdr(env))
            .into();

        let mut preimage = Bytes::new(env);
        preimage.append(&Bytes::from_slice(env, b"recover"));
        preimage.extend_from_array(&token_id.to_le_bytes());
        preimage.append(&Bytes::from(new_owner_hash));

        let message: BytesN<32> = env.crypto().sha256(&preimage).into();

        env.crypto()
            .ed25519_verify(&signer, &Bytes::from(message), signature);

        Ok(())
    }

    /// Verify a backend Ed25519 signature over the canonical mint payload
    /// which includes a nonce to prevent replay attacks.
    ///
    /// Payload:
    /// ```text
    /// owner_hash = SHA-256(XDR(owner))
    /// uri_hash   = SHA-256(UTF-8(metadata_uri))
    /// message    = SHA-256( "mint" || clip_id_le4 || owner_hash || uri_hash || nonce_le8 )
    /// ```
    fn verify_clip_signature_with_nonce(
        env: &Env,
        owner: &Address,
        clip_id: u32,
        metadata_uri: &String,
        nonce: u64,
        signature: &BytesN<64>,
    ) -> Result<BytesN<32>, Error> {
        let signer: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::Signer)
            .ok_or(Error::SignerNotSet)?;

        let owner_hash: BytesN<32> = env.crypto().sha256(&owner.clone().to_xdr(env)).into();
        let uri_hash: BytesN<32> = env.crypto().sha256(&Bytes::from(metadata_uri.to_xdr(env))).into();

        let mut preimage = Bytes::new(env);
        preimage.append(&Bytes::from_slice(env, b"mint"));
        preimage.extend_from_array(&clip_id.to_le_bytes());
        preimage.append(&Bytes::from(owner_hash));
        preimage.append(&Bytes::from(uri_hash));
        preimage.extend_from_array(&nonce.to_le_bytes());

        let message: BytesN<32> = env.crypto().sha256(&preimage).into();

        // Prevent replay: ensure message hash hasn't been used
        if env
            .storage()
            .persistent()
            .has(&DataKey::UsedSignature(message.clone()))
        {
            return Err(Error::InvalidSignature);
        }

        env.crypto()
            .ed25519_verify(&signer, &Bytes::from(message.clone()), signature);

        Ok(message)
    }

    /// Mark a signature message hash as used to prevent replay.
    fn mark_signature_used(env: &Env, message: &BytesN<32>) {
        env.storage()
            .persistent()
            .set(&DataKey::UsedSignature(message.clone()), &true);
    }

    /// Assert that `addr` is the stored admin and require its authorization.
    fn require_admin(env: &Env, addr: &Address) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Admin not initialized");

        if addr != &admin {
            return Err(Error::Unauthorized);
        }

        addr.require_auth();
        Ok(())
    }

    /// Return `ContractPaused` if the pause flag is set and the 24-hour timelock has elapsed.
    fn require_not_paused(env: &Env) -> Result<(), Error> {
        if Self::check_paused(env) {
            return Err(Error::ContractPaused);
        }
        Ok(())
    }

    /// Returns `true` if the pause flag is set AND the 24-hour timelock has elapsed.
    fn check_paused(env: &Env) -> bool {
        let flagged: bool = env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        if !flagged {
            return false;
        }
        // Check if the timelock has elapsed.
        match env.storage().instance().get::<DataKey, u64>(&DataKey::PauseUnlockTime) {
            Some(active_at) => env.ledger().timestamp() >= active_at,
            // No timelock stored — legacy pause (immediately active).
            None => true,
        }
    }

    /// Validate royalty recipients and append the platform 1 % cut if absent.
    fn normalize_royalty(env: &Env, royalty: Royalty) -> Result<Royalty, Error> {
        if royalty.recipients.is_empty() {
            return Err(Error::InvalidRoyaltySplit);
        }
        let default_asset = env
            .storage()
            .instance()
            .get::<DataKey, Option<Address>>(&DataKey::DefaultRoyaltyAsset)
            .unwrap_or(None);
        let asset_address = royalty.asset_address.clone().or(default_asset);

        let platform: Address = env
            .storage()
            .instance()
            .get(&DataKey::PlatformRecipient)
            .ok_or(Error::InvalidRecipient)?;

        let mut recipients = royalty.recipients;
        let mut has_platform = false;
        let mut total_bps: u32 = 0;

        for idx in 0..recipients.len() {
            let split = recipients.get(idx).ok_or(Error::InvalidRoyaltySplit)?;
            if split.recipient == platform {
                has_platform = true;
            }
            total_bps = total_bps.saturating_add(split.basis_points);
        }

        if !has_platform {
            recipients.push_back(RoyaltyRecipient {
                recipient: platform,
                basis_points: 100, // fixed default 1 %
            });
            total_bps = total_bps.saturating_add(100);
        }

        if total_bps > 10_000 {
            return Err(Error::RoyaltyTooHigh);
        }

        Ok(Royalty {
            recipients,
            asset_address,
        })
    }

    /// Validate URL format and supported protocol.
    fn validate_url(_env: &Env, url: &Option<String>) -> Result<(), Error> {
        if let Some(ref u) = url {
            let bytes = u.to_bytes();
            if bytes.len() == 0 {
                return Err(Error::MalformedUrl);
            }

            let scheme_end = Self::find_scheme_separator(&bytes).ok_or(Error::MalformedUrl)?;
            if scheme_end == 0 || scheme_end + 3 >= bytes.len() {
                return Err(Error::MalformedUrl);
            }

            if Self::has_ascii_whitespace(&bytes) {
                return Err(Error::MalformedUrl);
            }

            let is_https = Self::bytes_equal_prefix(&bytes, scheme_end, b"https");
            let is_ipfs = Self::bytes_equal_prefix(&bytes, scheme_end, b"ipfs");
            if !is_https && !is_ipfs {
                return Err(Error::UnsupportedProtocol);
            }
        }
        Ok(())
    }

    /// Returns true when `value` begins with the UTF-8 `prefix` bytes.
    fn url_starts_with(_env: &Env, value: &String, prefix: &[u8]) -> bool {
        let bytes = value.to_bytes();
        let prefix_len = prefix.len() as u32;
        if bytes.len() < prefix_len {
            return false;
        }
        for i in 0..end {
            if bytes.get(i) != Some(prefix[i as usize]) {
                return false;
            }
        }
        true
    }

    fn has_ascii_whitespace(bytes: &Bytes) -> bool {
        for i in 0..bytes.len() {
            if let Some(ch) = bytes.get(i) {
                if ch == b' ' || ch == b'\n' || ch == b'\r' || ch == b'\t' {
                    return true;
                }
            }
        }
        false
    }

    /// Append a Soroban [`String`] onto a byte buffer used for JSON assembly.
    fn append_string_bytes(_env: &Env, buffer: &mut Bytes, value: &String) {
        let chunk: Bytes = value.to_bytes();
        buffer.append(&chunk);
    }

    /// Append a static UTF-8 fragment onto a byte buffer.
    fn append_literal_bytes(env: &Env, buffer: &mut Bytes, literal: &[u8]) {
        buffer.append(&Bytes::from_slice(env, literal));
    }

    /// Calculate royalty amount using safe (checked) arithmetic.
    ///
    /// Formula: `royalty_amount = (sale_price * basis_points + 5_000) / 10_000`
    ///
    /// # Safe price limits
    /// `sale_price` must be ≤ `i128::MAX / 10_000` (≈ 1.7 × 10³⁴ stroops).
    /// Prices above this threshold return `RoyaltyOverflow`.
    ///
    /// Delegates to [`safe_math::safe_royalty_amount`] — see that module for
    /// full overflow-protection documentation.
    pub fn calculate_royalty(sale_price: i128, basis_points: u32) -> Result<i128, Error> {
        safe_math::safe_royalty_amount(sale_price, basis_points)
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
        let mut recipients = Vec::new(env);
        recipients.push_back(RoyaltyRecipient { recipient, basis_points: 500 });
        Royalty { recipients, asset_address: None }
    }

    fn sign_mint(
        env: &Env,
        signer_secret: &ed25519_dalek::SigningKey,
        owner: &Address,
        clip_id: u32,
        metadata_uri: &String,
    ) -> BytesN<64> {
        let owner_hash: BytesN<32> = env.crypto().sha256(&owner.clone().to_xdr(env)).into();
        let uri_hash: BytesN<32> = env.crypto().sha256(&Bytes::from(metadata_uri.to_xdr(env))).into();
        let mut preimage = Bytes::new(env);
        preimage.extend_from_array(&clip_id.to_le_bytes());
        preimage.append(&Bytes::from(owner_hash));
        preimage.append(&Bytes::from(uri_hash));
        let message: BytesN<32> = env.crypto().sha256(&preimage).into();
        use ed25519_dalek::Signer as _;
        let sig = signer_secret.sign(&message.to_array());
        BytesN::from_array(env, &sig.to_bytes())
    }

    fn register_signer(
        env: &Env,
        client: &ClipsNftContractClient,
        admin: &Address,
    ) -> ed25519_dalek::SigningKey {
        let sk_bytes = soroban_sdk::BytesN::<32>::random(env).to_array();
        let keypair = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let pubkey = BytesN::from_array(env, &keypair.verifying_key().to_bytes());
        client.set_signer(admin, &pubkey);
        keypair
    }

    fn do_mint(
        client: &ClipsNftContractClient,
        env: &Env,
        to: &Address,
        clip_id: u32,
        keypair: &ed25519_dalek::SigningKey,
    ) -> TokenId {
        let uri = String::from_str(env, "ipfs://QmExample");
        let sig = sign_mint(env, keypair, to, clip_id, &uri);
        client.mint(
            to,
            &clip_id,
            &uri,
            &None,  // image
            &None,  // animation_url
            &default_royalty(env, to.clone()),
            &false,
            &sig
        )
    }

    fn do_mint_soulbound(
        client: &ClipsNftContractClient,
        env: &Env,
        to: &Address,
        clip_id: u32,
        keypair: &ed25519_dalek::SigningKey,
    ) -> TokenId {
        let uri = String::from_str(env, "ipfs://QmExample");
        let sig = sign_mint(env, keypair, to, clip_id, &uri);
        client.mint(
            to,
            &clip_id,
            &uri,
            &None,  // image
            &None,  // animation_url
            &default_royalty(env, to.clone()),
            &true,
            &sig
        )
    }

    #[test]
    fn test_version() {
        let env = Env::default();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        assert_eq!(client.version(), 1);
    }

    #[test]
    fn test_fee_estimators_return_expected_values() {
        let env = Env::default();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        assert_eq!(client.estimate_mint_fee(), GAS_BASE_MINT as i128);
        assert_eq!(client.estimate_transfer_fee(), GAS_BASE_TRANSFER as i128);
    }

    #[test]
    fn test_contract_info_contains_core_fields() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        let info = client.contract_info();
        assert_eq!(info.name, String::from_str(&env, "ClipCash Clips"));
        assert_eq!(info.symbol, String::from_str(&env, "CLIP"));
        assert_eq!(info.version, VERSION);
        assert_eq!(info.owner, admin);
        assert_eq!(info.platform_fee, 100);
    }

    #[test]
    fn test_mint_cooldown_enforced_and_configurable() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        client.set_mint_cooldown(&admin, &120);
        assert_eq!(client.get_mint_cooldown(), 120);

        let first_clip_id = 9_001u32;
        let first_uri = String::from_str(&env, "ipfs://QmCooldown1");
        let first_sig = sign_mint(&env, &kp, &user1, first_clip_id, &first_uri);
        client.mint(
            &user1,
            &first_clip_id,
            &first_uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &first_sig,
        );

        let second_clip_id = 9_002u32;
        let second_uri = String::from_str(&env, "ipfs://QmCooldown2");
        let second_sig = sign_mint(&env, &kp, &user1, second_clip_id, &second_uri);
        assert_eq!(
            client.try_mint(
                &user1,
                &second_clip_id,
                &second_uri,
                &None,
                &None,
                &default_royalty(&env, user1.clone()),
                &false,
                &second_sig,
            ),
            Err(Ok(Error::MintCooldownActive))
        );

        env.ledger().with_mut(|li| li.timestamp += 121);
        client.mint(
            &user1,
            &second_clip_id,
            &second_uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &second_sig,
        );
    }

    #[test]
    fn test_mint_stores_owner_and_uri() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 42, &kp);
        assert_eq!(token_id, 1);
        assert_eq!(client.owner_of(&token_id), user1);
        assert_eq!(client.token_uri(&token_id), String::from_str(&env, "ipfs://QmExample"));
        assert_eq!(client.total_supply(), 1);
    }

    #[test]
    fn test_set_token_uri_owner_only_and_precedence() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 4242, &kp);
        let custom_uri = String::from_str(&env, "ipfs://QmCustomOverride");
        client.set_token_uri(&user1, &token_id, &custom_uri);
        assert_eq!(client.token_uri(&token_id), custom_uri.clone());
        assert_eq!(client.get_metadata(&token_id), custom_uri);
    }

    #[test]
    fn test_set_token_uri_non_owner_fails() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 4343, &kp);
        let result = client.try_set_token_uri(&user2, &token_id, &String::from_str(&env, "ipfs://QmShouldFail"));
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
        assert_eq!(client.token_uri(&token_id), String::from_str(&env, "ipfs://QmExample"));
    }

    #[test]
    fn test_set_token_uri_emits_event() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 4344, &kp);
        let custom_uri = String::from_str(&env, "ipfs://QmNewURI");

        client.set_token_uri(&user1, &token_id, &custom_uri.clone());

        let events = env.events().all();
        assert!(
            events.events().len() > 0,
            "TokenUriChanged event should be emitted"
        );
    }

    #[test]
    fn test_clip_token_id_lookup() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 99, &kp);
        assert_eq!(client.clip_token_id(&99), token_id);
    }

    #[test]
    #[should_panic]
    fn test_double_mint_same_clip_id_panics() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        do_mint(&client, &env, &user1, 7, &kp);
        do_mint(&client, &env, &user1, 7, &kp);
    }

    #[test]
    fn test_mint_emits_event() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 5, &kp);
        let events = env.events().all();
        // Mint emits both MintEvent and TransferEvent
        assert_eq!(events.events().len(), 2);
        assert_eq!(token_id, 1);
    }

    #[test]
    fn test_mint_fails_without_signer_set() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp_bytes = soroban_sdk::BytesN::<32>::random(&env).to_array();
        let kp = ed25519_dalek::SigningKey::from_bytes(&kp_bytes);
        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig = sign_mint(&env, &kp, &user1, 1, &uri);
        let result = client.try_mint(
            &user1,
            &1u32,
            &uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig,
        );
        assert_eq!(result, Err(Ok(Error::SignerNotSet)));
    }

    #[test]
    #[should_panic]
    fn test_mint_fails_with_wrong_signature() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        register_signer(&env, &client, &admin);
        let wrong_kp = ed25519_dalek::SigningKey::from_bytes(&soroban_sdk::BytesN::<32>::random(&env).to_array());
        let uri = String::from_str(&env, "ipfs://QmExample");
        let bad_sig = sign_mint(&env, &wrong_kp, &user1, 1, &uri);
        client.mint(&user1, &1u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &bad_sig);
    }

    #[test]
    #[should_panic]
    fn test_mint_fails_with_wrong_owner_in_payload() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig_for_user2 = sign_mint(&env, &kp, &user2, 1, &uri);
        client.mint(&user1, &1u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &sig_for_user2);
    }

    #[test]
    #[should_panic]
    fn test_mint_fails_with_wrong_clip_id_in_payload() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig_for_99 = sign_mint(&env, &kp, &user1, 99, &uri);
        client.mint(&user1, &1u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &sig_for_99);
    }

    #[test]
    fn test_set_signer_and_rotate() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp1 = register_signer(&env, &client, &admin);
        let kp1_pub = BytesN::from_array(&env, &kp1.verifying_key().to_bytes());
        assert_eq!(client.get_signer(), Some(kp1_pub));
        let kp2 = ed25519_dalek::SigningKey::from_bytes(&soroban_sdk::BytesN::<32>::random(&env).to_array());
        let kp2_pub = BytesN::from_array(&env, &kp2.verifying_key().to_bytes());
        client.set_signer(&admin, &kp2_pub);
        assert_eq!(client.get_signer(), Some(kp2_pub));
        let uri = String::from_str(&env, "ipfs://QmExample");
        let old_sig = sign_mint(&env, &kp1, &user1, 1, &uri);
        let result = client.try_mint(
            &user1,
            &1u32,
            &uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &old_sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_blacklist_clip_prevents_mint() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let clip_id = 777u32;
        client.blacklist_clip(&admin, &clip_id);

        let uri = String::from_str(&env, "ipfs://QmBlacklisted");
        let sig = sign_mint(&env, &kp, &user1, clip_id, &uri);
        let result = client.try_mint(
            &user1,
            &clip_id,
            &uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig,
        );
        assert_eq!(result, Err(Ok(Error::ClipBlacklisted)));
    }

    #[test]
    fn test_blacklist_clip_emits_event() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        client.blacklist_clip(&admin, &888u32);
        let events = env.events().all();
        assert!(!events.events().is_empty());
    }

    #[test]
    fn test_royalty_helper_zero_price_fails() {
        let (env, _, user1, _) = setup();
        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient {
            recipient: user1,
            basis_points: 10_000,
        });
        let royalty = Royalty {
            recipients,
            asset_address: None,
        };

        let result = royalty.calculate_royalty(0);
        assert_eq!(result, Err(Error::InvalidSalePrice));
    }

    #[test]
    fn test_royalty_helper_max_royalty_returns_full_sale_price() {
        let (env, _, user1, _) = setup();
        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient {
            recipient: user1,
            basis_points: 10_000, // 100%
        });
        let royalty = Royalty {
            recipients,
            asset_address: None,
        };

        let sale_price = 123_456_789i128;
        let amount = royalty.calculate_royalty(sale_price).unwrap();
        assert_eq!(amount, sale_price);
    }

    #[test]
    fn test_mint_fails_with_unsupported_url_protocol() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig = sign_mint(&env, &kp, &user1, 808, &uri);
        let image = Some(String::from_str(&env, "ftp://example.com/poster.png"));

        let result = client.try_mint(
            &user1,
            &808u32,
            &uri,
            &image,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig,
        );
        assert_eq!(result, Err(Ok(Error::UnsupportedProtocol)));
    }

    #[test]
    fn test_mint_fails_with_malformed_url() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig = sign_mint(&env, &kp, &user1, 809, &uri);
        let image = Some(String::from_str(&env, "https://"));

        let result = client.try_mint(
            &user1,
            &809u32,
            &uri,
            &image,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig,
        );
        assert_eq!(result, Err(Ok(Error::MalformedUrl)));
    }

    #[test]
    fn test_default_royalty_asset_applied_when_not_provided() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let default_asset = Address::generate(&env);
        client.set_default_royalty_asset(&admin, &Some(default_asset.clone()));
        assert_eq!(client.get_default_royalty_asset(), Some(default_asset.clone()));

        let token_id = do_mint(&client, &env, &user1, 901, &kp);
        let stored = client.get_royalty(&token_id);
        assert_eq!(stored.asset_address, Some(default_asset));
    }

    #[test]
    fn test_explicit_royalty_asset_overrides_default() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let default_asset = Address::generate(&env);
        let explicit_asset = Address::generate(&env);
        client.set_default_royalty_asset(&admin, &Some(default_asset));

        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient {
            recipient: user1.clone(),
            basis_points: 500,
        });
        let royalty = Royalty {
            recipients,
            asset_address: Some(explicit_asset.clone()),
        };
        let uri = String::from_str(&env, "ipfs://QmCustomAsset");
        let sig = sign_mint(&env, &kp, &user1, 902, &uri);
        let token_id = client.mint(&user1, &902u32, &uri, &None, &None, &royalty, &false, &sig);

        let stored = client.get_royalty(&token_id);
        assert_eq!(stored.asset_address, Some(explicit_asset));
    }

    #[test]
    fn test_transfer_updates_owner() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 1, &kp);
        client.transfer(&user1, &user2, &token_id, &0, &None);
        assert_eq!(client.owner_of(&token_id), user2);
    }

    #[test]
    fn test_transfer_emits_event() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 3, &kp);
        client.transfer(&user1, &user2, &token_id, &0, &None);
        let events = env.events().all();
        assert_eq!(events.events().len(), 1);
    }

    #[test]
    fn test_total_supply_derived_from_next_token_id() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        assert_eq!(client.total_supply(), 0);
        do_mint(&client, &env, &user1, 1, &kp);
        assert_eq!(client.total_supply(), 1);
        do_mint(&client, &env, &user1, 2, &kp);
        assert_eq!(client.total_supply(), 2);
    }

    #[test]
    fn test_royalty_info_xlm() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 1, &kp);
        let info = client.royalty_info(&token_id, &1_000_000i128);
        assert_eq!(info.royalty_amount, 60_000i128);
        assert_eq!(info.asset_address, None);
    }

    #[test]
    fn test_royalty_info_custom_asset() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let asset_addr = Address::generate(&env);
        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient { recipient: user1.clone(), basis_points: 1000 });
        let royalty = Royalty { recipients, asset_address: Some(asset_addr.clone()) };
        let uri = String::from_str(&env, "ipfs://QmCustom");
        let sig = sign_mint(&env, &kp, &user1, 2, &uri);
        let token_id = client.mint(&user1, &2u32, &uri, &None, &None, &royalty, &false, &sig);
        let info = client.royalty_info(&token_id, &500i128);
        assert_eq!(info.royalty_amount, 55i128);
        assert_eq!(info.asset_address, Some(asset_addr));
    }

    #[test]
    fn test_set_royalty_with_custom_asset() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 1, &kp);
        let asset_addr = Address::generate(&env);
        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient { recipient: user2.clone(), basis_points: 1000 });
        let new_royalty = Royalty { recipients, asset_address: Some(asset_addr.clone()) };
        client.set_royalty(&admin, &token_id, &new_royalty);
        let stored = client.get_royalty(&token_id);
        assert_eq!(stored.recipients.get(0).unwrap().recipient, user2);
        assert_eq!(stored.recipients.get(0).unwrap().basis_points, 1000);
        assert_eq!(stored.recipients.len(), 2);
        assert_eq!(stored.asset_address, Some(asset_addr));
    }

    #[test]
    fn test_burn() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 1, &kp);
        client.burn(&user1, &token_id);
        assert!(!client.exists(&token_id));
        let token_id2 = do_mint(&client, &env, &user1, 1, &kp);
        assert!(client.exists(&token_id2));
    }

    #[test]
    fn test_burn_emits_event() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 77, &kp);
        client.burn(&user1, &token_id);
        let events = env.events().all();
        // Burn emits both BurnEvent and TransferEvent
        assert_eq!(events.events().len(), 2);
    }

    #[test]
    fn test_pause_blocks_mint() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        assert!(!client.is_paused());
        client.pause(&admin);
        assert!(!client.is_paused());
        env.ledger().with_mut(|l| l.timestamp += 86_400 + 1);
        assert!(client.is_paused());
        let uri = String::from_str(&env, "ipfs://QmPaused");
        let sig = sign_mint(&env, &kp, &user1, 1, &uri);
        let result = client.try_mint(
            &user1,
            &1u32,
            &uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig,
        );
        assert_eq!(result, Err(Ok(Error::ContractPaused)));
    }

    #[test]
    fn test_pause_blocks_transfer() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 1, &kp);
        client.pause(&admin);
        env.ledger().with_mut(|l| l.timestamp += 86_400 + 1);
        let result = client.try_transfer(&user1, &user2, &token_id, &0, &None);
        assert_eq!(result, Err(Ok(Error::ContractPaused)));
    }

    #[test]
    fn test_unpause_restores_mint_and_transfer() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        client.pause(&admin);
        client.unpause(&admin);
        assert!(!client.is_paused());
        let token_id = do_mint(&client, &env, &user1, 1, &kp);
        client.transfer(&user1, &user2, &token_id, &0, &None);
        assert_eq!(client.owner_of(&token_id), user2);
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_pause() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        client.pause(&user1);
    }

    // soulbound tests
    #[test]
    fn test_mint_soulbound_token() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint_soulbound(&client, &env, &user1, 100, &kp);
        assert_eq!(token_id, 1);
        assert_eq!(client.owner_of(&token_id), user1);
        assert!(client.is_soulbound(&token_id));
    }

    #[test]
    fn test_soulbound_transfer_blocked() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint_soulbound(&client, &env, &user1, 101, &kp);
        let result = client.try_transfer(&user1, &user2, &token_id, &0, &None);
        assert_eq!(result, Err(Ok(Error::SoulboundTransferBlocked)));
        assert_eq!(client.owner_of(&token_id), user1);
    }

    #[test]
    fn test_regular_token_transferable() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 102, &kp);
        assert!(!client.is_soulbound(&token_id));
        client.transfer(&user1, &user2, &token_id, &0, &None);
        assert_eq!(client.owner_of(&token_id), user2);
    }

    #[test]
    fn test_soulbound_can_be_burned() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint_soulbound(&client, &env, &user1, 103, &kp);
        client.burn(&user1, &token_id);
        assert!(!client.exists(&token_id));
    }

    // royalty overflow / safe math tests
    #[test]
    fn test_royalty_calculation_safe_math() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let uri = String::from_str(&env, "ipfs://QmExample");

        let token_id = do_mint(&client, &env, &user1, 104, &kp);
        let info = client.royalty_info(&token_id, &1_000_000_000_000_000i128);
        assert_eq!(info.royalty_amount, 60_000_000_000_000i128);
    }

    #[test]
    fn test_royalty_overflow_detection() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 105, &kp);
        let result = client.try_royalty_info(&token_id, &i128::MAX);
        assert_eq!(result, Err(Ok(Error::RoyaltyOverflow)));
    }

    #[test]
    fn test_royalty_calculation_max_safe_price() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 106, &kp);
        let info = client.royalty_info(&token_id, &(i128::MAX / 10_000));
        assert!(info.royalty_amount > 0);
    }

    #[test]
    fn test_royalty_recipient_updated_event() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 107, &kp);
        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient {
            recipient: user2.clone(),
            basis_points: 500,
        });
        let new_royalty = Royalty {
            recipients,
            asset_address: None,
        };
        
        client.set_royalty(&admin, &token_id, &new_royalty);

        let stored = client.get_royalty(&token_id);
        assert_eq!(stored.recipients.get(0).unwrap().recipient, user2);
    }

    #[test]
    fn test_royalty_recipient_no_event_if_unchanged() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 108, &kp);
        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient { recipient: user1.clone(), basis_points: 600 });
        client.set_royalty(&admin, &token_id, &Royalty { recipients, asset_address: None });
        let updated = client.get_royalty(&token_id);
        assert_eq!(updated.recipients.get(0).unwrap().basis_points, 600);
    }

    #[test]
    fn test_double_mint_prevention() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let uri = String::from_str(&env, "ipfs://QmUnique");
        let sig = sign_mint(&env, &kp, &user1, 202, &uri);
        let token_id = client.mint(&user1, &202u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &sig);
        assert_eq!(token_id, 1);
        let sig2 = sign_mint(&env, &kp, &user1, 202, &uri);
        let result = client.try_mint(
            &user1,
            &202u32,
            &uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig2,
        );
        assert_eq!(result, Err(Ok(Error::ClipAlreadyMinted)));
    }

    #[test]
    fn test_mint_and_burn_cycle() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 204, &kp);
        assert!(client.exists(&token_id));
        client.burn(&user1, &token_id);
        assert!(!client.exists(&token_id));
        let token_id2 = do_mint(&client, &env, &user1, 204, &kp);
        assert!(client.exists(&token_id2));
    }

    #[test]
    fn test_multiple_mints_increment_token_id() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        assert_eq!(do_mint(&client, &env, &user1, 205, &kp), 1);
        assert_eq!(do_mint(&client, &env, &user1, 206, &kp), 2);
        assert_eq!(do_mint(&client, &env, &user1, 207, &kp), 3);
        assert_eq!(client.total_supply(), 3);
    }

    #[test]
    fn test_royalty_with_zero_sale_price_fails() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 208, &kp);
        assert_eq!(client.try_royalty_info(&token_id, &0i128), Err(Ok(Error::InvalidSalePrice)));
        assert_eq!(client.try_royalty_info(&token_id, &(-1000i128)), Err(Ok(Error::InvalidSalePrice)));
    }

    #[test]
    fn test_royalty_calculation_accuracy() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 209, &kp);
        for (price, expected) in [(100i128, 6i128), (1000, 60), (10000, 600), (1_000_000, 60_000)] {
            assert_eq!(client.royalty_info(&token_id, &price).royalty_amount, expected);
        }
    }

    // -------------------------------------------------------------------------
    // Task 1: update_royalty_recipient tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_update_royalty_recipient_success() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 300, &kp);

        // user1 is the primary recipient — they can update to user2
        client.update_royalty_recipient(&user1, &token_id, &user2);

        let royalty = client.get_royalty(&token_id);
        assert_eq!(royalty.recipients.get(0).unwrap().recipient, user2);
    }

    #[test]
    fn test_update_royalty_recipient_unauthorized() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 301, &kp);

        // user2 is not the royalty recipient — should fail
        let result = client.try_update_royalty_recipient(&user2, &token_id, &user2);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn test_update_royalty_recipient_emits_event() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 302, &kp);
        client.update_royalty_recipient(&user1, &token_id, &user2);

        let events = env.events().all();
        assert!(events.events().len() > 0);
    }

    // -------------------------------------------------------------------------
    // Task 1 (Issue #124): tokens_of_owner tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_tokens_of_owner_returns_owned_tokens() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let t1 = do_mint(&client, &env, &user1, 400, &kp);
        let t2 = do_mint(&client, &env, &user1, 401, &kp);
        let _t3 = do_mint(&client, &env, &user2, 402, &kp);

        // Pause the contract and advance time past the 24-hour timelock
        client.pause(&admin);
        env.ledger().set_timestamp(env.ledger().timestamp() + 86401);

        let uri = String::from_str(&env, "ipfs://QmPaused");
        let sig = sign_mint(&env, &kp, &user1, 1, &uri);
        let result = client.try_mint(
            &user1,
            &1u32,
            &uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig,
        );
        assert_eq!(result, Err(Ok(Error::ContractPaused)));
        let owned = client.tokens_of_owner(&user1, &None, &None);
        assert_eq!(owned.len(), 2);
        assert_eq!(owned.get(0).unwrap(), t1);
        assert_eq!(owned.get(1).unwrap(), t2);
    }

    #[test]
    fn test_tokens_of_owner_empty_for_non_owner() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        do_mint(&client, &env, &user1, 403, &kp);

        let owned = client.tokens_of_owner(&user2, &None, &None);
        assert_eq!(owned.len(), 0);
    }

    #[test]
    fn test_tokens_of_owner_updates_after_transfer() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 404, &kp);
        client.transfer(&user1, &user2, &token_id, &0, &None);

        assert_eq!(client.tokens_of_owner(&user1, &None, &None).len(), 0);
        assert_eq!(client.tokens_of_owner(&user2, &None, &None).len(), 1);
    }

    #[test]
    fn test_tokens_of_owner_respects_result_limit() {
        // This test verifies that tokens_of_owner respects the MAX_RESULTS limit
        // to prevent gas explosion. While we can't easily test 1000+ tokens,
        // we verify that the function returns a bounded result.
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        // Mint 5 tokens to verify basic functionality
        let mut minted = Vec::new(&env);
        for i in 0..5u32 {
            let token_id = do_mint(&client, &env, &user1, 500 + i, &kp);
            minted.push_back(token_id);
        }

        let owned = client.tokens_of_owner(&user1, &None, &None);
        assert_eq!(owned.len(), 5);
        
        // Verify returned tokens match minted tokens
        for i in 0..5 {
            assert_eq!(owned.get(i as u32).unwrap(), minted.get(i as u32).unwrap());
        }
    }

    #[test]
    fn test_tokens_of_owner_pagination_limit() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        // Mint 10 tokens
        let mut minted = Vec::new(&env);
        for i in 0..10u32 {
            let token_id = do_mint(&client, &env, &user1, 600 + i, &kp);
            minted.push_back(token_id);
        }

        // Test limit parameter
        let page1 = client.tokens_of_owner(&user1, &Some(3u32), &None);
        assert_eq!(page1.len(), 3);
        assert_eq!(page1.get(0).unwrap(), minted.get(0).unwrap());
        assert_eq!(page1.get(1).unwrap(), minted.get(1).unwrap());
        assert_eq!(page1.get(2).unwrap(), minted.get(2).unwrap());

        let page2 = client.tokens_of_owner(&user1, &Some(3u32), &None);
        assert_eq!(page2.len(), 3);
    }

    #[test]
    fn test_tokens_of_owner_pagination_offset() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        // Mint 10 tokens
        let mut minted = Vec::new(&env);
        for i in 0..10u32 {
            let token_id = do_mint(&client, &env, &user1, 610 + i, &kp);
            minted.push_back(token_id);
        }

        // Test offset parameter - skip first 3
        let page = client.tokens_of_owner(&user1, &None, &Some(3u32));
        assert_eq!(page.len(), 7);
        assert_eq!(page.get(0).unwrap(), minted.get(3).unwrap());
        assert_eq!(page.get(1).unwrap(), minted.get(4).unwrap());
    }

    #[test]
    fn test_tokens_of_owner_pagination_limit_and_offset() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        // Mint 10 tokens
        let mut minted = Vec::new(&env);
        for i in 0..10u32 {
            let token_id = do_mint(&client, &env, &user1, 620 + i, &kp);
            minted.push_back(token_id);
        }

        // Test both limit and offset - get page 2 (skip 3, take 3)
        let page1 = client.tokens_of_owner(&user1, &Some(3u32), &Some(0u32));
        assert_eq!(page1.len(), 3);
        assert_eq!(page1.get(0).unwrap(), minted.get(0).unwrap());
        assert_eq!(page1.get(1).unwrap(), minted.get(1).unwrap());
        assert_eq!(page1.get(2).unwrap(), minted.get(2).unwrap());

        let page2 = client.tokens_of_owner(&user1, &Some(3u32), &Some(3u32));
        assert_eq!(page2.len(), 3);
        assert_eq!(page2.get(0).unwrap(), minted.get(3).unwrap());
        assert_eq!(page2.get(1).unwrap(), minted.get(4).unwrap());
        assert_eq!(page2.get(2).unwrap(), minted.get(5).unwrap());

        let page3 = client.tokens_of_owner(&user1, &Some(3u32), &Some(6u32));
        assert_eq!(page3.len(), 3);
        assert_eq!(page3.get(0).unwrap(), minted.get(6).unwrap());
        assert_eq!(page3.get(1).unwrap(), minted.get(7).unwrap());
        assert_eq!(page3.get(2).unwrap(), minted.get(8).unwrap());

        let page4 = client.tokens_of_owner(&user1, &Some(3u32), &Some(9u32));
        assert_eq!(page4.len(), 1);
        assert_eq!(page4.get(0).unwrap(), minted.get(9).unwrap());
    }

    #[test]
    fn test_tokens_of_owner_pagination_limit_exceeds_max() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        // Mint 5 tokens
        for i in 0..5u32 {
            do_mint(&client, &env, &user1, 630 + i, &kp);
        }

        // Test that limit exceeding MAX_RESULTS is capped
        let result = client.tokens_of_owner(&user1, &Some(2000u32), &None);
        assert_eq!(result.len(), 5); // Only 5 tokens exist
    }

    #[test]
    fn test_tokens_of_owner_pagination_offset_exceeds_count() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        // Mint 5 tokens
        for i in 0..5u32 {
            do_mint(&client, &env, &user1, 635 + i, &kp);
        }

        // Test that offset exceeding token count returns empty
        let result = client.tokens_of_owner(&user1, &None, &Some(10u32));
        assert_eq!(result.len(), 0);
    }

    // -------------------------------------------------------------------------
    // Task 2: batch_mint tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_batch_mint_success() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let uri1 = String::from_str(&env, "ipfs://QmBatch1");
        let uri2 = String::from_str(&env, "ipfs://QmBatch2");
        let sig1 = sign_mint(&env, &kp, &user1, 500, &uri1);
        let sig2 = sign_mint(&env, &kp, &user1, 501, &uri2);

        let mut clip_ids = Vec::new(&env);
        clip_ids.push_back(500u32);
        clip_ids.push_back(501u32);

        let mut uris = Vec::new(&env);
        uris.push_back(uri1.clone());
        uris.push_back(uri2.clone());

        let mut sigs = Vec::new(&env);
        sigs.push_back(sig1);
        sigs.push_back(sig2);

        let mut images = Vec::new(&env);
        images.push_back(None);
        images.push_back(None);

        let mut animation_urls = Vec::new(&env);
        animation_urls.push_back(None);
        animation_urls.push_back(None);

        let minted = client.batch_mint(
            &user1,
            &clip_ids,
            &uris,
            &images,
            &animation_urls,
            &default_royalty(&env, user1.clone()),
            &false,
            &sigs,
        );

        assert_eq!(minted.len(), 2);
        assert_eq!(client.owner_of(&minted.get(0).unwrap()), user1);
        assert_eq!(client.owner_of(&minted.get(1).unwrap()), user1);
        assert_eq!(client.token_uri(&minted.get(0).unwrap()), uri1);
        assert_eq!(client.token_uri(&minted.get(1).unwrap()), uri2);
    }

    #[test]
    fn test_batch_mint_duplicate_clip_id_fails() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        // Pre-mint clip 502
        do_mint(&client, &env, &user1, 502, &kp);

        let uri = String::from_str(&env, "ipfs://QmDup");
        let sig = sign_mint(&env, &kp, &user1, 502, &uri);

        let mut clip_ids = Vec::new(&env);
        clip_ids.push_back(502u32);
        let mut uris = Vec::new(&env);
        uris.push_back(uri);
        let mut images = Vec::new(&env);
        images.push_back(None);
        let mut animation_urls = Vec::new(&env);
        animation_urls.push_back(None);
        let mut sigs = Vec::new(&env);
        sigs.push_back(sig);

        let result = client.try_batch_mint(
            &user1,
            &clip_ids,
            &uris,
            &images,
            &animation_urls,
            &default_royalty(&env, user1.clone()),
            &false,
            &sigs,
        );
        assert_eq!(result, Err(Ok(Error::ClipAlreadyMinted)));
    }

    #[test]
    fn test_batch_mint_emits_event() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let uri = String::from_str(&env, "ipfs://QmBatchEvt");
        let sig = sign_mint(&env, &kp, &user1, 503, &uri);

        let mut clip_ids = Vec::new(&env);
        clip_ids.push_back(503u32);
        let mut uris = Vec::new(&env);
        uris.push_back(uri);
        let mut sigs = Vec::new(&env);
        sigs.push_back(sig);

        let mut images = Vec::new(&env);
        images.push_back(None);
        let mut animation_urls = Vec::new(&env);
        animation_urls.push_back(None);

        client.batch_mint(
            &user1,
            &clip_ids,
            &uris,
            &images,
            &animation_urls,
            &default_royalty(&env, user1.clone()),
            &false,
            &sigs,
        );

        let events = env.events().all();
        assert!(events.events().len() > 0);
    }

    // -------------------------------------------------------------------------
    // Task 3: exists tests (function already existed, verify behavior)
    // -------------------------------------------------------------------------

    #[test]
    fn test_exists_returns_true_for_minted_token() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 600, &kp);
        assert!(client.exists(&token_id));
    }

    #[test]
    fn test_exists_returns_false_for_unminted_token() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        assert!(!client.exists(&9999u32));
    }

    #[test]
    fn test_exists_returns_false_after_burn() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 601, &kp);
        client.burn(&user1, &token_id);
        assert!(!client.exists(&token_id));
    }

    // -------------------------------------------------------------------------
    // Task 4: calculate_royalty_amount tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_calculate_royalty_amount_basic() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 104, &kp);

        // Test with large but safe values
        let large_price = 1_000_000_000_000_000i128; // 10^15
        let info = client.royalty_info(&token_id, &large_price);

        // Should calculate without overflow: 10^15 * 600 / 10000 = 6 * 10^13
        assert_eq!(info.royalty_amount, 60_000_000_000_000i128);
        // default_royalty = 5% creator + 1% platform = 6% total
        let token_id = do_mint(&client, &env, &user1, 700, &kp);
        let amount = client.calculate_royalty_amount(&token_id, &10_000i128);
        assert_eq!(amount, 600i128); // 6% of 10000
    }

    #[test]
    fn test_calculate_royalty_amount_zero_price_fails() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 105, &kp);

        // Test with value that would overflow: i128::MAX
        let overflow_price = i128::MAX;
        let result = client.try_royalty_info(&token_id, &overflow_price);

        // Should detect overflow and return error
        assert_eq!(result, Err(Ok(Error::RoyaltyOverflow)));
        let token_id = do_mint(&client, &env, &user1, 701, &kp);
        let result = client.try_calculate_royalty_amount(&token_id, &0i128);
        assert_eq!(result, Err(Ok(Error::InvalidSalePrice)));
    }

    #[test]
    fn test_calculate_royalty_amount_overflow_fails() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 106, &kp);

        // Test with maximum safe price: i128::MAX / 10000
        let max_safe_price = i128::MAX / 10_000;
        let info = client.royalty_info(&token_id, &max_safe_price);

        // Should succeed with safe calculation
        assert!(info.royalty_amount > 0);
        let token_id = do_mint(&client, &env, &user1, 702, &kp);
        let result = client.try_calculate_royalty_amount(&token_id, &i128::MAX);
        assert_eq!(result, Err(Ok(Error::RoyaltyOverflow)));
    }

    // -------------------------------------------------------------------------
    // Task 1: 48-hour timelock tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_withdraw_timelock_is_48h() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        // Request a withdrawal — unlock_time should be now + 172_800 seconds
        client.request_withdraw_asset(&admin, &1_000i128);

        let request: WithdrawRequest = env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .get(&DataKey::WithdrawXlmRequest)
                .unwrap()
        });

        let expected_unlock = env.ledger().timestamp() + 172_800;
        assert_eq!(request.unlock_time, expected_unlock);
        assert_eq!(request.amount, 1_000i128);
    }

    #[test]
    fn test_withdraw_blocked_before_48h() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        client.request_withdraw_asset(&admin, &500i128);

        // Advance time by only 47 hours — still locked
        env.ledger().with_mut(|l| l.timestamp += 169_200);

        let asset = Address::generate(&env);
        let result = client.try_withdraw_asset(&admin, &asset, &500i128);
        assert_eq!(result, Err(Ok(Error::WithdrawalStillLocked)));
    }

    #[test]
    fn test_last_withdrawal_time_not_set_before_execution() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        // Before any withdrawal, LastWithdrawalTime should not exist
        let stored: Option<u64> = env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .get(&DataKey::LastWithdrawalTime)
        });
        assert_eq!(stored, None);

        // After requesting (but not executing), it should still be absent
        client.request_withdraw_asset(&admin, &100i128);
        let stored: Option<u64> = env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .get(&DataKey::LastWithdrawalTime)
        });
        assert_eq!(stored, None);
    }

    // -------------------------------------------------------------------------
    // Task 3 & 4: Royalty overflow — checked_mul, max i128 boundary tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_royalty_checked_mul_max_safe_boundary() {
        // sale_price == i128::MAX / 10_000 should succeed (boundary value)
        let max_safe = i128::MAX / 10_000;
        let result = ClipsNftContract::calculate_royalty(max_safe, 10_000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), max_safe); // 100% of max_safe
    }

    #[test]
    fn test_royalty_checked_mul_one_over_boundary_fails() {
        // sale_price == i128::MAX / 10_000 + 1 should overflow
        let over_boundary = i128::MAX / 10_000 + 1;
        let result = ClipsNftContract::calculate_royalty(over_boundary, 1);
        assert_eq!(result, Err(Error::RoyaltyOverflow));
    }

    #[test]
    fn test_royalty_checked_mul_i128_max_fails() {
        let result = ClipsNftContract::calculate_royalty(i128::MAX, 500);
        assert_eq!(result, Err(Error::RoyaltyOverflow));
    }

    #[test]
    fn test_royalty_checked_mul_zero_basis_points() {
        // 0 basis points → 0 royalty regardless of price
        let result = ClipsNftContract::calculate_royalty(1_000_000, 0);
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn test_balance_of_counts_owned_tokens() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        assert_eq!(client.balance_of(&user1), 0);
        let t1 = do_mint(&client, &env, &user1, 800, &kp);
        assert_eq!(client.balance_of(&user1), 1);
        let _t2 = do_mint(&client, &env, &user1, 801, &kp);
        assert_eq!(client.balance_of(&user1), 2);

        client.transfer(&user1, &user2, &t1, &0, &None);
        assert_eq!(client.balance_of(&user1), 1);
        assert_eq!(client.balance_of(&user2), 1);
    }

    #[test]
    fn test_token_by_index_enumerable() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let t1 = do_mint(&client, &env, &user1, 810, &kp);
        let t2 = do_mint(&client, &env, &user1, 811, &kp);
        let t3 = do_mint(&client, &env, &user1, 812, &kp);

        // Before any burn: index maps directly to minted order.
        assert_eq!(client.token_by_index(&0), t1);
        assert_eq!(client.token_by_index(&1), t2);
        assert_eq!(client.token_by_index(&2), t3);

        // Burn t1 (position 0). Swap-and-pop moves t3 into slot 0.
        client.burn(&user1, &t1);
        assert_eq!(client.total_supply(), 2);
        // Slot 0 now holds t3 (swapped from last position).
        assert_eq!(client.token_by_index(&0), t3);
        // Slot 1 still holds t2.
        assert_eq!(client.token_by_index(&1), t2);
        // Index 2 is now out of bounds.
        assert_eq!(client.try_token_by_index(&2), Err(Ok(Error::InvalidTokenId)));
    }

    #[test]
    fn test_token_by_index_out_of_bounds() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        do_mint(&client, &env, &user1, 820, &kp);
        let result = client.try_token_by_index(&5);
        assert_eq!(result, Err(Ok(Error::InvalidTokenId)));
    }

    #[test]
    fn test_royalty_checked_mul_large_safe_price() {
        // 10^15 stroops * 600 bps / 10_000 = 6 * 10^13
        let result = ClipsNftContract::calculate_royalty(1_000_000_000_000_000i128, 600);
        assert_eq!(result, Ok(60_000_000_000_000i128));
    }

    #[test]
    fn test_royalty_max_basis_points_at_max_safe_price() {
        // Test maximum basis points (10,000 = 100%) at maximum safe price
        let max_safe = i128::MAX / 10_000;
        let result = ClipsNftContract::calculate_royalty(max_safe, 10_000);
        assert!(result.is_ok());
        // 100% of max_safe should equal max_safe (with rounding)
        assert_eq!(result.unwrap(), max_safe);
    }

    #[test]
    fn test_royalty_min_basis_points_at_max_safe_price() {
        // Test minimum basis points (1 = 0.01%) at maximum safe price
        let max_safe = i128::MAX / 10_000;
        let result = ClipsNftContract::calculate_royalty(max_safe, 1);
        assert!(result.is_ok());
        // Should be approximately 0.01% of max_safe
        let expected = (max_safe + 5_000) / 10_000;
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn test_royalty_rounding_at_boundary() {
        // Test rounding behavior with the +5,000 offset
        // (sale_price * basis_points + 5_000) / 10_000
        let result = ClipsNftContract::calculate_royalty(10_000, 1);
        // (10_000 * 1 + 5_000) / 10_000 = 15_000 / 10_000 = 1
        assert_eq!(result, Ok(1));
    }

    #[test]
    fn test_royalty_accumulation_does_not_overflow() {
        // Test that multiple royalty calculations in sequence don't overflow
        let max_safe = i128::MAX / 10_000;
        // First calculation at max safe price
        let result1 = ClipsNftContract::calculate_royalty(max_safe, 5_000);
        assert!(result1.is_ok());
        // Second calculation should also work
        let result2 = ClipsNftContract::calculate_royalty(max_safe, 5_000);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_royalty_negative_sale_price_fails() {
        // Negative sale prices should be rejected
        let result = ClipsNftContract::calculate_royalty(-1, 500);
        assert_eq!(result, Err(Error::InvalidSalePrice));
    }

    #[test]
    fn test_royalty_i128_min_fails() {
        // i128::MIN should be rejected as invalid sale price
        let result = ClipsNftContract::calculate_royalty(i128::MIN, 500);
        assert_eq!(result, Err(Error::InvalidSalePrice));
    }

    // -------------------------------------------------------------------------
    // Issue #117: refresh_metadata with 30-day cooldown
    // -------------------------------------------------------------------------

    #[test]
    fn test_refresh_metadata_admin_success() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 2000, &kp);

        let uri = String::from_str(&env, "ipfs://QmUnauth");
        // Sign for user1 but try to mint as user2
        let sig = sign_mint(&env, &kp, &user1, 203, &uri);

        let result = client.try_mint(
            &user2,
            &203u32,
            &uri,
            &None,
            &None,
            &default_royalty(&env, user2.clone()),
            &false,
            &sig,
        );
        // Should fail because signature doesn't match the caller
        assert!(result.is_err());
        let new_uri = String::from_str(&env, "ipfs://QmRefreshed");
        client.refresh_metadata(&admin, &token_id, &Some(new_uri.clone()), &None, &None);

        assert_eq!(client.token_uri(&token_id), new_uri);
    }

    #[test]
    fn test_refresh_metadata_emits_event() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        // Mint token
        let token_id = do_mint(&client, &env, &user1, 204, &kp);
        assert!(client.exists(&token_id));
        assert_eq!(client.total_supply(), 1);

        // Burn token
        client.burn(&user1, &token_id);
        assert!(!client.exists(&token_id));
        // total_supply is decremented on burn
        assert_eq!(client.total_supply(), 0);

        // Can re-mint same clip_id after burn
        let token_id2 = do_mint(&client, &env, &user1, 204, &kp);
        assert!(client.exists(&token_id2));
        assert_eq!(client.total_supply(), 1);
        let new_uri = String::from_str(&env, "ipfs://QmRefreshedEvt");
        client.refresh_metadata(&admin, &token_id2, &Some(new_uri.clone()), &None, &None);

        let events = env.events().all();
        assert!(events.events().len() >= 1);
        assert_eq!(client.token_uri(&token_id2), new_uri);
    }

    #[test]
    fn test_refresh_metadata_non_admin_fails() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 2002, &kp);

        let result = client.try_refresh_metadata(
            &user1,
            &token_id,
            &Some(String::from_str(&env, "ipfs://QmHack")),
            &None,
            &None,
        );
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn test_refresh_metadata_cooldown_enforced() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 2003, &kp);

        client.refresh_metadata(&admin, &token_id, &Some(String::from_str(&env, "ipfs://QmFirst")), &None, &None);

        // Advance time by 29 days — still within cooldown
        env.ledger().with_mut(|l| l.timestamp += 29 * 24 * 3600);

        let result = client.try_refresh_metadata(
            &admin,
            &token_id,
            &Some(String::from_str(&env, "ipfs://QmTooSoon")),
            &None,
            &None,
        );
        assert_eq!(result, Err(Ok(Error::MetadataRefreshTooSoon)));
    }

    #[test]
    fn test_refresh_metadata_allowed_after_30_days() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 2004, &kp);

        client.refresh_metadata(&admin, &token_id, &Some(String::from_str(&env, "ipfs://QmFirst")), &None, &None);

        // Advance time by exactly 30 days
        env.ledger().with_mut(|l| l.timestamp += 30 * 24 * 3600);

        let new_uri = String::from_str(&env, "ipfs://QmSecond");
        client.refresh_metadata(&admin, &token_id, &Some(new_uri.clone()), &None, &None);
        assert_eq!(client.token_uri(&token_id), new_uri);
    }

    #[test]
    fn test_refresh_metadata_invalid_token_fails() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        let result = client.try_refresh_metadata(
            &admin,
            &9999u32,
            &Some(String::from_str(&env, "ipfs://QmGhost")),
            &None,
            &None,
        );
        assert_eq!(result, Err(Ok(Error::InvalidTokenId)));
    }

    #[test]
    fn test_refresh_metadata_backend_address_success() {
        let (env, admin, user1, backend) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        
        // Set backend address
        client.set_backend_address(&admin, &backend);
        
        let token_id = do_mint(&client, &env, &user1, 2005, &kp);
        let new_uri = String::from_str(&env, "ipfs://QmBackendRefresh");
        
        // Backend should be able to refresh metadata
        client.refresh_metadata(&backend, &token_id, &Some(new_uri.clone()), &None, &None);
        assert_eq!(client.token_uri(&token_id), new_uri);
    }

    #[test]
    fn test_refresh_metadata_backend_address_unauthorized_fails() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        
        // Set user2 as backend address
        client.set_backend_address(&admin, &user2);
        
        let token_id = do_mint(&client, &env, &user1, 2006, &kp);
        
        // user1 should not be able to refresh metadata (not admin, not backend)
        let result = client.try_refresh_metadata(
            &user1,
            &token_id,
            &Some(String::from_str(&env, "ipfs://QmHack")),
            &None,
            &None,
        );
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

    // -------------------------------------------------------------------------
    // get_tokens_by_clip_ids tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_get_tokens_by_clip_ids_all_minted() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let t1 = do_mint(&client, &env, &user1, 1000, &kp);
        let t2 = do_mint(&client, &env, &user1, 1001, &kp);
        let t3 = do_mint(&client, &env, &user1, 1002, &kp);

        let mut clip_ids = Vec::new(&env);
        clip_ids.push_back(1000u32);
        clip_ids.push_back(1001u32);
        clip_ids.push_back(1002u32);

        let result = client.get_tokens_by_clip_ids(&clip_ids);
        assert_eq!(result.len(), 3);
        assert_eq!(result.get(0).unwrap(), Some(t1));
        assert_eq!(result.get(1).unwrap(), Some(t2));
        assert_eq!(result.get(2).unwrap(), Some(t3));
    }

    #[test]
    fn test_get_tokens_by_clip_ids_partial_minted() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        // Only mint clip_id 1000
        let t1 = do_mint(&client, &env, &user1, 1000, &kp);

        let mut clip_ids = Vec::new(&env);
        clip_ids.push_back(1000u32); // minted
        clip_ids.push_back(1001u32); // not minted
        clip_ids.push_back(1002u32); // not minted

        let result = client.get_tokens_by_clip_ids(&clip_ids);
        assert_eq!(result.len(), 3);
        assert_eq!(result.get(0).unwrap(), Some(t1));
        assert_eq!(result.get(1).unwrap(), None);
        assert_eq!(result.get(2).unwrap(), None);
    }

    #[test]
    fn test_get_tokens_by_clip_ids_empty_input() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        let clip_ids = Vec::new(&env);
        let result = client.get_tokens_by_clip_ids(&clip_ids);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_get_tokens_by_clip_ids_all_unminted() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        let mut clip_ids = Vec::new(&env);
        clip_ids.push_back(2000u32);
        clip_ids.push_back(2001u32);
        clip_ids.push_back(2002u32);

        let result = client.get_tokens_by_clip_ids(&clip_ids);
        assert_eq!(result.len(), 3);
        assert_eq!(result.get(0).unwrap(), None);
        assert_eq!(result.get(1).unwrap(), None);
        assert_eq!(result.get(2).unwrap(), None);
    }

    // -------------------------------------------------------------------------
    // Circuit breaker tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_circuit_breaker_disabled_by_default() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        assert!(!client.circuit_breaker_enabled());
    }

    #[test]
    fn test_circuit_breaker_can_be_enabled() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        client.set_circuit_breaker_enabled(&admin, &true);
        assert!(client.circuit_breaker_enabled());
    }

    #[test]
    fn test_circuit_breaker_threshold_configurable() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        client.set_circuit_breaker_threshold(&admin, &50);
        assert_eq!(client.circuit_breaker_threshold(), 50);
    }

    #[test]
    fn test_circuit_breaker_window_configurable() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        client.set_circuit_breaker_window(&admin, &30);
        assert_eq!(client.circuit_breaker_window_seconds(), 30);
    }

    #[test]
    fn test_circuit_breaker_non_admin_cannot_configure() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        let result = client.try_set_circuit_breaker_enabled(&user1, &true);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));

        let result = client.try_set_circuit_breaker_threshold(&user1, &50);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));

        let result = client.try_set_circuit_breaker_window(&user1, &30);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));

        let result = client.try_reset_circuit_breaker(&user1);
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
    }

}
