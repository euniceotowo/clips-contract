//! Upgrade and migration tests for ClipsNftContract.
//!
//! These tests verify that:
//! 1. `upgrade()` preserves all existing NFT and royalty state.
//! 2. `migrate()` correctly seeds missing fields and bumps ContractVersion.
//! 3. `migrate()` is idempotent (safe to call twice).
//! 4. Only the admin can call `upgrade()` and `migrate()`.
//! 5. A simulated "old contract" (version 0, no TotalSupply key) migrates cleanly.

#![cfg(test)]

mod test_helpers;

use clips_nft::{ClipsNftContract, ClipsNftContractClient, Royalty, RoyaltyRecipient, VERSION};
use soroban_sdk::{
    testutils::{Address as _, BytesN as _},
    Address, BytesN, Env, String, Vec,
};
use test_helpers::{mint_clip, setup};

// ---------------------------------------------------------------------------
// Helper: deploy a fresh contract and return (env, client, admin)
// ---------------------------------------------------------------------------
fn deploy() -> (Env, ClipsNftContractClient<'static>, Address) {
    let ctx = setup();
    // SAFETY: setup() leaks the Env onto the heap.
    let env = unsafe { &*(ctx.env as *const Env) };
    (env.clone(), ctx.client, ctx.admin)
}

// ---------------------------------------------------------------------------
// Test 1 — upgrade() preserves NFT ownership and royalty data
// ---------------------------------------------------------------------------
#[test]
fn test_upgrade_preserves_nft_and_royalty_state() {
    let ctx = setup();
    let env = ctx.env;
    let client = &ctx.client;
    let admin = &ctx.admin;

    // Mint a few tokens before the upgrade.
    let owner = Address::generate(env);
    let token_id_1 = mint_clip(&ctx, &owner, 1001, false);
    let token_id_2 = mint_clip(&ctx, &owner, 1002, false);

    let pre_supply = client.total_supply();
    let pre_owner_1 = client.owner_of(&token_id_1);
    let pre_royalty_1 = client.get_royalty(&token_id_1);
    let pre_owner_2 = client.owner_of(&token_id_2);

    // Simulate upgrade: in tests we re-register the same WASM (no actual new
    // binary), so we use the existing contract hash as the "new" hash.
    // The important thing is that upgrade() + migrate() run without error and
    // that all storage survives.
    let contract_id = client.address.clone();
    let wasm_hash: BytesN<32> = env.deployer().upload_contract_wasm(
        clips_nft::ClipsNftContract::__wasm_bytes(),
    );

    // upgrade() must succeed.
    client.upgrade(admin, &wasm_hash);

    // migrate() must succeed and bump the version.
    client.migrate(admin);

    // --- Verify NFT state is intact ---
    assert_eq!(client.total_supply(), pre_supply, "total_supply changed after upgrade");
    assert_eq!(client.owner_of(&token_id_1), pre_owner_1, "owner changed after upgrade");
    assert_eq!(client.owner_of(&token_id_2), pre_owner_2, "owner changed after upgrade");

    // Royalty recipients and basis points must be unchanged.
    let post_royalty_1 = client.get_royalty(&token_id_1);
    assert_eq!(
        post_royalty_1.recipients.len(),
        pre_royalty_1.recipients.len(),
        "royalty recipient count changed"
    );
    for i in 0..pre_royalty_1.recipients.len() {
        let pre = pre_royalty_1.recipients.get(i).unwrap();
        let post = post_royalty_1.recipients.get(i).unwrap();
        assert_eq!(pre.recipient, post.recipient, "royalty recipient changed at index {i}");
        assert_eq!(pre.basis_points, post.basis_points, "royalty bps changed at index {i}");
    }

    // contract_version must now equal VERSION.
    assert_eq!(client.contract_version(), VERSION, "contract_version not bumped by migrate()");
}

// ---------------------------------------------------------------------------
// Test 2 — migrate() is idempotent
// ---------------------------------------------------------------------------
#[test]
fn test_migrate_is_idempotent() {
    let ctx = setup();
    let env = ctx.env;
    let client = &ctx.client;
    let admin = &ctx.admin;

    let wasm_hash: BytesN<32> = env.deployer().upload_contract_wasm(
        clips_nft::ClipsNftContract::__wasm_bytes(),
    );
    client.upgrade(admin, &wasm_hash);
    client.migrate(admin);

    let version_after_first = client.contract_version();

    // Second call must not panic or change the version.
    client.migrate(admin);
    assert_eq!(
        client.contract_version(),
        version_after_first,
        "migrate() changed version on second call"
    );
}

// ---------------------------------------------------------------------------
// Test 3 — only admin can call upgrade() and migrate()
// ---------------------------------------------------------------------------
#[test]
fn test_upgrade_and_migrate_require_admin() {
    let ctx = setup();
    let env = ctx.env;
    let client = &ctx.client;
    let admin = &ctx.admin;
    let non_admin = Address::generate(env);

    let wasm_hash: BytesN<32> = env.deployer().upload_contract_wasm(
        clips_nft::ClipsNftContract::__wasm_bytes(),
    );

    // Non-admin upgrade must fail.
    assert!(
        client.try_upgrade(&non_admin, &wasm_hash).is_err(),
        "non-admin should not be able to call upgrade()"
    );

    // Perform a legitimate upgrade so we can test migrate() access control.
    client.upgrade(admin, &wasm_hash);

    // Non-admin migrate must fail.
    assert!(
        client.try_migrate(&non_admin).is_err(),
        "non-admin should not be able to call migrate()"
    );
}

// ---------------------------------------------------------------------------
// Test 4 — migrate() seeds TotalSupply when it was missing (v0 → v1)
// ---------------------------------------------------------------------------
#[test]
fn test_migrate_seeds_total_supply_from_next_token_id() {
    let ctx = setup();
    let env = ctx.env;
    let client = &ctx.client;
    let admin = &ctx.admin;

    // Mint some tokens so NextTokenId > 1.
    let owner = Address::generate(env);
    mint_clip(&ctx, &owner, 2001, false);
    mint_clip(&ctx, &owner, 2002, false);
    mint_clip(&ctx, &owner, 2003, false);

    // Manually remove TotalSupply to simulate a pre-v1 deployment.
    // We do this by directly manipulating instance storage via the env.
    // In a real upgrade scenario the old binary simply never wrote this key.
    env.as_contract(&client.address, || {
        use clips_nft::DataKey;
        env.storage().instance().remove(&DataKey::TotalSupply);
    });

    // Confirm TotalSupply is gone (total_supply() returns 0 as fallback).
    assert_eq!(client.total_supply(), 0, "TotalSupply should be absent before migration");

    // Run migration.
    let wasm_hash: BytesN<32> = env.deployer().upload_contract_wasm(
        clips_nft::ClipsNftContract::__wasm_bytes(),
    );
    client.upgrade(admin, &wasm_hash);
    client.migrate(admin);

    // After migration TotalSupply must equal the number of minted tokens.
    assert_eq!(client.total_supply(), 3, "migrate() should have seeded TotalSupply = 3");
    assert_eq!(client.contract_version(), VERSION);
}

// ---------------------------------------------------------------------------
// Test 5 — upgrade() + migrate() with active royalty balances
// ---------------------------------------------------------------------------
#[test]
fn test_upgrade_preserves_royalty_balances() {
    let ctx = setup();
    let env = ctx.env;
    let client = &ctx.client;
    let admin = &ctx.admin;

    // Set up a SEP-0041 asset and mint a token with it.
    let token_admin = Address::generate(env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let stellar_asset = soroban_sdk::token::StellarAssetClient::new(env, &asset);

    let creator = Address::generate(env);
    let buyer = Address::generate(env);
    stellar_asset.mint(&buyer, &1_000_000i128);

    let clip_id = 3001u32;
    let uri = String::from_str(env, "ipfs://QmUpgradeRoyalty");
    let sig = test_helpers::sign_mint(env, &ctx.keypair, &creator, clip_id, &uri);
    let mut recipients = Vec::new(env);
    recipients.push_back(RoyaltyRecipient {
        recipient: creator.clone(),
        basis_points: 500,
    });
    let royalty = Royalty {
        recipients,
        asset_address: Some(asset.clone()),
    };
    let token_id = client.mint(
        &creator, &clip_id, &uri, &None, &None, &royalty, &false, &sig,
    );

    // Pay royalty to accumulate a balance.
    client.pay_royalty(&buyer, &token_id, &1_000_000i128);

    // Upgrade.
    let wasm_hash: BytesN<32> = env.deployer().upload_contract_wasm(
        clips_nft::ClipsNftContract::__wasm_bytes(),
    );
    client.upgrade(admin, &wasm_hash);
    client.migrate(admin);

    // Creator should still be able to claim their royalties after the upgrade.
    client.claim_royalties(&creator, &token_id);

    let token_client = soroban_sdk::token::TokenClient::new(env, &asset);
    assert!(
        token_client.balance(&creator) > 0,
        "creator should have received royalties after upgrade"
    );
}
