# ClipCash NFT — Security Audit Preparation

Closes #226

## Scope

| File | Role |
|------|------|
| `clips_nft/src/lib.rs` | Soroban contract implementation |
| `clips_nft/src/safe_math.rs` | Checked royalty arithmetic |

## Executive summary

The contract is prepared for external audit with reentrancy guards on token-transfer entrypoints, centralized overflow-safe royalty math, and documented privileged operations below.

## Privileged functions (admin / trusted roles)

| Function | Role | Mitigation |
|----------|------|------------|
| `init` | One-time deployer | Panics on re-init |
| `set_admin` | Admin rotation | `require_admin` + auth |
| `set_signer` | Backend key rotation | Admin-only |
| `upgrade` | WASM upgrade | Admin-only + event |
| `pause` / `unpause` | Emergency stop | Admin-only; 24h timelock before active |
| `blacklist_clip` | Block clip mint | Admin-only |
| `freeze` / `unfreeze` | Block token transfer | Admin-only |
| `set_royalty` | Override royalties | Admin-only |
| `set_name` / `set_symbol` | Metadata branding | Admin-only |
| `set_platform_fee` / `set_default_royalty` | Economic params | Admin-only, capped at 10_000 bps |
| `set_mint_cooldown` | Rate limit mints | Admin-only |
| `refresh_metadata` | URI override | Admin-only, 30-day cooldown |
| `request_withdraw_asset` / `withdraw_asset` | Treasury pull | Admin-only, 48h timelock |
| `mint` | User mint | Ed25519 backend signature + cooldown |
| `pay_royalty` | Marketplace payout | Payer auth + reentrancy lock |
| `claim_royalties` | Creator claim | Recipient auth + reentrancy lock |

## Findings and mitigations

### F-1 Reentrancy via SEP-0041 token hooks

**Risk:** Malicious token contract could re-enter `pay_royalty`, `claim_royalties`, or `withdraw_asset` during `transfer`.

**Mitigation:** Instance-level `ReentrancyLock` with `Error::Reentrancy` (24). Guards acquired before external token calls and released on exit.

**Status:** Implemented.

### F-2 Integer overflow in royalty math

**Risk:** `sale_price × basis_points` can overflow `i128` for extreme inputs.

**Mitigation:** `safe_math::safe_royalty_amount` pre-checks `sale_price ≤ i128::MAX / 10_000` and uses `checked_mul` / `checked_add`. Property tests in `tests/safe_math_fuzz.rs`.

**Status:** Implemented.

### F-3 Pause timelock reduces surprise shutdown

**Risk:** Instant pause could trap in-flight marketplace sales.

**Mitigation:** `pause` schedules activation 24 hours ahead; `is_paused` reflects elapsed timelock.

**Status:** Implemented (verify UX with auditors).

### F-4 XLM royalties not handled in `pay_royalty`

**Risk:** Callers may expect on-chain XLM transfer; only SEP-0041 assets are supported in `pay_royalty`.

**Mitigation:** Returns `InvalidRecipient` when `asset_address` is `None`. Documented in README and audit checklist.

**Status:** Accepted design; auditors should confirm marketplace flow.

### F-5 Claim balance vs direct payout

**Risk:** `pay_royalty` pays recipients directly while `RoyaltyBalance` accrues; `claim_royalties` transfers from contract balance which may be empty.

**Mitigation:** Auditors should validate intended escrow model. Recommend follow-up: either escrow to contract before split, or remove accrual if unused.

**Status:** Open for auditor review.

## Pre-audit test evidence

```bash
cargo test
cargo test --test safe_math_fuzz
cargo test --test sep41_royalty_integration
```

## Auditor checklist

Use `AUDIT_CHECKLIST.md` for line-by-line verification during the formal engagement.
