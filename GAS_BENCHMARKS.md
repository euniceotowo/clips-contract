# Gas Cost Benchmarks

Living document tracking approximate gas (instruction fee) costs for all major
contract operations. Update this file after every optimization pass and after
each mainnet deployment.

> **Units** — all figures are in *stroops* (1 XLM = 10 000 000 stroops) unless
> noted. Soroban charges *CPU instructions* and *memory bytes*; the numbers
> below reflect the instruction-fee component measured on Futurenet / Testnet.
> Mainnet values are noted separately where they differ.

---

## Measurement methodology

1. Run `cargo test -- --nocapture 2>&1 | grep gas` after enabling the
   `TotalGasMint` / `TotalGasTransfer` counters (see `average_gas_mint` /
   `average_gas_transfer` view functions).
2. Deploy to Testnet with `./deploy-testnet.sh` and observe the fee breakdown
   in Stellar Lab → Transaction → Operations.
3. Record the *base fee* (minimum network fee) plus the *inclusion fee* charged
   by the validator.

---

## Function benchmarks

| Function | Constant baseline | Testnet (stroops) | Mainnet (stroops) | Notes |
|---|---|---|---|---|
| `init` | — | ~5 000 | ~5 000 | One-time setup |
| `mint` | `GAS_BASE_MINT = 50 000` | ~50 000 | ~55 000 | Includes signature verify + enumeration index writes |
| `batch_mint` (N=1) | `GAS_BASE_MINT = 50 000` | ~52 000 | ~57 000 | Amortised per-token |
| `batch_mint` (N=25) | `GAS_BASE_MINT × 25` | ~1 200 000 | ~1 300 000 | Max batch size |
| `mint_with_signature` | `GAS_BASE_MINT = 50 000` | ~52 000 | ~57 000 | Nonce + replay-protection adds ~2 000 |
| `transfer` (no royalty) | `GAS_BASE_TRANSFER = 30 000` | ~30 000 | ~33 000 | No SEP-0041 call |
| `transfer` (with royalty) | `GAS_BASE_TRANSFER = 30 000` | ~45 000 | ~50 000 | Includes token client call per recipient |
| `burn` | — | ~25 000 | ~27 000 | 2 persistent removes + index cleanup |
| `burn_with_refund` (no balance) | — | ~25 000 | ~27 000 | Same as `burn` |
| `burn_with_refund` (with refund) | — | ~40 000 | ~44 000 | Adds SEP-0041 transfer |
| `freeze_token` | — | ~8 000 | ~8 500 | 1 persistent write |
| `unfreeze_token` | — | ~7 000 | ~7 500 | 1 persistent remove |
| `pay_royalty` | — | ~35 000 | ~38 000 | Per-recipient token transfer |
| `claim_royalties` | — | ~30 000 | ~33 000 | 1 persistent remove + 1 token transfer |
| `set_royalty` | — | ~12 000 | ~13 000 | 1 persistent read + write |
| `approve` | — | ~8 000 | ~8 500 | 1 persistent write |
| `set_approval_for_all` | — | ~8 000 | ~8 500 | 1 persistent write |
| `refresh_metadata` | — | ~10 000 | ~11 000 | 1 persistent write + cooldown check |
| `pause` / `unpause` | — | ~5 000 | ~5 500 | Instance storage write |
| `blacklist_clip` | — | ~7 000 | ~7 500 | 1 persistent write |
| `set_platform_fee` | — | ~5 000 | ~5 500 | Instance storage write |
| `request_withdraw_asset` | — | ~6 000 | ~6 500 | Instance storage write with timelock |
| `withdraw_asset` | — | ~20 000 | ~22 000 | Token transfer + storage remove |

---

## Testnet vs Mainnet differences

| Factor | Testnet | Mainnet |
|---|---|---|
| Base inclusion fee | 100 stroops | 100 stroops |
| CPU instruction multiplier | 1× | ~1.1× (network congestion) |
| Memory byte fee | same | same |
| Ledger-entry write fee | same | same |

Mainnet figures are typically **5–10 % higher** due to higher median inclusion
fees bid by other transactions during peak periods.

---

## Optimization history

| Date | Change | Impact |
|---|---|---|
| 2024-Q1 | Replaced linear token scan with `OwnerTokenIndex` | `get_user_tokens`: O(n) → O(limit) |
| 2024-Q1 | Added `TokenIndex` global enumeration | `token_by_index`: O(n) → O(1) |
| 2024-Q2 | Reduced `burn` from 4 persistent removes to 2 | ~8 000 stroop saving |
| 2025-Q2 | `batch_mint` gas is now tracked per-token | Better profiling |

---

## How to update this file

After any optimization, run the contract on Testnet and record the new values:

```bash
./deploy-testnet.sh
stellar contract invoke --id <CONTRACT_ID> -- average_gas_mint
stellar contract invoke --id <CONTRACT_ID> -- average_gas_transfer
```

Then update the table above and add a row to the *Optimization history* section.
