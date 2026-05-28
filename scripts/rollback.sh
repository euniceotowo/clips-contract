#!/usr/bin/env bash
# =============================================================================
# rollback.sh — Revert a contract upgrade using the artefact from upgrade.sh
#
# Usage:
#   # Source the rollback artefact first, then run this script:
#   source .soroban/rollback-<network>.env
#   ./scripts/rollback.sh
#
#   # Or pass the network explicitly (reads artefact automatically):
#   ./scripts/rollback.sh testnet
#
# What this script does:
#   1. Reads rollback artefact (.soroban/rollback-<network>.env)
#   2. Verifies the previous WASM hash is known
#   3. Calls upgrade() with the OLD wasm hash — reverts the code
#   4. Does NOT call migrate() — the old code's storage layout is already in place
#   5. Post-flight: verifies total_supply is unchanged
#
# Limitations:
#   - Storage migrations applied by migrate() are NOT automatically reversed.
#     If migrate() wrote new keys, those keys will remain (but the old code
#     will simply ignore them — they are harmless extra entries).
#   - If migrate() deleted or transformed existing keys, manual intervention
#     may be required. Review the migration steps in lib.rs before rolling back.
# =============================================================================

set -euo pipefail

NETWORK="${1:-${ROLLBACK_NETWORK:-testnet}}"
SOROBAN_DIR=".soroban"
ROLLBACK_FILE="$SOROBAN_DIR/rollback-$NETWORK.env"

log()  { echo "[rollback] $*"; }
die()  { echo "[rollback] ✗  $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Load rollback artefact
# ---------------------------------------------------------------------------
if [[ -f "$ROLLBACK_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$ROLLBACK_FILE"
    log "Loaded artefact: $ROLLBACK_FILE"
fi

CONTRACT_ID="${ROLLBACK_CONTRACT_ID:-${CONTRACT_ID:-}}"
ACCOUNT="${ROLLBACK_ACCOUNT:-${SOROBAN_ACCOUNT:-default}}"
PRE_WASM_HASH="${ROLLBACK_PRE_WASM_HASH:-}"
PRE_SUPPLY="${ROLLBACK_PRE_SUPPLY:-unknown}"

[[ -n "$CONTRACT_ID" ]]   || die "CONTRACT_ID not set. Source the rollback artefact first."
[[ -n "$PRE_WASM_HASH" ]] || die "ROLLBACK_PRE_WASM_HASH not set. Cannot roll back without the previous WASM hash."

log "Contract      : $CONTRACT_ID"
log "Network       : $NETWORK"
log "Account       : $ACCOUNT"
log "Target hash   : $PRE_WASM_HASH"
log "Expected supply: $PRE_SUPPLY"

# ---------------------------------------------------------------------------
# Confirm
# ---------------------------------------------------------------------------
read -r -p "[rollback] This will revert the live contract. Type 'yes' to continue: " CONFIRM
[[ "$CONFIRM" == "yes" ]] || { log "Aborted."; exit 0; }

# ---------------------------------------------------------------------------
# Step 1 — Snapshot current state
# ---------------------------------------------------------------------------
log ""
log "=== Step 1: Pre-rollback snapshot ==="
ADMIN_ADDRESS=$(soroban config identity address "$ACCOUNT" 2>/dev/null || echo "")
CUR_SUPPLY=$(soroban contract invoke \
    --id "$CONTRACT_ID" --source "$ACCOUNT" --network "$NETWORK" \
    -- total_supply 2>/dev/null || echo "unknown")
log "  current total_supply: $CUR_SUPPLY"

# ---------------------------------------------------------------------------
# Step 2 — Call upgrade() with the old WASM hash
# ---------------------------------------------------------------------------
log ""
log "=== Step 2: Revert code via upgrade() ==="
soroban contract invoke \
    --id "$CONTRACT_ID" \
    --source "$ACCOUNT" \
    --network "$NETWORK" \
    -- upgrade \
    --admin "$ADMIN_ADDRESS" \
    --new_wasm_hash "$PRE_WASM_HASH"
log "  upgrade() called with previous WASM hash."

# ---------------------------------------------------------------------------
# Step 3 — Post-rollback verification
# ---------------------------------------------------------------------------
log ""
log "=== Step 3: Post-rollback verification ==="
POST_SUPPLY=$(soroban contract invoke \
    --id "$CONTRACT_ID" --source "$ACCOUNT" --network "$NETWORK" \
    -- total_supply 2>/dev/null || echo "unknown")
log "  total_supply: $CUR_SUPPLY → $POST_SUPPLY"

if [[ "$POST_SUPPLY" != "$CUR_SUPPLY" ]]; then
    echo "[rollback] ⚠️  total_supply changed during rollback ($CUR_SUPPLY → $POST_SUPPLY). Investigate." >&2
fi

log ""
log "=== Rollback complete ==="
log "  The contract is now running the previous WASM."
log "  Note: any storage keys written by migrate() remain but are ignored by the old code."
log "  Review the migration steps in clips_nft/src/lib.rs if you need to clean them up manually."
