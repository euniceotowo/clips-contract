#!/usr/bin/env bash
# =============================================================================
# upgrade.sh — Safe contract upgrade with pre-flight checks and rollback plan
#
# Usage:
#   ./scripts/upgrade.sh [testnet|mainnet] [CONTRACT_ID]
#
# Environment variables (override defaults):
#   SOROBAN_ACCOUNT   — Stellar account alias (default: "default")
#   CONTRACT_ID       — Contract address (falls back to .soroban/contract-id-<network>)
#   DRY_RUN=1         — Print what would happen without executing any on-chain calls
#
# What this script does:
#   1. Pre-flight: snapshot current state (version, total_supply, admin)
#   2. Build the new WASM
#   3. Install the new WASM on-chain and capture its hash
#   4. Call upgrade() — swaps the code, storage is untouched
#   5. Call migrate() — runs data-migration logic, bumps ContractVersion
#   6. Post-flight: verify state is consistent (supply unchanged, version bumped)
#   7. Write a rollback artefact (.soroban/rollback-<network>.env) with the
#      previous WASM hash so you can revert if needed
#
# Rollback:
#   source .soroban/rollback-<network>.env
#   ./scripts/rollback.sh [testnet|mainnet]
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
NETWORK="${1:-${NETWORK:-testnet}}"
CONTRACT_ID="${2:-${CONTRACT_ID:-}}"
ACCOUNT="${SOROBAN_ACCOUNT:-default}"
DRY_RUN="${DRY_RUN:-0}"
WASM_PATH="target/wasm32-unknown-unknown/release/clips_nft.wasm"
SOROBAN_DIR=".soroban"
ROLLBACK_FILE="$SOROBAN_DIR/rollback-$NETWORK.env"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { echo "[upgrade] $*"; }
warn() { echo "[upgrade] ⚠️  $*" >&2; }
die()  { echo "[upgrade] ✗  $*" >&2; exit 1; }

run() {
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[DRY-RUN] $*"
    else
        "$@"
    fi
}

soroban_invoke() {
    # Wrapper so DRY_RUN suppresses on-chain writes but still runs reads.
    local readonly_flag="${READONLY:-0}"
    if [[ "$DRY_RUN" == "1" && "$readonly_flag" != "1" ]]; then
        echo "[DRY-RUN] soroban contract invoke --id $CONTRACT_ID --source $ACCOUNT --network $NETWORK -- $*"
        return 0
    fi
    soroban contract invoke \
        --id "$CONTRACT_ID" \
        --source "$ACCOUNT" \
        --network "$NETWORK" \
        -- "$@"
}

# ---------------------------------------------------------------------------
# Resolve contract ID
# ---------------------------------------------------------------------------
if [[ -z "$CONTRACT_ID" ]]; then
    ID_FILE="$SOROBAN_DIR/contract-id-$NETWORK"
    [[ -f "$ID_FILE" ]] || die "No CONTRACT_ID provided and $ID_FILE not found. Deploy first."
    CONTRACT_ID="$(cat "$ID_FILE")"
fi
log "Contract : $CONTRACT_ID"
log "Network  : $NETWORK"
log "Account  : $ACCOUNT"
[[ "$DRY_RUN" == "1" ]] && log "Mode     : DRY RUN (no on-chain writes)"

# ---------------------------------------------------------------------------
# Step 1 — Pre-flight snapshot
# ---------------------------------------------------------------------------
log ""
log "=== Step 1: Pre-flight snapshot ==="

READONLY=1
PRE_VERSION=$(soroban_invoke contract_version 2>/dev/null || echo "0")
PRE_SUPPLY=$(soroban_invoke total_supply 2>/dev/null || echo "0")
PRE_ADMIN=$(soroban_invoke contract_info 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['owner'])" 2>/dev/null || echo "unknown")
unset READONLY

log "  contract_version : $PRE_VERSION"
log "  total_supply     : $PRE_SUPPLY"
log "  admin            : $PRE_ADMIN"

# Capture the current WASM hash for rollback
PRE_WASM_HASH=$(soroban contract info \
    --id "$CONTRACT_ID" \
    --network "$NETWORK" \
    2>/dev/null | grep -i "wasm_hash" | awk '{print $2}' || echo "")

if [[ -z "$PRE_WASM_HASH" ]]; then
    warn "Could not read current WASM hash — rollback artefact will be incomplete."
fi

# ---------------------------------------------------------------------------
# Step 2 — Build
# ---------------------------------------------------------------------------
log ""
log "=== Step 2: Build new WASM ==="
run cargo build --target wasm32-unknown-unknown --release -p clips_nft
[[ -f "$WASM_PATH" ]] || die "WASM not found at $WASM_PATH after build."
log "  Built: $WASM_PATH"

# ---------------------------------------------------------------------------
# Step 3 — Install WASM on-chain
# ---------------------------------------------------------------------------
log ""
log "=== Step 3: Install WASM on-chain ==="
if [[ "$DRY_RUN" == "1" ]]; then
    NEW_WASM_HASH="<dry-run-hash>"
    log "  [DRY-RUN] soroban contract install ..."
else
    NEW_WASM_HASH=$(soroban contract install \
        --network "$NETWORK" \
        --source "$ACCOUNT" \
        --wasm "$WASM_PATH")
fi
log "  New WASM hash: $NEW_WASM_HASH"

# ---------------------------------------------------------------------------
# Step 4 — Write rollback artefact BEFORE touching the live contract
# ---------------------------------------------------------------------------
log ""
log "=== Step 4: Write rollback artefact ==="
mkdir -p "$SOROBAN_DIR"
cat > "$ROLLBACK_FILE" <<EOF
# Rollback artefact generated by upgrade.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
export ROLLBACK_NETWORK="$NETWORK"
export ROLLBACK_CONTRACT_ID="$CONTRACT_ID"
export ROLLBACK_ACCOUNT="$ACCOUNT"
export ROLLBACK_PRE_WASM_HASH="$PRE_WASM_HASH"
export ROLLBACK_PRE_VERSION="$PRE_VERSION"
export ROLLBACK_PRE_SUPPLY="$PRE_SUPPLY"
EOF
log "  Saved: $ROLLBACK_FILE"

# ---------------------------------------------------------------------------
# Step 5 — Call upgrade()
# ---------------------------------------------------------------------------
log ""
log "=== Step 5: Call upgrade() ==="
ADMIN_ADDRESS=$(soroban config identity address "$ACCOUNT" 2>/dev/null || echo "$PRE_ADMIN")
run soroban_invoke upgrade \
    --admin "$ADMIN_ADDRESS" \
    --new_wasm_hash "$NEW_WASM_HASH"
log "  upgrade() succeeded — code swapped, storage intact."

# ---------------------------------------------------------------------------
# Step 6 — Call migrate()
# ---------------------------------------------------------------------------
log ""
log "=== Step 6: Call migrate() ==="
run soroban_invoke migrate \
    --admin "$ADMIN_ADDRESS"
log "  migrate() succeeded — data migration complete."

# ---------------------------------------------------------------------------
# Step 7 — Post-flight verification
# ---------------------------------------------------------------------------
log ""
log "=== Step 7: Post-flight verification ==="

if [[ "$DRY_RUN" != "1" ]]; then
    READONLY=1
    POST_VERSION=$(soroban_invoke contract_version 2>/dev/null || echo "0")
    POST_SUPPLY=$(soroban_invoke total_supply 2>/dev/null || echo "0")
    unset READONLY

    log "  contract_version : $PRE_VERSION → $POST_VERSION"
    log "  total_supply     : $PRE_SUPPLY → $POST_SUPPLY"

    if [[ "$POST_SUPPLY" != "$PRE_SUPPLY" ]]; then
        die "total_supply changed during upgrade ($PRE_SUPPLY → $POST_SUPPLY). Investigate immediately."
    fi

    if [[ "$POST_VERSION" -le "$PRE_VERSION" && "$PRE_VERSION" != "0" ]]; then
        warn "contract_version did not increase ($PRE_VERSION → $POST_VERSION). Check migrate() logic."
    fi

    log "  ✓ Supply preserved. Upgrade complete."
else
    log "  [DRY-RUN] Skipping post-flight checks."
fi

log ""
log "=== Upgrade complete ==="
log "  To roll back: source $ROLLBACK_FILE && ./scripts/rollback.sh"
