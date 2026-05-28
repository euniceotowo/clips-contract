//! Safe arithmetic helpers for royalty calculations.
//!
//! # Overflow protection
//!
//! Royalty amounts are computed as:
//!
//! ```text
//! royalty_amount = (sale_price × basis_points + 5_000) / 10_000
//! ```
//!
//! `sale_price` is an `i128`. The multiplication `sale_price × basis_points`
//! can overflow when `sale_price` is very large. This module guards against
//! that by:
//!
//! 1. Rejecting any `sale_price > i128::MAX / 10_000` before multiplying.
//! 2. Using `checked_mul` / `checked_add` so any residual overflow returns
//!    `Err` rather than wrapping silently.
//!
//! # Safe price limits
//!
//! ## Maximum safe sale price
//!
//! The maximum safe sale price is `i128::MAX / 10_000 ≈ 1.7 × 10³⁴` stroops.
//!
//! In practical terms:
//! - **In stroops**: ~170,000,000,000,000,000,000,000,000,000,000,000 stroops
//! - **In XLM**: ~170,000,000,000,000,000,000,000,000,000 XLM (1 XLM = 10⁷ stroops)
//! - **In USD** (at $1/XLM): ~1.7 × 10²⁹ USD
//!
//! This limit is astronomically larger than any realistic Stellar transaction value,
//! effectively making overflow impossible in practice while still providing
//! mathematical correctness guarantees.
//!
//! ## Basis points range
//!
//! - Valid range: 0–10,000 basis points (0%–100%)
//! - 1 basis point = 0.01%
//! - 10,000 basis points = 100%
//!
//! ## Rounding behavior
//!
//! The formula includes a +5,000 offset for rounding:
//!
//! ```text
//! royalty_amount = (sale_price × basis_points + 5_000) / 10_000
//! ```
//!
//! This provides banker's rounding (round half up) to ensure fair royalty
//! distribution for small amounts.
//!
//! # Error handling
//!
//! - [`Error::InvalidSalePrice`] — Returned when `sale_price ≤ 0`
//! - [`Error::RoyaltyOverflow`] — Returned when calculation would overflow

use crate::Error;

/// Compute `(sale_price × basis_points + 5_000) / 10_000` with overflow protection.
///
/// # Arguments
/// * `sale_price`   — Sale price in the asset's smallest unit. Must be > 0.
/// * `basis_points` — Royalty rate in basis points (1 bp = 0.01 %). Range: 0–10 000.
///
/// # Errors
/// * [`Error::InvalidSalePrice`] — `sale_price` ≤ 0.
/// * [`Error::RoyaltyOverflow`]  — `sale_price > i128::MAX / 10_000` or intermediate overflow.
pub fn safe_royalty_amount(sale_price: i128, basis_points: u32) -> Result<i128, Error> {
    if sale_price <= 0 {
        return Err(Error::InvalidSalePrice);
    }
    // Pre-check: sale_price × 10_000 must fit in i128.
    if sale_price > i128::MAX / 10_000 {
        return Err(Error::RoyaltyOverflow);
    }
    let numerator = sale_price
        .checked_mul(basis_points as i128)
        .ok_or(Error::RoyaltyOverflow)?
        .checked_add(5_000)
        .ok_or(Error::RoyaltyOverflow)?;
    Ok(numerator / 10_000)
}
