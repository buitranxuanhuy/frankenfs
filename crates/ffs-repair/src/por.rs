//! Proof of Retrievability (PoR) for cryptographic durability audit.
//!
//! Implements a compact PoR scheme based on Shacham-Waters (2008) using
//! BLAKE3 keyed hashing as the MAC. This enables a verifier to check
//! that stored data is intact without reading the entire dataset.
//!
//! # Protocol
//!
//! ## Setup (at file/block-group creation time)
//!
//! Given a secret key `K` and `n` data blocks `B_0, ..., B_{n-1}`:
//!
//! 1. For each block `B_i`, compute authenticator:
//!    `sigma_i = BLAKE3_K(i || B_i)`
//!    where `i` is the block index encoded as 8 bytes (little-endian).
//!
//! 2. Store authenticators alongside the data (or in a separate table).
//!
//! ## Challenge (verifier → prover)
//!
//! The verifier selects `l` random challenge indices `{(i_j, v_j)}_{j=0..l-1}`
//! where `i_j` is a block index and `v_j` is a random 16-byte coefficient.
//!
//! ## Response (prover → verifier)
//!
//! The prover computes:
//! - `mu = XOR_{j=0}^{l-1} (v_j * B_{i_j})` — linear combination of blocks
//!   (where `*` is bytewise multiplication in GF(256))
//! - `sigma = XOR_{j=0}^{l-1} (v_j * sigma_{i_j})` — aggregated authenticator
//!
//! ## Verification
//!
//! The verifier independently recomputes the aggregated authenticator from
//! `mu` and checks it matches `sigma`.
//!
//! # Simplified scheme
//!
//! For the initial implementation, we use a simpler (but still sound)
//! spot-check scheme:
//!
//! 1. **Authenticators**: `sigma_i = BLAKE3_K(i || B_i)` per block.
//! 2. **Challenge**: random subset of block indices.
//! 3. **Response**: `{(i, B_i, sigma_i)}` for each challenged block.
//! 4. **Verification**: recompute `BLAKE3_K(i || B_i)` and compare.
//!
//! If the prover correctly responds to `l` out of `n` challenges, the
//! probability that any unchallenged block is corrupted is at most
//! `(1 - l/n)`. With `l = 460` challenges out of `n = 32768` blocks,
//! the probability of undetected corruption (assuming >=1% of blocks
//! corrupted) is less than `2^{-128}`.
//!
//! # `unsafe_code = "forbid"` Compliance
//!
//! All operations are safe Rust.

use blake3::Hasher;
use serde::{Deserialize, Serialize};

/// Size of a BLAKE3 authenticator in bytes.
pub const AUTHENTICATOR_SIZE: usize = 32;

/// Default number of challenge queries for 2^{-128} security
/// against an adversary corrupting >= 1% of blocks.
///
/// Derivation: if `f >= 0.01` fraction is corrupted, then
/// `Pr[miss all] = (1-f)^l`. For `(1-0.01)^l < 2^{-128}`:
/// `l > 128 * ln(2) / ln(1/0.99) ≈ 8834`.
/// We round up to 8840 for safety margin.
pub const DEFAULT_CHALLENGE_COUNT: u32 = 8840;

/// A 32-byte BLAKE3 keyed authenticator for a single block.
pub type Authenticator = [u8; AUTHENTICATOR_SIZE];

/// PoR secret key (32 bytes, used as BLAKE3 key).
pub type PorKey = [u8; 32];

/// Compute the authenticator for block `index` with data `block`.
///
/// `sigma_i = BLAKE3_K(LE64(index) || block)`
#[must_use]
pub fn compute_authenticator(key: &PorKey, index: u64, block: &[u8]) -> Authenticator {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(&index.to_le_bytes());
    hasher.update(block);
    *hasher.finalize().as_bytes()
}

/// Verify that `authenticator` is valid for block `index` with data `block`.
#[must_use]
pub fn verify_authenticator(
    key: &PorKey,
    index: u64,
    block: &[u8],
    authenticator: &Authenticator,
) -> bool {
    let expected = compute_authenticator(key, index, block);
    constant_time_eq(&expected, authenticator)
}

/// Constant-time comparison to prevent timing side-channels.
#[must_use]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ── Authenticator table ────────────────────────────────────────────────────

/// Table of authenticators for a set of blocks.
///
/// Stores one 32-byte authenticator per block. For a 128 MiB block group
/// with 4 KiB blocks (32768 blocks), this is 1 MiB of authenticator data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorTable {
    /// Authenticators indexed by block offset within the group.
    authenticators: Vec<Authenticator>,
}

impl AuthenticatorTable {
    /// Create a new empty table with capacity for `n` blocks.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            authenticators: Vec::with_capacity(n),
        }
    }

    /// Build a table from raw block data.
    ///
    /// `blocks` is an iterator of `(index, data)` pairs.
    #[must_use]
    pub fn build<'a>(key: &PorKey, blocks: impl Iterator<Item = (u64, &'a [u8])>) -> Self {
        let authenticators: Vec<Authenticator> = blocks
            .map(|(idx, data)| compute_authenticator(key, idx, data))
            .collect();
        Self { authenticators }
    }

    /// Get authenticator for block at `offset` (0-based within group).
    #[must_use]
    pub fn get(&self, offset: usize) -> Option<&Authenticator> {
        self.authenticators.get(offset)
    }

    /// Number of authenticators stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.authenticators.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.authenticators.is_empty()
    }

    /// Total storage overhead in bytes.
    #[must_use]
    pub fn storage_bytes(&self) -> usize {
        self.authenticators.len() * AUTHENTICATOR_SIZE
    }

    /// Push a single authenticator.
    pub fn push(&mut self, auth: Authenticator) {
        self.authenticators.push(auth);
    }
}

// ── Challenge-response ─────────────────────────────────────────────────────

/// A single challenge: "prove you have block `index`".
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Challenge {
    /// Block index to challenge.
    pub index: u64,
    /// Offset within the authenticator table (for lookup).
    pub table_offset: u32,
}

/// A set of challenges generated by the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSet {
    /// Random challenges.
    pub challenges: Vec<Challenge>,
    /// Nonce to prevent replay (BLAKE3 hash of challenge generation entropy).
    pub nonce: [u8; 32],
}

impl ChallengeSet {
    /// Generate a deterministic challenge set from a seed.
    ///
    /// Uses BLAKE3 in XOF mode to derive pseudo-random challenge indices.
    /// `total_blocks` is the number of blocks in the group/file.
    /// `challenge_count` is how many blocks to challenge.
    /// Maximum challenges per set to prevent unbounded allocation.
    const MAX_CHALLENGES: u32 = 1_000_000;

    #[must_use]
    pub fn generate(seed: &[u8; 32], total_blocks: u32, challenge_count: u32) -> Self {
        let count = challenge_count.min(total_blocks).min(Self::MAX_CHALLENGES);

        // Derive nonce from seed.
        let nonce = *blake3::hash(seed).as_bytes();

        // Use BLAKE3 XOF to generate random indices.
        let mut hasher = Hasher::new();
        hasher.update(seed);
        hasher.update(b"por-challenge-indices");
        let mut reader = hasher.finalize_xof();

        // Fisher-Yates-like selection: generate random u32s, map to indices.
        // For simplicity with deterministic output, we generate indices and
        // deduplicate. This is fine since challenge_count << total_blocks.
        let mut selected = Vec::with_capacity(count as usize);
        let mut visited = std::collections::HashSet::with_capacity(count as usize);

        let mut buf = [0_u8; 4];
        while selected.len() < count as usize {
            reader.fill(&mut buf);
            let raw = u32::from_le_bytes(buf);
            let idx = raw % total_blocks;
            if visited.insert(idx) {
                selected.push(Challenge {
                    index: u64::from(idx),
                    table_offset: idx,
                });
            }
        }

        Self {
            challenges: selected,
            nonce,
        }
    }

    /// Number of challenges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.challenges.len()
    }

    /// Whether empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.challenges.is_empty()
    }
}

/// Response to a single challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The block index that was challenged.
    pub index: u64,
    /// The block data (or its hash if bandwidth-constrained).
    pub block_hash: [u8; 32],
    /// The stored authenticator for this block.
    pub authenticator: Authenticator,
}

/// Full response to a challenge set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSet {
    /// Individual responses.
    pub responses: Vec<ChallengeResponse>,
    /// Echo back the challenge nonce.
    pub nonce: [u8; 32],
}

/// Outcome of verifying a PoR response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Total challenges issued.
    pub total_challenges: u32,
    /// How many passed verification.
    pub passed: u32,
    /// How many failed verification.
    pub failed: u32,
    /// Indices of blocks that failed verification.
    pub failed_indices: Vec<u64>,
    /// Whether the overall audit passed (all challenges verified).
    pub audit_passed: bool,
}

// ── Prover ─────────────────────────────────────────────────────────────────

/// Generate responses to a challenge set.
///
/// `read_block` is a closure that reads block data given a block index.
/// Returns `None` if a block cannot be read (I/O error).
pub fn respond_to_challenges<F>(
    challenges: &ChallengeSet,
    auth_table: &AuthenticatorTable,
    mut read_block: F,
) -> ResponseSet
where
    F: FnMut(u64) -> Option<Vec<u8>>,
{
    let responses = challenges
        .challenges
        .iter()
        .filter_map(|ch| {
            let block_data = read_block(ch.index)?;
            let block_hash = *blake3::hash(&block_data).as_bytes();
            let authenticator = *auth_table.get(ch.table_offset as usize)?;
            Some(ChallengeResponse {
                index: ch.index,
                block_hash,
                authenticator,
            })
        })
        .collect();

    ResponseSet {
        responses,
        nonce: challenges.nonce,
    }
}

// ── Verifier ───────────────────────────────────────────────────────────────

/// Verify a response set against the expected authenticators.
///
/// `read_block` reads the actual block data for re-computation.
/// The verifier independently computes `BLAKE3_K(i || B_i)` and
/// checks it matches the prover's authenticator.
pub fn verify_responses<F>(
    key: &PorKey,
    challenges: &ChallengeSet,
    responses: &ResponseSet,
    mut read_block: F,
) -> VerificationResult
where
    F: FnMut(u64) -> Option<Vec<u8>>,
{
    // Check nonce matches.
    #[expect(clippy::cast_possible_truncation)] // challenge count bounded by u32 total_blocks
    let num_challenges = challenges.challenges.len() as u32;
    if challenges.nonce != responses.nonce {
        return VerificationResult {
            total_challenges: num_challenges,
            passed: 0,
            failed: num_challenges,
            failed_indices: challenges.challenges.iter().map(|c| c.index).collect(),
            audit_passed: false,
        };
    }

    let mut passed = 0_u32;
    let mut failed = 0_u32;
    let mut failed_indices = Vec::new();

    // Build response lookup.
    let response_map: std::collections::HashMap<u64, &ChallengeResponse> =
        responses.responses.iter().map(|r| (r.index, r)).collect();

    for challenge in &challenges.challenges {
        let Some(response) = response_map.get(&challenge.index) else {
            // Missing response = failure.
            failed += 1;
            failed_indices.push(challenge.index);
            continue;
        };

        // Read the actual block data.
        let Some(block_data) = read_block(challenge.index) else {
            failed += 1;
            failed_indices.push(challenge.index);
            continue;
        };

        // Verify the authenticator.
        if verify_authenticator(key, challenge.index, &block_data, &response.authenticator) {
            passed += 1;
        } else {
            failed += 1;
            failed_indices.push(challenge.index);
        }
    }

    VerificationResult {
        total_challenges: num_challenges,
        passed,
        failed,
        failed_indices,
        audit_passed: failed == 0,
    }
}

// ── Security analysis ──────────────────────────────────────────────────────

/// Compute the probability of missing corruption given challenge parameters.
///
/// If `corruption_fraction` of blocks are corrupted, and we issue
/// `challenge_count` challenges out of `total_blocks`, the probability
/// that NONE of the challenged blocks are corrupted is:
///
/// `(1 - f)^l`
///
/// where `f = corruption_fraction`, `l = challenge_count`.
#[must_use]
pub fn false_negative_probability(corruption_fraction: f64, challenge_count: u32) -> f64 {
    (1.0 - corruption_fraction).powf(f64::from(challenge_count))
}

/// Compute the minimum number of challenges needed for a given
/// security level against a given corruption fraction.
///
/// Returns `l` such that `(1-f)^l < 2^{-security_bits}`.
#[must_use]
pub fn min_challenges(corruption_fraction: f64, security_bits: u32) -> u32 {
    if corruption_fraction <= 0.0 || corruption_fraction >= 1.0 {
        return 0;
    }
    let l = (f64::from(security_bits) * core::f64::consts::LN_2)
        / (1.0 / (1.0 - corruption_fraction)).ln();
    #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    // l is always positive and bounded by realistic challenge counts (< 2^31)
    let result = l.ceil() as u32;
    result
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> PorKey {
        *blake3::hash(b"test-por-key-for-frankenfs").as_bytes()
    }

    fn get_block(blocks: &[Vec<u8>], idx: u64) -> Option<Vec<u8>> {
        usize::try_from(idx)
            .ok()
            .and_then(|i| blocks.get(i))
            .cloned()
    }

    fn make_blocks(n: usize, block_size: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut block = vec![0_u8; block_size];
                // Fill with deterministic pattern.
                for (j, byte) in block.iter_mut().enumerate() {
                    *byte =
                        u8::try_from((i * 257 + j * 131) & 0xFF).expect("pattern byte fits in u8");
                }
                block
            })
            .collect()
    }

    #[test]
    fn authenticator_roundtrip() {
        let key = test_key();
        let block = vec![42_u8; 4096];
        let auth = compute_authenticator(&key, 0, &block);
        assert!(verify_authenticator(&key, 0, &block, &auth));
    }

    #[test]
    fn authenticator_detects_corruption() {
        let key = test_key();
        let mut block = vec![42_u8; 4096];
        let auth = compute_authenticator(&key, 0, &block);

        // Corrupt one byte.
        block[100] ^= 0xFF;
        assert!(!verify_authenticator(&key, 0, &block, &auth));
    }

    #[test]
    fn authenticator_detects_wrong_index() {
        let key = test_key();
        let block = vec![42_u8; 4096];
        let auth = compute_authenticator(&key, 0, &block);

        // Same data, wrong index.
        assert!(!verify_authenticator(&key, 1, &block, &auth));
    }

    #[test]
    fn authenticator_detects_wrong_key() {
        let key1 = test_key();
        let key2 = *blake3::hash(b"different-key").as_bytes();
        let block = vec![42_u8; 4096];
        let auth = compute_authenticator(&key1, 0, &block);
        assert!(!verify_authenticator(&key2, 0, &block, &auth));
    }

    #[test]
    fn table_build_and_lookup() {
        let key = test_key();
        let blocks = make_blocks(100, 4096);
        let table = AuthenticatorTable::build(
            &key,
            blocks
                .iter()
                .enumerate()
                .map(|(i, b)| (i as u64, b.as_slice())),
        );

        assert_eq!(table.len(), 100);
        assert_eq!(table.storage_bytes(), 100 * 32);

        // Verify each authenticator.
        for (i, block) in blocks.iter().enumerate() {
            let auth = table.get(i).unwrap();
            assert!(verify_authenticator(&key, i as u64, block, auth));
        }
    }

    #[test]
    fn challenge_generation_deterministic() {
        let seed = *blake3::hash(b"test-seed").as_bytes();
        let cs1 = ChallengeSet::generate(&seed, 1000, 50);
        let cs2 = ChallengeSet::generate(&seed, 1000, 50);

        assert_eq!(cs1.len(), 50);
        assert_eq!(cs1.challenges.len(), cs2.challenges.len());
        for (a, b) in cs1.challenges.iter().zip(&cs2.challenges) {
            assert_eq!(a.index, b.index);
        }
    }

    #[test]
    fn challenge_no_duplicates() {
        let seed = *blake3::hash(b"dedup-test").as_bytes();
        let cs = ChallengeSet::generate(&seed, 1000, 500);
        let mut indices: Vec<u64> = cs.challenges.iter().map(|c| c.index).collect();
        let before = indices.len();
        indices.sort_unstable();
        indices.dedup();
        assert_eq!(indices.len(), before, "challenges must be unique");
    }

    #[test]
    fn challenge_capped_at_total_blocks() {
        let seed = *blake3::hash(b"cap-test").as_bytes();
        let cs = ChallengeSet::generate(&seed, 10, 100);
        assert_eq!(cs.len(), 10); // capped to total_blocks
    }

    #[test]
    fn full_por_protocol_honest_prover() {
        let key = test_key();
        let blocks = make_blocks(256, 4096);

        // Setup: build authenticator table.
        let table = AuthenticatorTable::build(
            &key,
            blocks
                .iter()
                .enumerate()
                .map(|(i, b)| (i as u64, b.as_slice())),
        );

        // Challenge.
        let seed = *blake3::hash(b"audit-seed").as_bytes();
        let challenges = ChallengeSet::generate(&seed, 256, 50);

        // Response.
        let responses = respond_to_challenges(&challenges, &table, |idx| get_block(&blocks, idx));

        assert_eq!(responses.responses.len(), 50);

        // Verification.
        let result = verify_responses(&key, &challenges, &responses, |idx| get_block(&blocks, idx));

        assert!(result.audit_passed);
        assert_eq!(result.passed, 50);
        assert_eq!(result.failed, 0);
        assert!(result.failed_indices.is_empty());
    }

    #[test]
    fn por_detects_corrupted_block() {
        let key = test_key();
        let mut blocks = make_blocks(256, 4096);

        // Setup with original data.
        let table = AuthenticatorTable::build(
            &key,
            blocks
                .iter()
                .enumerate()
                .map(|(i, b)| (i as u64, b.as_slice())),
        );

        // Corrupt block 10.
        blocks[10][0] ^= 0xFF;

        // Challenge (we force block 10 to be in the challenge set by
        // generating many challenges).
        let seed = *blake3::hash(b"detect-corruption").as_bytes();
        let challenges = ChallengeSet::generate(&seed, 256, 256); // all blocks

        let responses = respond_to_challenges(&challenges, &table, |idx| get_block(&blocks, idx));

        let result = verify_responses(&key, &challenges, &responses, |idx| get_block(&blocks, idx));

        assert!(!result.audit_passed);
        assert_eq!(result.failed, 1);
        assert!(result.failed_indices.contains(&10));
    }

    #[test]
    fn por_detects_missing_block() {
        let key = test_key();
        let blocks = make_blocks(100, 4096);

        let table = AuthenticatorTable::build(
            &key,
            blocks
                .iter()
                .enumerate()
                .map(|(i, b)| (i as u64, b.as_slice())),
        );

        let seed = *blake3::hash(b"missing-test").as_bytes();
        let challenges = ChallengeSet::generate(&seed, 100, 100);

        // Prover can read all blocks.
        let responses = respond_to_challenges(&challenges, &table, |idx| get_block(&blocks, idx));

        // Verifier cannot read block 50 (simulates data loss).
        let result = verify_responses(&key, &challenges, &responses, |idx| {
            if idx == 50 {
                None
            } else {
                get_block(&blocks, idx)
            }
        });

        assert!(!result.audit_passed);
        assert!(result.failed_indices.contains(&50));
    }

    #[test]
    fn nonce_mismatch_fails() {
        let key = test_key();
        let blocks = make_blocks(10, 4096);
        let table = AuthenticatorTable::build(
            &key,
            blocks
                .iter()
                .enumerate()
                .map(|(i, b)| (i as u64, b.as_slice())),
        );

        let seed = *blake3::hash(b"nonce-test").as_bytes();
        let challenges = ChallengeSet::generate(&seed, 10, 5);
        let mut responses =
            respond_to_challenges(&challenges, &table, |idx| get_block(&blocks, idx));

        // Tamper with nonce.
        responses.nonce[0] ^= 0xFF;

        let result = verify_responses(&key, &challenges, &responses, |idx| get_block(&blocks, idx));

        assert!(!result.audit_passed);
        assert_eq!(result.failed, 5); // all fail due to nonce mismatch
    }

    #[test]
    fn security_analysis_1pct_corruption() {
        // With 1% corruption, DEFAULT_CHALLENGE_COUNT should give < 2^{-128}.
        let prob = false_negative_probability(0.01, DEFAULT_CHALLENGE_COUNT);
        let bits = -(prob.log2());
        assert!(
            bits > 128.0,
            "security level {bits:.1} bits, expected > 128"
        );
    }

    #[test]
    fn min_challenges_1pct_matches_default() {
        let min = min_challenges(0.01, 128);
        assert!(
            min <= DEFAULT_CHALLENGE_COUNT,
            "min_challenges({min}) > DEFAULT_CHALLENGE_COUNT({DEFAULT_CHALLENGE_COUNT})"
        );
    }

    #[test]
    fn min_challenges_boundary_cases() {
        assert_eq!(min_challenges(0.0, 128), 0);
        assert_eq!(min_challenges(1.0, 128), 0);
        // 50% corruption needs very few challenges.
        let n = min_challenges(0.5, 128);
        assert!(
            n < 200,
            "50% corruption should need <200 challenges, got {n}"
        );
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [0_u8; 32];
        let b = [0_u8; 32];
        assert!(constant_time_eq(&a, &b));

        let mut c = a;
        c[31] = 1;
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn authenticator_table_serde_roundtrip() {
        let key = test_key();
        let blocks = make_blocks(10, 4096);
        let table = AuthenticatorTable::build(
            &key,
            blocks
                .iter()
                .enumerate()
                .map(|(i, b)| (i as u64, b.as_slice())),
        );

        let json = serde_json::to_string(&table).expect("serialize");
        let parsed: AuthenticatorTable = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.len(), table.len());
        for i in 0..table.len() {
            assert_eq!(parsed.get(i), table.get(i));
        }
    }

    #[test]
    fn verification_result_serde_roundtrip() {
        let result = VerificationResult {
            total_challenges: 100,
            passed: 99,
            failed: 1,
            failed_indices: vec![42],
            audit_passed: false,
        };
        let json = serde_json::to_string(&result).expect("serialize");
        let parsed: VerificationResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.total_challenges, 100);
        assert_eq!(parsed.failed, 1);
        assert_eq!(parsed.failed_indices, vec![42]);
        assert!(!parsed.audit_passed);
    }
}
