//! Automatic corruption recovery pipeline.
//!
//! [`ScrubWithRecovery`] connects the scrub engine ([`Scrubber`]) with the
//! recovery orchestrator ([`GroupRecoveryOrchestrator`]) and the evidence
//! ledger ([`EvidenceLedger`]).  When a scrub pass detects corruption, the
//! pipeline automatically attempts RaptorQ recovery, logs structured evidence
//! for every decision, and optionally refreshes repair symbols after a
//! successful recovery.
//!
//! # Flow
//!
//! ```text
//! scrub range → corrupt blocks → group recovery → evidence → symbol refresh
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use asupersync::{Cx, SystemPressure};
use ffs_block::BlockDevice;
use ffs_error::{FfsError, Result};
use ffs_types::{BlockNumber, GroupNumber};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

use crate::autopilot::{DurabilityAutopilot, OverheadDecision};
use crate::codec::{EncodedGroup, encode_group};
use crate::evidence::{
    CorruptionDetail, EvidenceLedger, EvidenceRecord, PolicyDecisionDetail, RepairDetail,
    SymbolRefreshDetail,
};
use crate::recovery::{
    GroupRecoveryOrchestrator, RecoveryAttemptResult, RecoveryDecoderStats, RecoveryOutcome,
};
use crate::scrub::{BlockValidator, ScrubReport, Scrubber, Severity};
use crate::storage::{RepairGroupLayout, RepairGroupStorage};
use crate::symbol::RepairGroupDescExt;

// ── Per-group configuration ───────────────────────────────────────────────

/// Configuration for one block group's recovery-capable scrub.
#[derive(Debug, Clone, Copy)]
pub struct GroupConfig {
    /// On-image tail layout for this group.
    pub layout: RepairGroupLayout,
    /// First source (data) block in this group.
    pub source_first_block: BlockNumber,
    /// Number of source (data) blocks in this group.
    pub source_block_count: u32,
}

/// Refresh policy for repair symbol regeneration after writes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RefreshPolicy {
    /// Refresh immediately on every write to the group.
    Eager,
    /// Refresh on scrub (or when staleness budget is exceeded).
    Lazy { max_staleness: Duration },
    /// Switch eager/lazy behavior based on corruption posterior.
    Adaptive {
        /// Posterior threshold above which eager refresh is used.
        risk_threshold: f64,
        /// Maximum allowed dirty age before forced refresh.
        max_staleness: Duration,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshMode {
    Recovery,
    EagerWrite,
    LazyScrub,
    AdaptiveEagerWrite,
    AdaptiveLazyScrub,
    StalenessTimeout,
}

impl RefreshMode {
    #[must_use]
    fn as_str(self) -> &'static str {
        match self {
            Self::Recovery => "recovery",
            Self::EagerWrite => "eager_write",
            Self::LazyScrub => "lazy_scrub",
            Self::AdaptiveEagerWrite => "adaptive_eager_write",
            Self::AdaptiveLazyScrub => "adaptive_lazy_scrub",
            Self::StalenessTimeout => "staleness_timeout",
        }
    }
}

#[derive(Debug, Clone)]
struct GroupRefreshState {
    dirty: bool,
    dirty_since: Option<Instant>,
    policy: RefreshPolicy,
    last_refresh: Instant,
}

impl GroupRefreshState {
    #[must_use]
    fn new(policy: RefreshPolicy) -> Self {
        let now = Instant::now();
        Self {
            dirty: false,
            dirty_since: None,
            policy,
            last_refresh: now,
        }
    }
}

// ── Recovery report ───────────────────────────────────────────────────────

/// Outcome for a single block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockOutcome {
    /// Block was clean — no corruption detected.
    Clean,
    /// Block was corrupt and successfully recovered.
    Recovered,
    /// Block was corrupt but recovery failed.
    Unrecoverable,
}

/// Per-group recovery summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecoverySummary {
    /// Block group number.
    pub group: u32,
    /// Number of corrupt blocks detected in this group.
    pub corrupt_count: usize,
    /// Number of blocks successfully recovered.
    pub recovered_count: usize,
    /// Number of blocks that could not be recovered.
    pub unrecoverable_count: usize,
    /// Whether repair symbols were refreshed after recovery.
    pub symbols_refreshed: bool,
    /// Recovery decoder statistics (if recovery was attempted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoder_stats: Option<RecoveryDecoderStats>,
}

/// Aggregated report from a scrub-with-recovery pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    /// Underlying scrub statistics.
    pub blocks_scanned: u64,
    /// Total corrupt blocks detected across all groups.
    pub total_corrupt: usize,
    /// Total blocks successfully recovered.
    pub total_recovered: usize,
    /// Total blocks that could not be recovered.
    pub total_unrecoverable: usize,
    /// Per-block outcomes (only for blocks that had findings).
    pub block_outcomes: BTreeMap<u64, BlockOutcome>,
    /// Per-group recovery summaries.
    pub group_summaries: Vec<GroupRecoverySummary>,
}

impl RecoveryReport {
    /// True if all corrupt blocks were recovered (or none were corrupt).
    #[must_use]
    pub fn is_fully_recovered(&self) -> bool {
        self.total_unrecoverable == 0
    }
}

// ── Daemon scheduler ──────────────────────────────────────────────────────

/// Background scrub daemon configuration.
#[derive(Debug, Clone)]
pub struct ScrubDaemonConfig {
    /// Delay between daemon ticks.
    pub interval: Duration,
    /// Cancellation polling granularity while sleeping.
    pub cancel_check_interval: Duration,
    /// Headroom threshold below which the daemon yields for backpressure.
    pub backpressure_headroom_threshold: f32,
    /// Yield duration when backpressure is active.
    pub backpressure_sleep: Duration,
}

impl Default for ScrubDaemonConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            cancel_check_interval: Duration::from_millis(100),
            backpressure_headroom_threshold: 0.3,
            backpressure_sleep: Duration::from_millis(25),
        }
    }
}

/// Live scrub daemon counters exposed to callers/TUI layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubDaemonMetrics {
    pub blocks_scanned_total: u64,
    pub blocks_corrupt_found: u64,
    pub blocks_recovered: u64,
    pub blocks_unrecoverable: u64,
    pub scrub_rounds_completed: u64,
    pub current_group: u32,
    pub scrub_rate_blocks_per_sec: f64,
    pub backpressure_yields: u64,
}

impl Default for ScrubDaemonMetrics {
    fn default() -> Self {
        Self {
            blocks_scanned_total: 0,
            blocks_corrupt_found: 0,
            blocks_recovered: 0,
            blocks_unrecoverable: 0,
            scrub_rounds_completed: 0,
            current_group: 0,
            scrub_rate_blocks_per_sec: 0.0,
            backpressure_yields: 0,
        }
    }
}

/// Summary for one daemon tick (one group scan attempt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubDaemonStep {
    pub group: u32,
    pub blocks_scanned: u64,
    pub corrupt_count: usize,
    pub recovered_count: usize,
    pub unrecoverable_count: usize,
    pub duration_ms: u64,
}

/// Round-robin background scheduler over [`ScrubWithRecovery`] group configs.
pub struct ScrubDaemon<'a, W: Write> {
    pipeline: ScrubWithRecovery<'a, W>,
    config: ScrubDaemonConfig,
    metrics: ScrubDaemonMetrics,
    next_group_index: usize,
    pressure: Option<Arc<SystemPressure>>,
    round_number: u64,
    round_started_at: Instant,
    round_groups_scanned: usize,
    round_corrupt: usize,
    round_recovered: usize,
}

// ── Pipeline ──────────────────────────────────────────────────────────────

/// Automatic corruption recovery pipeline.
///
/// Wraps a [`Scrubber`] and a set of per-group configurations to provide
/// end-to-end scrub → detect → recover → evidence → refresh.
pub struct ScrubWithRecovery<'a, W: Write> {
    device: &'a dyn BlockDevice,
    validator: &'a dyn BlockValidator,
    fs_uuid: [u8; 16],
    groups: Vec<GroupConfig>,
    ledger: EvidenceLedger<W>,
    /// Static fallback symbol count when adaptive policy is disabled.
    repair_symbol_count: u32,
    /// Optional adaptive overhead policy state.
    adaptive_overhead: Option<DurabilityAutopilot>,
    /// Groups treated as metadata-critical for policy multiplier.
    metadata_groups: BTreeSet<u32>,
    /// Latest adaptive decisions keyed by group number.
    policy_decisions: BTreeMap<u32, OverheadDecision>,
    /// Per-group refresh protocol state (dirty tracking + policy).
    refresh_states: BTreeMap<u32, GroupRefreshState>,
}

impl<'a, W: Write> ScrubWithRecovery<'a, W> {
    /// Create a new pipeline.
    ///
    /// - `device`: block device to scrub and recover on.
    /// - `validator`: pluggable block validation strategy.
    /// - `fs_uuid`: filesystem UUID for deterministic seed derivation.
    /// - `groups`: per-group layout and source range configurations.
    /// - `ledger_writer`: sink for JSONL evidence records.
    /// - `repair_symbol_count`: number of symbols to generate on refresh
    ///   (set to 0 to skip symbol refresh after recovery).
    pub fn new(
        device: &'a dyn BlockDevice,
        validator: &'a dyn BlockValidator,
        fs_uuid: [u8; 16],
        groups: Vec<GroupConfig>,
        ledger_writer: W,
        repair_symbol_count: u32,
    ) -> Self {
        let metadata_groups = BTreeSet::from([0_u32]);
        let refresh_states = groups
            .iter()
            .map(|group_cfg| {
                let group = group_cfg.layout.group.0;
                let policy = if metadata_groups.contains(&group) {
                    RefreshPolicy::Eager
                } else {
                    RefreshPolicy::Lazy {
                        max_staleness: Duration::from_secs(30),
                    }
                };
                (group, GroupRefreshState::new(policy))
            })
            .collect();

        Self {
            device,
            validator,
            fs_uuid,
            groups,
            ledger: EvidenceLedger::new(ledger_writer),
            repair_symbol_count,
            adaptive_overhead: None,
            metadata_groups,
            policy_decisions: BTreeMap::new(),
            refresh_states,
        }
    }

    /// Enable adaptive Bayesian overhead policy.
    #[must_use]
    pub fn with_adaptive_overhead(mut self, autopilot: DurabilityAutopilot) -> Self {
        self.adaptive_overhead = Some(autopilot);
        self
    }

    /// Override metadata-critical group set for 2x overhead multiplier.
    #[must_use]
    pub fn with_metadata_groups<I>(mut self, groups: I) -> Self
    where
        I: IntoIterator<Item = GroupNumber>,
    {
        self.metadata_groups = groups.into_iter().map(|group| group.0).collect();
        self.apply_default_refresh_policies();
        self
    }

    /// Override refresh policy for a single block group.
    #[must_use]
    pub fn with_group_refresh_policy(mut self, group: GroupNumber, policy: RefreshPolicy) -> Self {
        self.refresh_states
            .entry(group.0)
            .and_modify(|state| state.policy = policy)
            .or_insert_with(|| GroupRefreshState::new(policy));
        self
    }

    /// Notify the refresh policy that a write dirtied `group`.
    ///
    /// Eager/adaptive-eager policies will immediately refresh symbols.
    pub fn on_group_write(&mut self, cx: &Cx, group: GroupNumber) -> Result<()> {
        self.mark_group_dirty(group)?;
        self.maybe_refresh_dirty_group(cx, group, true)?;
        Ok(())
    }

    /// Run the full scrub-and-recover pipeline.
    ///
    /// 1. Scrub the device (full or range-based, depending on group configs).
    /// 2. For each group with corruption, attempt RaptorQ recovery.
    /// 3. Log evidence for every detection, recovery attempt, and outcome.
    /// 4. Optionally refresh repair symbols after successful recovery.
    /// 5. Return a [`RecoveryReport`] with per-block outcomes.
    pub fn scrub_and_recover(&mut self, cx: &Cx) -> Result<RecoveryReport> {
        let scrubber = Scrubber::new(self.device, self.validator);

        // Scrub the entire device.
        info!("scrub_and_recover: starting full device scrub");
        let report = scrubber.scrub_all(cx)?;
        debug!(
            blocks_scanned = report.blocks_scanned,
            blocks_corrupt = report.blocks_corrupt,
            findings = report.findings.len(),
            "scrub complete"
        );
        self.update_adaptive_policy(&report)?;
        self.refresh_dirty_groups(cx)?;

        if report.is_clean() {
            info!("scrub_and_recover: no corruption found");
            return Ok(RecoveryReport {
                blocks_scanned: report.blocks_scanned,
                total_corrupt: 0,
                total_recovered: 0,
                total_unrecoverable: 0,
                block_outcomes: BTreeMap::new(),
                group_summaries: Vec::new(),
            });
        }

        // Group corrupt blocks by their owning group.
        let grouped_corrupt = self.group_corrupt_blocks(&report);

        let mut block_outcomes = BTreeMap::new();
        let mut group_summaries = Vec::new();
        let mut total_recovered: usize = 0;
        let mut total_unrecoverable: usize = 0;

        for (group_cfg, corrupt_blocks) in &grouped_corrupt {
            let summary = self.recover_group(
                cx,
                group_cfg,
                corrupt_blocks,
                &mut block_outcomes,
                &mut total_recovered,
                &mut total_unrecoverable,
            )?;
            group_summaries.push(summary);
        }

        Ok(RecoveryReport {
            blocks_scanned: report.blocks_scanned,
            total_corrupt: grouped_corrupt.iter().map(|(_, blocks)| blocks.len()).sum(),
            total_recovered,
            total_unrecoverable,
            block_outcomes,
            group_summaries,
        })
    }

    /// Consume the pipeline and return the underlying evidence writer.
    #[must_use]
    pub fn into_ledger(self) -> W {
        self.ledger.into_inner()
    }

    // ── Internal helpers ──────────────────────────────────────────────

    fn corrupt_blocks_from_report(report: &ScrubReport) -> Vec<BlockNumber> {
        let mut blocks: Vec<BlockNumber> = report
            .findings
            .iter()
            .filter(|finding| finding.severity >= Severity::Error)
            .map(|finding| finding.block)
            .collect();
        blocks.sort_unstable_by_key(|block| block.0);
        blocks.dedup_by_key(|block| block.0);
        blocks
    }

    fn scrub_group_once(
        &mut self,
        cx: &Cx,
        group_cfg: GroupConfig,
    ) -> Result<(ScrubReport, Option<GroupRecoverySummary>)> {
        let group = group_cfg.layout.group;
        let scrubber = Scrubber::new(self.device, self.validator);
        let report = scrubber.scrub_range(
            cx,
            group_cfg.source_first_block,
            u64::from(group_cfg.source_block_count),
        )?;

        let scrub_record = EvidenceRecord::from_scrub_report(group.0, &report);
        self.ledger.append(&scrub_record).map_err(|e| {
            FfsError::RepairFailed(format!("failed to write scrub-cycle evidence: {e}"))
        })?;

        self.update_adaptive_policy(&report)?;
        self.maybe_refresh_dirty_group(cx, group, false)?;

        let corrupt_blocks = Self::corrupt_blocks_from_report(&report);
        if corrupt_blocks.is_empty() {
            return Ok((report, None));
        }

        let mut block_outcomes = BTreeMap::new();
        let mut total_recovered = 0_usize;
        let mut total_unrecoverable = 0_usize;
        let summary = self.recover_group(
            cx,
            &group_cfg,
            &corrupt_blocks,
            &mut block_outcomes,
            &mut total_recovered,
            &mut total_unrecoverable,
        )?;
        Ok((report, Some(summary)))
    }

    fn apply_default_refresh_policies(&mut self) {
        for group_cfg in &self.groups {
            let group = group_cfg.layout.group.0;
            let policy = if self.metadata_groups.contains(&group) {
                RefreshPolicy::Eager
            } else {
                RefreshPolicy::Lazy {
                    max_staleness: Duration::from_secs(30),
                }
            };
            self.refresh_states
                .entry(group)
                .and_modify(|state| state.policy = policy)
                .or_insert_with(|| GroupRefreshState::new(policy));
        }
    }

    #[must_use]
    fn find_group_config(&self, group: GroupNumber) -> Option<GroupConfig> {
        self.groups
            .iter()
            .copied()
            .find(|cfg| cfg.layout.group == group)
    }

    fn mark_group_dirty(&mut self, group: GroupNumber) -> Result<()> {
        let state = self
            .refresh_states
            .get_mut(&group.0)
            .ok_or_else(|| FfsError::Format(format!("group {} not configured", group.0)))?;
        if !state.dirty {
            state.dirty = true;
            state.dirty_since = Some(Instant::now());
        }
        debug!(
            target: "ffs::repair::refresh",
            group = group.0,
            policy = ?state.policy,
            dirty = state.dirty,
            "refresh_group_marked_dirty"
        );
        Ok(())
    }

    fn refresh_dirty_groups(&mut self, cx: &Cx) -> Result<()> {
        let dirty_groups: Vec<GroupNumber> = self
            .refresh_states
            .iter()
            .filter_map(|(group, state)| state.dirty.then_some(GroupNumber(*group)))
            .collect();
        for group in dirty_groups {
            self.maybe_refresh_dirty_group(cx, group, false)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn maybe_refresh_dirty_group(
        &mut self,
        cx: &Cx,
        group: GroupNumber,
        write_trigger: bool,
    ) -> Result<()> {
        let group_cfg = self
            .find_group_config(group)
            .ok_or_else(|| FfsError::Format(format!("group {} not configured", group.0)))?;

        let Some(state) = self.refresh_states.get(&group.0) else {
            return Ok(());
        };
        if !state.dirty {
            return Ok(());
        }
        let dirty_since = state.dirty_since.unwrap_or_else(Instant::now);
        let policy = state.policy;
        let dirty_age = Instant::now().saturating_duration_since(dirty_since);
        let decision = self.policy_decisions.get(&group.0).copied();

        trace!(
            target: "ffs::repair::refresh",
            group = group.0,
            policy = ?policy,
            dirty = state.dirty,
            dirty_since_ms = dirty_age.as_millis(),
            last_refresh_ms = Instant::now()
                .saturating_duration_since(state.last_refresh)
                .as_millis(),
            "refresh_policy_evaluated"
        );

        let refresh_mode = match policy {
            RefreshPolicy::Eager => Some(RefreshMode::EagerWrite),
            RefreshPolicy::Lazy { max_staleness } => {
                if write_trigger {
                    if dirty_age >= max_staleness {
                        warn!(
                            target: "ffs::repair::refresh",
                            group = group.0,
                            dirty_age_ms = dirty_age.as_millis(),
                            max_staleness_ms = max_staleness.as_millis(),
                            "refresh_staleness_timeout_triggered"
                        );
                        Some(RefreshMode::StalenessTimeout)
                    } else {
                        None
                    }
                } else {
                    Some(RefreshMode::LazyScrub)
                }
            }
            RefreshPolicy::Adaptive {
                risk_threshold,
                max_staleness,
            } => {
                let posterior = decision.map_or_else(
                    || {
                        self.adaptive_overhead
                            .map_or(0.0, |autopilot| autopilot.posterior_mean())
                    },
                    |d| d.corruption_posterior,
                );
                debug!(
                    target: "ffs::repair::refresh",
                    group = group.0,
                    policy = ?policy,
                    risk_threshold,
                    posterior_mean = posterior,
                    max_staleness_ms = max_staleness.as_millis(),
                    "adaptive_refresh_policy_resolved"
                );
                if posterior >= risk_threshold {
                    if write_trigger {
                        Some(RefreshMode::AdaptiveEagerWrite)
                    } else {
                        Some(RefreshMode::AdaptiveLazyScrub)
                    }
                } else if write_trigger {
                    if dirty_age >= max_staleness {
                        warn!(
                            target: "ffs::repair::refresh",
                            group = group.0,
                            dirty_age_ms = dirty_age.as_millis(),
                            max_staleness_ms = max_staleness.as_millis(),
                            "refresh_staleness_timeout_triggered"
                        );
                        Some(RefreshMode::StalenessTimeout)
                    } else {
                        None
                    }
                } else {
                    Some(RefreshMode::AdaptiveLazyScrub)
                }
            }
        };

        if let Some(mode) = refresh_mode {
            let refresh_symbol_count = self.selected_refresh_symbol_count(&group_cfg);
            if refresh_symbol_count == 0 {
                return Ok(());
            }
            self.refresh_symbols(cx, &group_cfg, refresh_symbol_count, mode)?;
            if let Some(state) = self.refresh_states.get_mut(&group.0) {
                state.dirty = false;
                state.dirty_since = None;
                state.last_refresh = Instant::now();
            }
        }
        Ok(())
    }

    fn update_adaptive_policy(&mut self, report: &ScrubReport) -> Result<()> {
        self.policy_decisions.clear();

        let Some(mut autopilot) = self.adaptive_overhead else {
            return Ok(());
        };

        trace!(
            target: "ffs::repair::policy",
            checked_blocks = report.blocks_scanned,
            corrupted_blocks = report.blocks_corrupt,
            groups_total = self.groups.len(),
            "policy_scrub_observation"
        );
        autopilot.update_posterior(report.blocks_corrupt, report.blocks_scanned);
        let (posterior_alpha, posterior_beta) = autopilot.posterior_params();
        debug!(
            target: "ffs::repair::policy",
            posterior_alpha,
            posterior_beta,
            posterior_mean = autopilot.posterior_mean(),
            "policy_posterior_updated"
        );

        for group_cfg in &self.groups {
            let group = group_cfg.layout.group.0;
            let metadata_group = self.metadata_groups.contains(&group);
            let mut decision =
                autopilot.decision_for_group(group_cfg.source_block_count, metadata_group);

            if decision.symbols_selected > group_cfg.layout.repair_block_count {
                let effective_symbols = group_cfg.layout.repair_block_count;
                let source_count = group_cfg.source_block_count.max(1);
                let effective_overhead = f64::from(effective_symbols) / f64::from(source_count);
                decision.symbols_selected = effective_symbols;
                decision.overhead_ratio = effective_overhead;
                decision.risk_bound =
                    autopilot.risk_bound(effective_overhead, group_cfg.source_block_count);
                decision.expected_loss =
                    autopilot.expected_loss(effective_overhead, group_cfg.source_block_count);
                warn!(
                    target: "ffs::repair::policy",
                    group,
                    selected_symbols = decision.symbols_selected,
                    layout_capacity = group_cfg.layout.repair_block_count,
                    effective_overhead,
                    "policy_symbol_count_clamped"
                );
            }

            info!(
                target: "ffs::repair::policy",
                group,
                metadata_group = decision.metadata_group,
                selected_overhead = decision.overhead_ratio,
                symbol_count = decision.symbols_selected,
                risk_bound = decision.risk_bound,
                expected_loss = decision.expected_loss,
                "policy_decision_selected"
            );

            let record = EvidenceRecord::policy_decision(
                group,
                PolicyDecisionDetail {
                    corruption_posterior: decision.corruption_posterior,
                    posterior_alpha: decision.posterior_alpha,
                    posterior_beta: decision.posterior_beta,
                    overhead_ratio: decision.overhead_ratio,
                    risk_bound: decision.risk_bound,
                    expected_loss: decision.expected_loss,
                    symbols_selected: decision.symbols_selected,
                    metadata_group: decision.metadata_group,
                    decision: "adaptive_overhead_expected_loss".to_owned(),
                },
            );
            self.ledger.append(&record).map_err(|e| {
                error!(
                    target: "ffs::repair::policy",
                    group,
                    error = %e,
                    "policy_evidence_append_failed"
                );
                FfsError::RepairFailed(format!("failed to write policy evidence: {e}"))
            })?;
            self.policy_decisions.insert(group, decision);
        }

        self.adaptive_overhead = Some(autopilot);
        Ok(())
    }

    #[must_use]
    fn selected_refresh_symbol_count(&self, group_cfg: &GroupConfig) -> u32 {
        self.policy_decisions
            .get(&group_cfg.layout.group.0)
            .map_or(self.repair_symbol_count, |decision| {
                decision.symbols_selected
            })
    }

    /// Recover a single group's corrupt blocks and return a summary.
    fn recover_group(
        &mut self,
        cx: &Cx,
        group_cfg: &GroupConfig,
        corrupt_blocks: &[BlockNumber],
        block_outcomes: &mut BTreeMap<u64, BlockOutcome>,
        total_recovered: &mut usize,
        total_unrecoverable: &mut usize,
    ) -> Result<GroupRecoverySummary> {
        let group_num = group_cfg.layout.group;

        // Log corruption detection evidence.
        self.log_corruption_detected(group_num, corrupt_blocks)?;

        info!(
            group = group_num.0,
            corrupt_count = corrupt_blocks.len(),
            "attempting recovery for group"
        );

        let attempt_detail = RepairDetail {
            generation: 0,
            corrupt_count: corrupt_blocks.len(),
            symbols_used: 0,
            symbols_available: usize::try_from(group_cfg.layout.repair_block_count)
                .unwrap_or(usize::MAX),
            decoder_stats: RecoveryDecoderStats::default(),
            verify_pass: false,
            reason: None,
        };
        self.ledger
            .append(&EvidenceRecord::repair_attempted(
                group_num.0,
                attempt_detail,
            ))
            .map_err(|e| {
                FfsError::RepairFailed(format!("failed to write recovery evidence: {e}"))
            })?;

        // Attempt recovery.
        let recovery_result = self.attempt_group_recovery(cx, group_cfg, corrupt_blocks);

        // Log recovery evidence.
        let evidence_record = EvidenceRecord::from_recovery(&recovery_result.evidence);
        self.ledger.append(&evidence_record).map_err(|e| {
            FfsError::RepairFailed(format!("failed to write recovery evidence: {e}"))
        })?;

        let mut symbols_refreshed = false;

        match recovery_result.evidence.outcome {
            RecoveryOutcome::Recovered => {
                info!(
                    group = group_num.0,
                    blocks_recovered = recovery_result.repaired_blocks.len(),
                    "recovery successful"
                );
                for block in &recovery_result.repaired_blocks {
                    block_outcomes.insert(block.0, BlockOutcome::Recovered);
                }
                *total_recovered += recovery_result.repaired_blocks.len();

                // Refresh symbols after successful recovery.
                let refresh_symbol_count = self.selected_refresh_symbol_count(group_cfg);
                if refresh_symbol_count > 0 {
                    match self.refresh_symbols(
                        cx,
                        group_cfg,
                        refresh_symbol_count,
                        RefreshMode::Recovery,
                    ) {
                        Ok(()) => {
                            symbols_refreshed = true;
                            info!(group = group_num.0, "repair symbols refreshed");
                        }
                        Err(e) => {
                            error!(
                                group = group_num.0,
                                error = %e,
                                "failed to refresh repair symbols"
                            );
                        }
                    }
                }
            }
            RecoveryOutcome::Partial => {
                warn!(
                    group = group_num.0,
                    reason = recovery_result
                        .evidence
                        .reason
                        .as_deref()
                        .unwrap_or("unknown"),
                    "partial recovery"
                );
                for block in &recovery_result.repaired_blocks {
                    block_outcomes.insert(block.0, BlockOutcome::Recovered);
                }
                *total_recovered += recovery_result.repaired_blocks.len();

                // Mark remaining corrupt blocks as unrecoverable.
                let repaired_set: std::collections::BTreeSet<u64> = recovery_result
                    .repaired_blocks
                    .iter()
                    .map(|b| b.0)
                    .collect();
                for block in corrupt_blocks {
                    if !repaired_set.contains(&block.0) {
                        block_outcomes.insert(block.0, BlockOutcome::Unrecoverable);
                        *total_unrecoverable += 1;
                    }
                }
            }
            RecoveryOutcome::Failed => {
                error!(
                    group = group_num.0,
                    reason = recovery_result
                        .evidence
                        .reason
                        .as_deref()
                        .unwrap_or("unknown"),
                    "recovery failed"
                );
                for block in corrupt_blocks {
                    block_outcomes.insert(block.0, BlockOutcome::Unrecoverable);
                }
                *total_unrecoverable += corrupt_blocks.len();
            }
        }

        Ok(GroupRecoverySummary {
            group: group_num.0,
            corrupt_count: corrupt_blocks.len(),
            recovered_count: recovery_result.repaired_blocks.len(),
            unrecoverable_count: corrupt_blocks.len() - recovery_result.repaired_blocks.len(),
            symbols_refreshed,
            decoder_stats: Some(recovery_result.evidence.decoder_stats),
        })
    }

    /// Group corrupt block numbers by their owning group configuration.
    ///
    /// Blocks that don't fall into any configured group are logged and skipped.
    fn group_corrupt_blocks(&self, report: &ScrubReport) -> Vec<(GroupConfig, Vec<BlockNumber>)> {
        // Only consider Error-or-above severity findings.
        let corrupt_blocks: Vec<BlockNumber> = report
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::Error)
            .map(|f| f.block)
            .collect();

        // Deduplicate block numbers (a block may have multiple findings).
        let mut unique_blocks = corrupt_blocks;
        unique_blocks.sort_unstable_by_key(|b| b.0);
        unique_blocks.dedup_by_key(|b| b.0);

        let mut result: Vec<(GroupConfig, Vec<BlockNumber>)> = Vec::new();

        for block in unique_blocks {
            let mut found = false;
            for group_cfg in &self.groups {
                let start = group_cfg.source_first_block.0;
                let end = start + u64::from(group_cfg.source_block_count);
                if block.0 >= start && block.0 < end {
                    // Find or create entry for this group.
                    if let Some(entry) = result
                        .iter_mut()
                        .find(|(g, _)| g.layout.group == group_cfg.layout.group)
                    {
                        entry.1.push(block);
                    } else {
                        result.push((*group_cfg, vec![block]));
                    }
                    found = true;
                    break;
                }
            }
            if !found {
                warn!(
                    block = block.0,
                    "corrupt block does not belong to any configured group"
                );
            }
        }

        result
    }

    /// Attempt recovery for one group.
    fn attempt_group_recovery(
        &self,
        cx: &Cx,
        group_cfg: &GroupConfig,
        corrupt_blocks: &[BlockNumber],
    ) -> RecoveryAttemptResult {
        let orchestrator = match GroupRecoveryOrchestrator::new(
            self.device,
            self.fs_uuid,
            group_cfg.layout,
            group_cfg.source_first_block,
            group_cfg.source_block_count,
        ) {
            Ok(o) => o,
            Err(e) => {
                error!(
                    group = group_cfg.layout.group.0,
                    error = %e,
                    "failed to create recovery orchestrator"
                );
                return RecoveryAttemptResult {
                    evidence: crate::recovery::RecoveryEvidence {
                        group: group_cfg.layout.group.0,
                        generation: 0,
                        corrupt_count: corrupt_blocks.len(),
                        symbols_available: 0,
                        symbols_used: 0,
                        decoder_stats: RecoveryDecoderStats::default(),
                        outcome: RecoveryOutcome::Failed,
                        reason: Some(format!("orchestrator creation failed: {e}")),
                    },
                    repaired_blocks: Vec::new(),
                };
            }
        };

        debug!(
            group = group_cfg.layout.group.0,
            corrupt_count = corrupt_blocks.len(),
            "calling recovery orchestrator"
        );
        orchestrator.recover_from_corrupt_blocks(cx, corrupt_blocks)
    }

    /// Re-encode repair symbols for a group after successful recovery.
    fn refresh_symbols(
        &mut self,
        cx: &Cx,
        group_cfg: &GroupConfig,
        repair_symbol_count: u32,
        mode: RefreshMode,
    ) -> Result<()> {
        let group_num = group_cfg.layout.group;
        let storage = RepairGroupStorage::new(self.device, group_cfg.layout);

        // Read current generation.
        let old_desc = storage.read_group_desc_ext(cx)?;
        let old_gen = old_desc.repair_generation;
        let effective_symbol_count = repair_symbol_count.min(group_cfg.layout.repair_block_count);
        if effective_symbol_count != repair_symbol_count {
            warn!(
                target: "ffs::repair::policy",
                group = group_num.0,
                selected_symbols = repair_symbol_count,
                layout_capacity = group_cfg.layout.repair_block_count,
                effective_overhead = f64::from(effective_symbol_count)
                    / f64::from(group_cfg.source_block_count.max(1)),
                "policy_symbol_count_clamped"
            );
        }

        debug!(
            target: "ffs::repair::refresh",
            group = group_num.0,
            refresh_mode = mode.as_str(),
            previous_generation = old_gen,
            requested_symbols = repair_symbol_count,
            effective_symbols = effective_symbol_count,
            "refreshing repair symbols"
        );

        // Re-encode.
        let encoded: EncodedGroup = encode_group(
            cx,
            self.device,
            &self.fs_uuid,
            group_num,
            group_cfg.source_first_block,
            group_cfg.source_block_count,
            effective_symbol_count,
        )?;

        let new_gen = old_gen + 1;

        // Write symbols.
        let symbols: Vec<(u32, Vec<u8>)> = encoded
            .repair_symbols
            .into_iter()
            .map(|s| (s.esi, s.data))
            .collect();
        let symbols_generated = u32::try_from(symbols.len()).unwrap_or(u32::MAX);

        storage.write_repair_symbols(cx, &symbols, new_gen)?;

        // Write updated descriptor.
        let new_desc = RepairGroupDescExt {
            repair_generation: new_gen,
            ..old_desc
        };
        storage.write_group_desc_ext(cx, &new_desc)?;

        info!(
            target: "ffs::repair::refresh",
            group = group_num.0,
            refresh_mode = mode.as_str(),
            symbols_generated,
            generation_before = old_gen,
            generation_after = new_gen,
            "refresh_symbols_applied"
        );
        trace!(
            group = group_num.0,
            new_generation = new_gen,
            symbols_generated,
            "symbol refresh complete"
        );

        // Log evidence.
        let evidence = EvidenceRecord::symbol_refresh(
            group_num.0,
            SymbolRefreshDetail {
                previous_generation: old_gen,
                new_generation: new_gen,
                symbols_generated,
            },
        );
        self.ledger.append(&evidence).map_err(|e| {
            FfsError::RepairFailed(format!("failed to write symbol refresh evidence: {e}"))
        })?;

        Ok(())
    }

    /// Log corruption detection events for a group.
    fn log_corruption_detected(
        &mut self,
        group: GroupNumber,
        corrupt_blocks: &[BlockNumber],
    ) -> Result<()> {
        warn!(
            group = group.0,
            corrupt_blocks = corrupt_blocks.len(),
            "corruption detected"
        );

        let detail = CorruptionDetail {
            blocks_affected: u32::try_from(corrupt_blocks.len()).unwrap_or(u32::MAX),
            corruption_kind: "checksum_mismatch".to_owned(),
            severity: "error".to_owned(),
            detail: format!(
                "blocks: {:?}",
                corrupt_blocks
                    .iter()
                    .take(16)
                    .map(|b| b.0)
                    .collect::<Vec<_>>()
            ),
        };
        let record = EvidenceRecord::corruption_detected(group.0, detail);
        self.ledger.append(&record).map_err(|e| {
            FfsError::RepairFailed(format!("failed to write corruption evidence: {e}"))
        })?;
        Ok(())
    }
}

impl<'a, W: Write> ScrubDaemon<'a, W> {
    /// Create a round-robin scrub daemon over an existing recovery pipeline.
    pub fn new(pipeline: ScrubWithRecovery<'a, W>, config: ScrubDaemonConfig) -> Self {
        Self {
            pipeline,
            config,
            metrics: ScrubDaemonMetrics::default(),
            next_group_index: 0,
            pressure: None,
            round_number: 0,
            round_started_at: Instant::now(),
            round_groups_scanned: 0,
            round_corrupt: 0,
            round_recovered: 0,
        }
    }

    /// Attach shared system pressure for backpressure-aware yielding.
    #[must_use]
    pub fn with_pressure(mut self, pressure: Arc<SystemPressure>) -> Self {
        self.pressure = Some(pressure);
        self
    }

    /// Current daemon counters.
    #[must_use]
    pub fn metrics(&self) -> &ScrubDaemonMetrics {
        &self.metrics
    }

    /// Consume the daemon and return the inner pipeline + final metrics.
    #[must_use]
    pub fn into_parts(self) -> (ScrubWithRecovery<'a, W>, ScrubDaemonMetrics) {
        (self.pipeline, self.metrics)
    }

    /// Consume the daemon and return only the inner pipeline.
    #[must_use]
    pub fn into_pipeline(self) -> ScrubWithRecovery<'a, W> {
        self.pipeline
    }

    /// Execute one daemon tick (scan one group, recover if needed).
    pub fn run_once(&mut self, cx: &Cx) -> Result<ScrubDaemonStep> {
        if self.pipeline.groups.is_empty() {
            return Err(FfsError::RepairFailed(
                "scrub daemon requires at least one group".to_owned(),
            ));
        }

        if self.next_group_index == 0 {
            self.round_number = self.round_number.saturating_add(1);
            self.round_started_at = Instant::now();
            self.round_groups_scanned = 0;
            self.round_corrupt = 0;
            self.round_recovered = 0;
            debug!(
                target: "ffs::repair::daemon",
                round_number = self.round_number,
                starting_group = self.pipeline.groups[0].layout.group.0,
                "scrub_round_start"
            );
        }

        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;

        let group_cfg = self.pipeline.groups[self.next_group_index];
        let group = group_cfg.layout.group;
        trace!(
            target: "ffs::repair::daemon",
            group_id = group.0,
            "group_scan_start"
        );

        let started = Instant::now();
        let (report, summary) = self.pipeline.scrub_group_once(cx, group_cfg)?;
        let elapsed = started.elapsed();
        let duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);

        let corrupt_count = summary.as_ref().map_or(0, |s| s.corrupt_count);
        let recovered_count = summary.as_ref().map_or(0, |s| s.recovered_count);
        let unrecoverable_count = summary.as_ref().map_or(0, |s| s.unrecoverable_count);

        trace!(
            target: "ffs::repair::daemon",
            group_id = group.0,
            duration_ms,
            blocks_scanned = report.blocks_scanned,
            errors_found = report.findings.len(),
            "group_scan_complete"
        );

        self.metrics.current_group = group.0;
        self.metrics.blocks_scanned_total = self
            .metrics
            .blocks_scanned_total
            .saturating_add(report.blocks_scanned);
        self.metrics.blocks_corrupt_found = self
            .metrics
            .blocks_corrupt_found
            .saturating_add(u64::try_from(corrupt_count).unwrap_or(u64::MAX));
        self.metrics.blocks_recovered = self
            .metrics
            .blocks_recovered
            .saturating_add(u64::try_from(recovered_count).unwrap_or(u64::MAX));
        self.metrics.blocks_unrecoverable = self
            .metrics
            .blocks_unrecoverable
            .saturating_add(u64::try_from(unrecoverable_count).unwrap_or(u64::MAX));
        self.metrics.scrub_rate_blocks_per_sec = if elapsed.is_zero() {
            0.0
        } else {
            report.blocks_scanned as f64 / elapsed.as_secs_f64()
        };

        self.round_groups_scanned = self.round_groups_scanned.saturating_add(1);
        self.round_corrupt = self.round_corrupt.saturating_add(corrupt_count);
        self.round_recovered = self.round_recovered.saturating_add(recovered_count);

        self.next_group_index += 1;
        if self.next_group_index >= self.pipeline.groups.len() {
            self.next_group_index = 0;
            self.metrics.scrub_rounds_completed =
                self.metrics.scrub_rounds_completed.saturating_add(1);
            info!(
                target: "ffs::repair::daemon",
                round_number = self.round_number,
                duration_secs = self.round_started_at.elapsed().as_secs_f64(),
                groups_scanned = self.round_groups_scanned,
                total_corrupt = self.round_corrupt,
                total_recovered = self.round_recovered,
                "scrub_round_complete"
            );
        }

        self.maybe_backpressure_yield(cx, group)?;

        Ok(ScrubDaemonStep {
            group: group.0,
            blocks_scanned: report.blocks_scanned,
            corrupt_count,
            recovered_count,
            unrecoverable_count,
            duration_ms,
        })
    }

    /// Execute one full round (all configured groups exactly once).
    pub fn run_one_round(&mut self, cx: &Cx) -> Result<()> {
        let total_groups = self.pipeline.groups.len();
        for _ in 0..total_groups {
            self.run_once(cx)?;
        }
        Ok(())
    }

    /// Run continuously until cancellation is requested.
    pub fn run_until_cancelled(&mut self, cx: &Cx) -> Result<ScrubDaemonMetrics> {
        info!(
            target: "ffs::repair::daemon",
            total_groups = self.pipeline.groups.len(),
            interval_secs = self.config.interval.as_secs_f64(),
            backpressure_threshold = self.config.backpressure_headroom_threshold,
            "scrub_daemon_start"
        );

        loop {
            if cx.checkpoint().is_err() {
                info!(
                    target: "ffs::repair::daemon",
                    reason = "cancelled",
                    blocks_scanned_total = self.metrics.blocks_scanned_total,
                    blocks_corrupt_found = self.metrics.blocks_corrupt_found,
                    blocks_recovered = self.metrics.blocks_recovered,
                    blocks_unrecoverable = self.metrics.blocks_unrecoverable,
                    scrub_rounds_completed = self.metrics.scrub_rounds_completed,
                    "scrub_daemon_stop"
                );
                return Ok(self.metrics.clone());
            }

            let tick_started = Instant::now();
            match self.run_once(cx) {
                Ok(_) => {}
                Err(FfsError::Cancelled) => {
                    info!(
                        target: "ffs::repair::daemon",
                        reason = "cancelled",
                        blocks_scanned_total = self.metrics.blocks_scanned_total,
                        blocks_corrupt_found = self.metrics.blocks_corrupt_found,
                        blocks_recovered = self.metrics.blocks_recovered,
                        blocks_unrecoverable = self.metrics.blocks_unrecoverable,
                        scrub_rounds_completed = self.metrics.scrub_rounds_completed,
                        "scrub_daemon_stop"
                    );
                    return Ok(self.metrics.clone());
                }
                Err(err) => return Err(err),
            }

            let tick_elapsed = tick_started.elapsed();
            let idle = self.config.interval.saturating_sub(tick_elapsed);
            if let Err(err) = self.sleep_with_checkpoint(cx, idle) {
                if matches!(err, FfsError::Cancelled) {
                    info!(
                        target: "ffs::repair::daemon",
                        reason = "cancelled",
                        blocks_scanned_total = self.metrics.blocks_scanned_total,
                        blocks_corrupt_found = self.metrics.blocks_corrupt_found,
                        blocks_recovered = self.metrics.blocks_recovered,
                        blocks_unrecoverable = self.metrics.blocks_unrecoverable,
                        scrub_rounds_completed = self.metrics.scrub_rounds_completed,
                        "scrub_daemon_stop"
                    );
                    return Ok(self.metrics.clone());
                }
                return Err(err);
            }
        }
    }

    fn maybe_backpressure_yield(&mut self, cx: &Cx, group: GroupNumber) -> Result<()> {
        let Some(pressure) = self.pressure.as_ref() else {
            return Ok(());
        };

        let headroom = pressure.headroom();
        if headroom >= self.config.backpressure_headroom_threshold {
            return Ok(());
        }

        let yield_duration = self.config.backpressure_sleep;
        self.metrics.backpressure_yields = self.metrics.backpressure_yields.saturating_add(1);
        debug!(
            target: "ffs::repair::daemon",
            current_group = group.0,
            pressure_source = pressure.level_label(),
            headroom,
            yield_duration_ms = yield_duration.as_millis(),
            "backpressure_yield"
        );
        self.sleep_with_checkpoint(cx, yield_duration)
    }

    fn sleep_with_checkpoint(&self, cx: &Cx, duration: Duration) -> Result<()> {
        if duration.is_zero() {
            return Ok(());
        }

        let mut remaining = duration;
        while !remaining.is_zero() {
            let slice = remaining.min(self.config.cancel_check_interval);
            std::thread::sleep(slice);
            remaining = remaining.saturating_sub(slice);
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autopilot::DurabilityAutopilot;
    use crate::codec::encode_group;
    use crate::evidence::EvidenceEventType;
    use crate::scrub::{BlockVerdict, CorruptionKind, Severity};
    use crate::symbol::RepairGroupDescExt;
    use ffs_block::BlockBuf;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};

    // ── In-memory block device ────────────────────────────────────────

    struct MemBlockDevice {
        blocks: Mutex<HashMap<u64, Vec<u8>>>,
        block_size: u32,
        block_count: u64,
    }

    impl MemBlockDevice {
        fn new(block_size: u32, block_count: u64) -> Self {
            Self {
                blocks: Mutex::new(HashMap::new()),
                block_size,
                block_count,
            }
        }
    }

    impl BlockDevice for MemBlockDevice {
        fn read_block(&self, _cx: &Cx, block: BlockNumber) -> Result<BlockBuf> {
            if block.0 >= self.block_count {
                return Err(FfsError::Format(format!(
                    "read out of range: block={} block_count={}",
                    block.0, self.block_count
                )));
            }
            let bytes = self
                .blocks
                .lock()
                .expect("mutex")
                .get(&block.0)
                .cloned()
                .unwrap_or_else(|| vec![0_u8; self.block_size as usize]);
            Ok(BlockBuf::new(bytes))
        }

        fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> Result<()> {
            if block.0 >= self.block_count {
                return Err(FfsError::Format(format!(
                    "write out of range: block={} block_count={}",
                    block.0, self.block_count
                )));
            }
            if data.len() != self.block_size as usize {
                return Err(FfsError::Format(format!(
                    "write size mismatch: got={} expected={}",
                    data.len(),
                    self.block_size
                )));
            }
            self.blocks
                .lock()
                .expect("mutex")
                .insert(block.0, data.to_vec());
            Ok(())
        }

        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn block_count(&self) -> u64 {
            self.block_count
        }

        fn sync(&self, _cx: &Cx) -> Result<()> {
            Ok(())
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────

    fn test_uuid() -> [u8; 16] {
        [0x22; 16]
    }

    fn deterministic_block(index: u64, block_size: u32) -> Vec<u8> {
        (0..block_size as usize)
            .map(|i| {
                let value = (index.wrapping_mul(31))
                    .wrapping_add(i as u64)
                    .wrapping_add(7)
                    % 251;
                u8::try_from(value).expect("value < 251")
            })
            .collect()
    }

    fn write_source_blocks(
        cx: &Cx,
        device: &MemBlockDevice,
        source_first_block: BlockNumber,
        source_block_count: u32,
    ) -> Vec<Vec<u8>> {
        let block_size = device.block_size();
        let mut originals = Vec::with_capacity(source_block_count as usize);
        for i in 0..u64::from(source_block_count) {
            let data = deterministic_block(i, block_size);
            let block = BlockNumber(source_first_block.0 + i);
            device
                .write_block(cx, block, &data)
                .expect("write source block");
            originals.push(data);
        }
        originals
    }

    fn bootstrap_storage(
        cx: &Cx,
        device: &MemBlockDevice,
        layout: RepairGroupLayout,
        source_first_block: BlockNumber,
        source_block_count: u32,
        repair_symbol_count: u32,
    ) -> usize {
        let encoded = encode_group(
            cx,
            device,
            &test_uuid(),
            layout.group,
            source_first_block,
            source_block_count,
            repair_symbol_count,
        )
        .expect("encode group");

        let storage = RepairGroupStorage::new(device, layout);
        let desc = RepairGroupDescExt {
            transfer_length: u64::from(encoded.source_block_count) * u64::from(encoded.symbol_size),
            symbol_size: u16::try_from(encoded.symbol_size).expect("symbol_size fits u16"),
            source_block_count: u16::try_from(encoded.source_block_count)
                .expect("source_block_count fits u16"),
            sub_blocks: 1,
            symbol_alignment: 4,
            repair_start_block: layout.repair_start_block(),
            repair_block_count: layout.repair_block_count,
            repair_generation: 0,
            checksum: 0,
        };
        storage
            .write_group_desc_ext(cx, &desc)
            .expect("write bootstrap desc");

        let symbols = encoded
            .repair_symbols
            .into_iter()
            .map(|s| (s.esi, s.data))
            .collect::<Vec<_>>();
        storage
            .write_repair_symbols(cx, &symbols, 1)
            .expect("write repair symbols");
        symbols.len()
    }

    fn read_generation(cx: &Cx, device: &MemBlockDevice, layout: RepairGroupLayout) -> u64 {
        let storage = RepairGroupStorage::new(device, layout);
        storage
            .read_group_desc_ext(cx)
            .expect("read group desc")
            .repair_generation
    }

    fn policy_decision_stub(symbols_selected: u32, corruption_posterior: f64) -> OverheadDecision {
        OverheadDecision {
            overhead_ratio: 0.05,
            corruption_posterior,
            posterior_alpha: 1.0,
            posterior_beta: 100.0,
            risk_bound: 1e-6,
            expected_loss: 10.0,
            symbols_selected,
            metadata_group: false,
        }
    }

    fn splitmix64(mut x: u64) -> u64 {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    fn block_hashes(cx: &Cx, device: &MemBlockDevice, blocks: &[u64]) -> BTreeMap<u64, String> {
        let mut hashes = BTreeMap::new();
        for &block in blocks {
            let bytes = device.read_block(cx, BlockNumber(block)).expect("read");
            let digest = blake3::hash(bytes.as_slice()).to_hex().to_string();
            hashes.insert(block, digest);
        }
        hashes
    }

    fn maybe_write_repair_e2e_artifacts(
        before: &BTreeMap<u64, String>,
        after: &BTreeMap<u64, String>,
        corrupt_blocks: &[u64],
        ledger_data: &[u8],
        seed: u64,
        corruption_percent: u64,
    ) {
        let Ok(dir) = std::env::var("FFS_REPAIR_E2E_ARTIFACT_DIR") else {
            return;
        };
        let dir_path = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir_path).expect("create artifact dir");

        let before_body = before
            .iter()
            .map(|(block, digest)| format!("{block} {digest}"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            dir_path.join("before_checksums.txt"),
            format!("{before_body}\n"),
        )
        .expect("write before checksums");

        let after_body = after
            .iter()
            .map(|(block, digest)| format!("{block} {digest}"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            dir_path.join("after_checksums.txt"),
            format!("{after_body}\n"),
        )
        .expect("write after checksums");

        let corruption_plan = serde_json::json!({
            "seed": seed,
            "corruption_percent": corruption_percent,
            "total_corrupted_blocks": corrupt_blocks.len(),
            "corrupted_blocks": corrupt_blocks,
        });
        std::fs::write(
            dir_path.join("corruption_plan.json"),
            serde_json::to_vec_pretty(&corruption_plan).expect("serialize corruption plan"),
        )
        .expect("write corruption plan");

        std::fs::write(dir_path.join("recovery_evidence.jsonl"), ledger_data)
            .expect("write recovery evidence");
    }

    /// Validator that flags specific block numbers as corrupt.
    struct CorruptBlockValidator {
        corrupt_blocks: Vec<u64>,
    }

    impl CorruptBlockValidator {
        fn new(corrupt_blocks: Vec<u64>) -> Self {
            Self { corrupt_blocks }
        }
    }

    impl BlockValidator for CorruptBlockValidator {
        fn validate(&self, block: BlockNumber, _data: &BlockBuf) -> BlockVerdict {
            if self.corrupt_blocks.contains(&block.0) {
                BlockVerdict::Corrupt(vec![(
                    CorruptionKind::ChecksumMismatch,
                    Severity::Error,
                    format!("injected corruption at block {}", block.0),
                )])
            } else {
                BlockVerdict::Clean
            }
        }
    }

    // ── Unit tests ────────────────────────────────────────────────────

    #[test]
    fn single_corrupt_block_automatic_recovery() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        // Inject corruption at block 3.
        let corrupt_block = BlockNumber(3);
        device
            .write_block(&cx, corrupt_block, &vec![0xDE; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![3]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(
            report.is_fully_recovered(),
            "expected full recovery: {report:?}"
        );
        assert_eq!(report.total_corrupt, 1);
        assert_eq!(report.total_recovered, 1);
        assert_eq!(report.total_unrecoverable, 0);
        assert_eq!(
            report.block_outcomes.get(&3),
            Some(&BlockOutcome::Recovered)
        );

        // Verify the block was actually restored.
        let restored = device.read_block(&cx, corrupt_block).expect("read");
        assert_eq!(restored.as_slice(), originals[3].as_slice());
    }

    #[test]
    fn multiple_corrupt_blocks_same_group_recovered() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        // Corrupt blocks 1 and 5.
        for idx in [1_u64, 5] {
            device
                .write_block(&cx, BlockNumber(idx), &vec![0xAA; block_size as usize])
                .expect("inject corruption");
        }

        let validator = CorruptBlockValidator::new(vec![1, 5]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(report.is_fully_recovered());
        assert_eq!(report.total_corrupt, 2);
        assert_eq!(report.total_recovered, 2);

        for idx in [1_u64, 5] {
            let restored = device.read_block(&cx, BlockNumber(idx)).expect("read");
            assert_eq!(
                restored.as_slice(),
                originals[usize::try_from(idx).unwrap()].as_slice(),
                "block {idx} not restored"
            );
        }
    }

    #[test]
    fn too_many_corrupt_blocks_graceful_failure() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 2).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 1);

        // Corrupt 3 blocks but only 1 repair symbol available.
        for idx in [0_u64, 1, 2] {
            device
                .write_block(&cx, BlockNumber(idx), &vec![0xBB; block_size as usize])
                .expect("inject corruption");
        }

        let validator = CorruptBlockValidator::new(vec![0, 1, 2]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            0, // no refresh
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(!report.is_fully_recovered());
        assert_eq!(report.total_corrupt, 3);
        assert_eq!(report.total_unrecoverable, 3);

        // All blocks marked unrecoverable.
        for idx in [0_u64, 1, 2] {
            assert_eq!(
                report.block_outcomes.get(&idx),
                Some(&BlockOutcome::Unrecoverable),
                "block {idx} should be unrecoverable"
            );
        }
    }

    #[test]
    fn clean_scrub_produces_empty_report() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 64);

        // Write non-zero data to all blocks so ZeroCheckValidator won't trigger.
        for i in 0..64 {
            let data = deterministic_block(i, block_size);
            device
                .write_block(&cx, BlockNumber(i), &data)
                .expect("write");
        }

        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 32, 0, 2).expect("layout");
        let group_cfg = GroupConfig {
            layout,
            source_first_block: BlockNumber(0),
            source_block_count: 8,
        };

        // Validator that always says clean.
        let validator = CorruptBlockValidator::new(vec![]);

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            0,
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(report.is_fully_recovered());
        assert_eq!(report.total_corrupt, 0);
        assert_eq!(report.total_recovered, 0);
        assert_eq!(report.blocks_scanned, 64);
        assert!(report.group_summaries.is_empty());
    }

    #[test]
    fn evidence_ledger_captures_all_events() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        device
            .write_block(&cx, BlockNumber(2), &vec![0xCC; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![2]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4, // enable refresh
        );

        let _report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        let ledger_data = pipeline.into_ledger();

        let records = crate::evidence::parse_evidence_ledger(ledger_data);
        assert!(
            records.len() >= 4,
            "expected at least 4 evidence records (corruption + attempt + repair + refresh), got {}",
            records.len()
        );

        // First record: corruption detected.
        assert_eq!(
            records[0].event_type,
            crate::evidence::EvidenceEventType::CorruptionDetected
        );
        assert!(
            records
                .iter()
                .any(|r| { r.event_type == crate::evidence::EvidenceEventType::RepairAttempted })
        );
        assert!(
            records
                .iter()
                .any(|r| { r.event_type == crate::evidence::EvidenceEventType::RepairSucceeded })
        );
        assert!(
            records
                .iter()
                .any(|r| { r.event_type == crate::evidence::EvidenceEventType::SymbolRefresh })
        );
    }

    #[test]
    fn symbol_refresh_after_recovery() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        device
            .write_block(&cx, BlockNumber(1), &vec![0xDD; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![1]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(report.is_fully_recovered());

        // Verify generation was bumped.
        let storage = RepairGroupStorage::new(&device, layout);
        let desc = storage.read_group_desc_ext(&cx).expect("read desc");
        assert!(
            desc.repair_generation >= 2,
            "expected generation >= 2 after refresh, got {}",
            desc.repair_generation
        );

        // Verify symbols_refreshed in group summary.
        assert_eq!(report.group_summaries.len(), 1);
        assert!(report.group_summaries[0].symbols_refreshed);
    }

    #[test]
    fn stress_random_corruption_patterns() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 8).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 16;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 8);

        // Corrupt up to 4 blocks (within RaptorQ capacity of 8 symbols).
        let corrupt_indices: Vec<u64> = vec![2, 7, 11, 14];
        for &idx in &corrupt_indices {
            device
                .write_block(&cx, BlockNumber(idx), &vec![0xEE; block_size as usize])
                .expect("inject corruption");
        }

        let validator = CorruptBlockValidator::new(corrupt_indices.clone());
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            8,
        );

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(
            report.is_fully_recovered(),
            "expected full recovery: corrupt={} recovered={} unrecoverable={}",
            report.total_corrupt,
            report.total_recovered,
            report.total_unrecoverable,
        );
        assert_eq!(report.total_corrupt, 4);
        assert_eq!(report.total_recovered, 4);

        // Verify all blocks restored correctly.
        for &idx in &corrupt_indices {
            let restored = device.read_block(&cx, BlockNumber(idx)).expect("read");
            assert_eq!(
                restored.as_slice(),
                originals[usize::try_from(idx).unwrap()].as_slice(),
                "block {idx} not restored correctly"
            );
        }
    }

    #[test]
    fn eager_policy_refreshes_symbols_on_write() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let generation_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_group_refresh_policy(GroupNumber(0), RefreshPolicy::Eager);

        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("eager refresh");

        let generation_after = read_generation(&cx, &device, layout);
        assert_eq!(generation_after, generation_before + 1);
    }

    #[test]
    fn lazy_policy_refreshes_on_next_scrub_cycle() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let generation_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_secs(30),
            },
        );

        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("mark dirty");
        let generation_after_write = read_generation(&cx, &device, layout);
        assert_eq!(generation_after_write, generation_before);

        let _report = pipeline.scrub_and_recover(&cx).expect("scrub");
        let generation_after_scrub = read_generation(&cx, &device, layout);
        assert_eq!(generation_after_scrub, generation_before + 1);
    }

    #[test]
    fn adaptive_policy_switches_eager_based_on_posterior() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let generation_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Adaptive {
                risk_threshold: 0.05,
                max_staleness: Duration::from_secs(30),
            },
        );

        pipeline
            .policy_decisions
            .insert(0, policy_decision_stub(4, 0.01));
        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("adaptive low-risk write");
        assert_eq!(read_generation(&cx, &device, layout), generation_before);
        assert!(
            pipeline
                .refresh_states
                .get(&0)
                .expect("refresh state")
                .dirty
        );

        pipeline
            .policy_decisions
            .insert(0, policy_decision_stub(4, 0.2));
        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("adaptive high-risk write");
        assert_eq!(read_generation(&cx, &device, layout), generation_before + 1);
        assert!(
            !pipeline
                .refresh_states
                .get(&0)
                .expect("refresh state")
                .dirty
        );
    }

    #[test]
    fn staleness_timeout_forces_refresh() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);
        let generation_before = read_generation(&cx, &device, layout);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_group_refresh_policy(
            GroupNumber(0),
            RefreshPolicy::Lazy {
                max_staleness: Duration::from_millis(5),
            },
        );

        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("mark dirty");
        if let Some(state) = pipeline.refresh_states.get_mut(&0) {
            state.dirty = true;
            state.dirty_since = Instant::now().checked_sub(Duration::from_millis(25));
        }
        pipeline
            .on_group_write(&cx, GroupNumber(0))
            .expect("force stale refresh");

        assert_eq!(read_generation(&cx, &device, layout), generation_before + 1);
    }

    #[test]
    fn adaptive_policy_logs_decision_on_clean_scrub() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 64);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 32, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 16;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_adaptive_overhead(DurabilityAutopilot::default())
        .with_metadata_groups([GroupNumber(0)]);

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(report.is_fully_recovered());

        let records = crate::evidence::parse_evidence_ledger(pipeline.into_ledger());
        let policy = records
            .iter()
            .find(|record| record.event_type == crate::evidence::EvidenceEventType::PolicyDecision)
            .expect("policy decision record");
        let detail = policy.policy.as_ref().expect("policy detail");
        assert!(detail.posterior_alpha >= 1.0);
        assert!(detail.posterior_beta >= 100.0);
        assert!(detail.overhead_ratio >= 0.03);
        assert!(detail.overhead_ratio <= 0.20);
    }

    #[test]
    fn adaptive_policy_controls_symbol_refresh_count() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        device
            .write_block(&cx, BlockNumber(2), &vec![0xAB; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![2]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };

        let mut ledger_buf = Vec::new();
        let mut pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        )
        .with_adaptive_overhead(DurabilityAutopilot::default())
        .with_metadata_groups([GroupNumber(0)]);

        let report = pipeline.scrub_and_recover(&cx).expect("pipeline");
        assert!(report.is_fully_recovered());

        let records = crate::evidence::parse_evidence_ledger(pipeline.into_ledger());
        let policy_detail = records
            .iter()
            .filter_map(|record| {
                if record.event_type == crate::evidence::EvidenceEventType::PolicyDecision {
                    record.policy.as_ref()
                } else {
                    None
                }
            })
            .find(|detail| detail.symbols_selected > 0)
            .unwrap_or_else(|| {
                records
                    .iter()
                    .find_map(|record| record.policy.as_ref())
                    .expect("policy detail")
            });

        let refresh_detail = records
            .iter()
            .find_map(|record| {
                if record.event_type == crate::evidence::EvidenceEventType::SymbolRefresh {
                    record.symbol_refresh.as_ref()
                } else {
                    None
                }
            })
            .expect("symbol refresh detail");

        assert_eq!(
            refresh_detail.symbols_generated,
            policy_detail.symbols_selected
        );
    }

    #[test]
    fn scrub_daemon_scans_at_least_one_group() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        );

        let step = daemon.run_once(&cx).expect("run once");
        assert_eq!(step.group, 0);
        assert!(step.blocks_scanned > 0);
        assert!(daemon.metrics().blocks_scanned_total >= u64::from(source_count));
        assert_eq!(daemon.metrics().scrub_rounds_completed, 1);
    }

    #[test]
    fn scrub_daemon_detects_corruption_and_triggers_recovery() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        let originals = write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let corrupt_block = BlockNumber(3);
        device
            .write_block(&cx, corrupt_block, &vec![0xEF; block_size as usize])
            .expect("inject corruption");

        let validator = CorruptBlockValidator::new(vec![3]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        );

        let step = daemon.run_once(&cx).expect("run once");
        assert_eq!(step.corrupt_count, 1);
        assert_eq!(step.recovered_count, 1);
        assert_eq!(step.unrecoverable_count, 0);

        let restored = device
            .read_block(&cx, corrupt_block)
            .expect("read restored");
        assert_eq!(restored.as_slice(), originals[3].as_slice());

        let (pipeline, _metrics) = daemon.into_parts();
        let ledger = pipeline.into_ledger();
        let records = crate::evidence::parse_evidence_ledger(ledger);
        assert!(
            records.iter().any(|r| {
                r.event_type == crate::evidence::EvidenceEventType::ScrubCycleComplete
            })
        );
        assert!(
            records
                .iter()
                .any(|r| r.event_type == crate::evidence::EvidenceEventType::RepairSucceeded)
        );
    }

    #[test]
    fn scrub_daemon_respects_cancellation_promptly() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let mut daemon = ScrubDaemon::new(pipeline, ScrubDaemonConfig::default());

        let metrics = daemon.run_until_cancelled(&cx).expect("cancelled stop");
        assert_eq!(metrics.blocks_scanned_total, 0);
        assert_eq!(metrics.scrub_rounds_completed, 0);
    }

    #[test]
    fn scrub_daemon_yields_under_backpressure() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 128);
        let layout =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout");
        let source_first = BlockNumber(0);
        let source_count = 8;

        write_source_blocks(&cx, &device, source_first, source_count);
        bootstrap_storage(&cx, &device, layout, source_first, source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let group_cfg = GroupConfig {
            layout,
            source_first_block: source_first,
            source_block_count: source_count,
        };
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            vec![group_cfg],
            &mut ledger_buf,
            4,
        );
        let pressure = Arc::new(SystemPressure::with_headroom(0.1));
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                backpressure_headroom_threshold: 0.5,
                backpressure_sleep: Duration::from_millis(1),
            },
        )
        .with_pressure(pressure);

        let _step = daemon.run_once(&cx).expect("run once");
        assert_eq!(daemon.metrics().backpressure_yields, 1);
    }

    #[test]
    fn scrub_daemon_completes_full_round_without_error() {
        let cx = Cx::for_testing();
        let block_size = 256;
        let device = MemBlockDevice::new(block_size, 256);

        let layout0 =
            RepairGroupLayout::new(GroupNumber(0), BlockNumber(0), 64, 0, 4).expect("layout0");
        let layout1 =
            RepairGroupLayout::new(GroupNumber(1), BlockNumber(64), 64, 0, 4).expect("layout1");

        let source_count = 8;
        write_source_blocks(&cx, &device, BlockNumber(0), source_count);
        write_source_blocks(&cx, &device, BlockNumber(64), source_count);
        bootstrap_storage(&cx, &device, layout0, BlockNumber(0), source_count, 4);
        bootstrap_storage(&cx, &device, layout1, BlockNumber(64), source_count, 4);

        let validator = CorruptBlockValidator::new(vec![]);
        let groups = vec![
            GroupConfig {
                layout: layout0,
                source_first_block: BlockNumber(0),
                source_block_count: source_count,
            },
            GroupConfig {
                layout: layout1,
                source_first_block: BlockNumber(64),
                source_block_count: source_count,
            },
        ];

        let mut ledger_buf = Vec::new();
        let pipeline =
            ScrubWithRecovery::new(&device, &validator, test_uuid(), groups, &mut ledger_buf, 4);
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        );

        daemon.run_one_round(&cx).expect("run one round");
        assert_eq!(daemon.metrics().scrub_rounds_completed, 1);
        assert!(daemon.metrics().blocks_scanned_total >= u64::from(source_count) * 2);
    }

    #[test]
    fn e2e_survive_five_percent_random_block_corruption_with_daemon() {
        let cx = Cx::for_testing();
        const GROUP_COUNT: u32 = 20;
        const GROUP_BLOCK_COUNT: u32 = 64;
        const SOURCE_BLOCK_COUNT: u32 = 20;
        const REPAIR_SYMBOL_COUNT: u32 = 8;
        const CORRUPTION_PERCENT: u64 = 5;
        const SEED: u64 = 0x5eed_f00d_d15c_a11;

        let total_blocks = u64::from(GROUP_COUNT) * u64::from(GROUP_BLOCK_COUNT);
        let device = MemBlockDevice::new(1024, total_blocks);

        let mut groups = Vec::new();
        let mut source_blocks = Vec::new();
        for group in 0..GROUP_COUNT {
            let group_first = u64::from(group) * u64::from(GROUP_BLOCK_COUNT);
            let layout = RepairGroupLayout::new(
                GroupNumber(group),
                BlockNumber(group_first),
                GROUP_BLOCK_COUNT,
                0,
                4,
            )
            .expect("layout");
            let source_first = BlockNumber(group_first);

            write_source_blocks(&cx, &device, source_first, SOURCE_BLOCK_COUNT);
            bootstrap_storage(
                &cx,
                &device,
                layout,
                source_first,
                SOURCE_BLOCK_COUNT,
                REPAIR_SYMBOL_COUNT,
            );

            groups.push(GroupConfig {
                layout,
                source_first_block: source_first,
                source_block_count: SOURCE_BLOCK_COUNT,
            });
            for idx in 0..u64::from(SOURCE_BLOCK_COUNT) {
                source_blocks.push(group_first + idx);
            }
        }

        let target_corrupt = (source_blocks.len()
            * usize::try_from(CORRUPTION_PERCENT).expect("percent fits"))
            / 100;
        assert_eq!(
            target_corrupt,
            usize::try_from(GROUP_COUNT).expect("group count fits")
        );

        let mut corrupt_blocks = Vec::with_capacity(target_corrupt);
        for group in 0..GROUP_COUNT {
            let group_first = u64::from(group) * u64::from(GROUP_BLOCK_COUNT);
            let offset = splitmix64(SEED ^ u64::from(group)) % u64::from(SOURCE_BLOCK_COUNT);
            corrupt_blocks.push(group_first + offset);
        }

        let before_hashes = block_hashes(&cx, &device, &source_blocks);

        for &block in &corrupt_blocks {
            let mut bytes = device
                .read_block(&cx, BlockNumber(block))
                .expect("read source block")
                .as_slice()
                .to_vec();
            let last = bytes.len().saturating_sub(1);
            bytes[0] ^= 0xA5;
            bytes[last] ^= 0x5A;
            device
                .write_block(&cx, BlockNumber(block), &bytes)
                .expect("inject corruption");
        }

        let validator = CorruptBlockValidator::new(corrupt_blocks.clone());
        let mut ledger_buf = Vec::new();
        let pipeline = ScrubWithRecovery::new(
            &device,
            &validator,
            test_uuid(),
            groups,
            &mut ledger_buf,
            REPAIR_SYMBOL_COUNT,
        );
        let mut daemon = ScrubDaemon::new(
            pipeline,
            ScrubDaemonConfig {
                interval: Duration::ZERO,
                cancel_check_interval: Duration::from_millis(1),
                ..ScrubDaemonConfig::default()
            },
        );

        let started = Instant::now();
        daemon.run_one_round(&cx).expect("daemon one round");
        let elapsed = started.elapsed();

        assert_eq!(
            daemon.metrics().blocks_corrupt_found,
            u64::try_from(corrupt_blocks.len()).expect("len fits u64")
        );
        assert_eq!(
            daemon.metrics().blocks_recovered,
            u64::try_from(corrupt_blocks.len()).expect("len fits u64")
        );
        assert_eq!(daemon.metrics().blocks_unrecoverable, 0);
        assert_eq!(daemon.metrics().scrub_rounds_completed, 1);

        let after_hashes = block_hashes(&cx, &device, &source_blocks);
        assert_eq!(before_hashes, after_hashes, "data mismatch after repair");

        let (pipeline, _metrics) = daemon.into_parts();
        let ledger_data = pipeline.into_ledger();
        let records = crate::evidence::parse_evidence_ledger(ledger_data);

        let corruption_detected = records
            .iter()
            .filter(|r| r.event_type == EvidenceEventType::CorruptionDetected)
            .count();
        let repair_attempted = records
            .iter()
            .filter(|r| r.event_type == EvidenceEventType::RepairAttempted)
            .count();
        let repair_succeeded = records
            .iter()
            .filter(|r| r.event_type == EvidenceEventType::RepairSucceeded)
            .count();
        let repair_failed = records
            .iter()
            .filter(|r| r.event_type == EvidenceEventType::RepairFailed)
            .count();
        let scrub_cycle_complete = records
            .iter()
            .filter(|r| r.event_type == EvidenceEventType::ScrubCycleComplete)
            .count();

        assert_eq!(corruption_detected, corrupt_blocks.len());
        assert_eq!(repair_attempted, corrupt_blocks.len());
        assert_eq!(repair_succeeded, corrupt_blocks.len());
        assert_eq!(repair_failed, 0);
        assert_eq!(scrub_cycle_complete, corrupt_blocks.len());
        assert!(
            elapsed <= Duration::from_secs(120),
            "repair e2e exceeded timeout: {:?}",
            elapsed
        );

        maybe_write_repair_e2e_artifacts(
            &before_hashes,
            &after_hashes,
            &corrupt_blocks,
            ledger_data,
            SEED,
            CORRUPTION_PERCENT,
        );
    }
}
