#![forbid(unsafe_code)]
//! TUI monitoring and management for FrankenFS.
//!
//! Live dashboard showing ARC cache hit rates, MVCC version chain depths,
//! active transaction counts, RaptorQ repair status, I/O throughput, and
//! block group health. Built on frankentui.

use ftui::layout::{Constraint, Flex, Rect};
use ftui::render::frame::Frame;
use ftui::widgets::Widget;
use ftui::widgets::block::Block;
use ftui::widgets::paragraph::Paragraph;
use ftui::{Cmd, Event, KeyCode, Model};

// ── Metric snapshot ─────────────────────────────────────────────────────────

/// Point-in-time snapshot of all metrics displayed by the dashboard.
///
/// This is a plain data struct with no dependencies on internal subsystem
/// crates (ffs-block, ffs-mvcc, ffs-repair). The caller populates it from
/// whatever metric sources are available.
#[derive(Debug, Clone, Default)]
pub struct DashboardSnapshot {
    // ARC cache
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_evictions: u64,
    pub cache_resident: usize,
    pub cache_capacity: usize,
    pub cache_t1_len: usize,
    pub cache_t2_len: usize,

    // MVCC
    pub mvcc_snapshot_seq: u64,
    pub mvcc_active_snapshots: usize,
    pub mvcc_watermark: Option<u64>,
    pub mvcc_version_count: usize,
    pub mvcc_versioned_blocks: usize,

    // Scrub
    pub scrub_blocks_scanned: u64,
    pub scrub_blocks_corrupt: u64,
    pub scrub_blocks_io_error: u64,
    pub scrub_findings_count: usize,
}

impl DashboardSnapshot {
    /// Cache hit ratio in the range [0.0, 1.0].
    #[must_use]
    pub fn cache_hit_ratio(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }
}

// ── Dashboard model ─────────────────────────────────────────────────────────

/// Message type for the dashboard model.
#[derive(Debug)]
pub enum DashboardMsg {
    /// Terminal input event.
    Input(Event),
    /// New metrics arrived.
    MetricsUpdated(DashboardSnapshot),
}

impl From<Event> for DashboardMsg {
    fn from(event: Event) -> Self {
        Self::Input(event)
    }
}

/// FrankenFS monitoring dashboard.
///
/// Implements [`ftui::Model`] so it can be driven by the ftui runtime.
/// Call [`Dashboard::update_metrics`] to push new metric snapshots, or
/// send a [`DashboardMsg::MetricsUpdated`] message through the runtime.
#[derive(Debug)]
pub struct Dashboard {
    snapshot: DashboardSnapshot,
}

impl Dashboard {
    /// Create a new dashboard with default (zeroed) metrics.
    #[must_use]
    pub fn new() -> Self {
        Self {
            snapshot: DashboardSnapshot::default(),
        }
    }

    /// Create a dashboard pre-populated with a metrics snapshot.
    #[must_use]
    pub fn with_snapshot(snapshot: DashboardSnapshot) -> Self {
        Self { snapshot }
    }

    /// Replace the current metrics snapshot.
    pub fn update_metrics(&mut self, snapshot: DashboardSnapshot) {
        self.snapshot = snapshot;
    }

    /// Current snapshot (for testing / inspection).
    #[must_use]
    pub fn snapshot(&self) -> &DashboardSnapshot {
        &self.snapshot
    }
}

impl Default for Dashboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Model for Dashboard {
    type Message = DashboardMsg;

    fn update(&mut self, msg: Self::Message) -> Cmd<Self::Message> {
        match msg {
            DashboardMsg::Input(Event::Key(key)) => {
                if matches!(key.code, KeyCode::Char('q' | 'Q')) || key.code == KeyCode::Escape {
                    return Cmd::quit();
                }
                Cmd::none()
            }
            DashboardMsg::MetricsUpdated(snap) => {
                self.snapshot = snap;
                Cmd::none()
            }
            DashboardMsg::Input(_) => Cmd::none(),
        }
    }

    fn view(&self, frame: &mut Frame) {
        let bounds = Rect {
            x: 0,
            y: 0,
            width: frame.buffer.width(),
            height: frame.buffer.height(),
        };

        let rows = Flex::vertical()
            .constraints([Constraint::Percentage(50.0), Constraint::Percentage(50.0)])
            .split(bounds);

        // Top row: cache + MVCC side by side
        let top_cols = Flex::horizontal()
            .constraints([Constraint::Percentage(50.0), Constraint::Percentage(50.0)])
            .split(rows[0]);

        render_cache_panel(&self.snapshot, top_cols[0], frame);
        render_mvcc_panel(&self.snapshot, top_cols[1], frame);

        // Bottom row: scrub status (full width)
        render_scrub_panel(&self.snapshot, rows[1], frame);
    }
}

// ── Panel renderers ─────────────────────────────────────────────────────────

fn render_cache_panel(snap: &DashboardSnapshot, area: Rect, frame: &mut Frame) {
    let block = Block::bordered().title("ARC Cache");
    let inner = block.inner(area);
    block.render(area, frame);

    let hit_pct = snap.cache_hit_ratio() * 100.0;
    let text = format!(
        "Hit ratio:  {hit_pct:>6.1}%\n\
         Hits:       {:>10}\n\
         Misses:     {:>10}\n\
         Evictions:  {:>10}\n\
         Resident:   {:>6} / {}\n\
         T1 / T2:    {} / {}",
        snap.cache_hits,
        snap.cache_misses,
        snap.cache_evictions,
        snap.cache_resident,
        snap.cache_capacity,
        snap.cache_t1_len,
        snap.cache_t2_len,
    );
    Paragraph::new(text).render(inner, frame);
}

fn render_mvcc_panel(snap: &DashboardSnapshot, area: Rect, frame: &mut Frame) {
    let block = Block::bordered().title("MVCC");
    let inner = block.inner(area);
    block.render(area, frame);

    let wm = snap
        .mvcc_watermark
        .map_or_else(|| "-".to_owned(), |w| w.to_string());
    let text = format!(
        "Snapshot:    {:>10}\n\
         Active snap: {:>10}\n\
         Watermark:   {:>10}\n\
         Versions:    {:>10}\n\
         Blocks (v):  {:>10}",
        snap.mvcc_snapshot_seq,
        snap.mvcc_active_snapshots,
        wm,
        snap.mvcc_version_count,
        snap.mvcc_versioned_blocks,
    );
    Paragraph::new(text).render(inner, frame);
}

fn render_scrub_panel(snap: &DashboardSnapshot, area: Rect, frame: &mut Frame) {
    let block = Block::bordered().title("Scrub / Repair");
    let inner = block.inner(area);
    block.render(area, frame);

    let status = if snap.scrub_blocks_scanned == 0 {
        "No scrub data"
    } else if snap.scrub_blocks_corrupt == 0 && snap.scrub_blocks_io_error == 0 {
        "Clean"
    } else {
        "Issues found"
    };
    let text = format!(
        "Status:       {status}\n\
         Scanned:      {:>10}\n\
         Corrupt:      {:>10}\n\
         I/O errors:   {:>10}\n\
         Findings:     {:>10}",
        snap.scrub_blocks_scanned,
        snap.scrub_blocks_corrupt,
        snap.scrub_blocks_io_error,
        snap.scrub_findings_count,
    );
    Paragraph::new(text).render(inner, frame);
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_snapshot_default_is_zeroed() {
        let snap = DashboardSnapshot::default();
        assert_eq!(snap.cache_hits, 0);
        assert_eq!(snap.cache_misses, 0);
        assert_eq!(snap.cache_evictions, 0);
        assert_eq!(snap.cache_resident, 0);
        assert_eq!(snap.cache_capacity, 0);
        assert_eq!(snap.mvcc_snapshot_seq, 0);
        assert_eq!(snap.mvcc_active_snapshots, 0);
        assert!(snap.mvcc_watermark.is_none());
        assert_eq!(snap.scrub_blocks_scanned, 0);
        assert_eq!(snap.scrub_findings_count, 0);
    }

    #[test]
    fn hit_ratio_zero_when_no_accesses() {
        let snap = DashboardSnapshot::default();
        assert!((snap.cache_hit_ratio()).abs() < f64::EPSILON);
    }

    #[test]
    fn hit_ratio_computed_correctly() {
        let snap = DashboardSnapshot {
            cache_hits: 75,
            cache_misses: 25,
            ..Default::default()
        };
        assert!((snap.cache_hit_ratio() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn dashboard_new_has_zeroed_snapshot() {
        let dash = Dashboard::new();
        assert_eq!(dash.snapshot().cache_hits, 0);
    }

    #[test]
    fn dashboard_with_snapshot() {
        let snap = DashboardSnapshot {
            cache_hits: 42,
            ..Default::default()
        };
        let dash = Dashboard::with_snapshot(snap);
        assert_eq!(dash.snapshot().cache_hits, 42);
    }

    #[test]
    fn dashboard_update_metrics() {
        let mut dash = Dashboard::new();
        dash.update_metrics(DashboardSnapshot {
            mvcc_version_count: 10,
            ..Default::default()
        });
        assert_eq!(dash.snapshot().mvcc_version_count, 10);
    }

    #[test]
    fn dashboard_update_metrics_via_msg() {
        let mut dash = Dashboard::new();
        let snap = DashboardSnapshot {
            scrub_blocks_scanned: 1000,
            ..Default::default()
        };
        let cmd = dash.update(DashboardMsg::MetricsUpdated(snap));
        assert!(matches!(cmd, Cmd::None));
        assert_eq!(dash.snapshot().scrub_blocks_scanned, 1000);
    }

    #[test]
    fn dashboard_quit_on_q() {
        let mut dash = Dashboard::new();
        let key = ftui::KeyEvent {
            code: KeyCode::Char('q'),
            kind: ftui::KeyEventKind::Press,
            modifiers: ftui::Modifiers::empty(),
        };
        let cmd = dash.update(DashboardMsg::Input(Event::Key(key)));
        assert!(matches!(cmd, Cmd::Quit));
    }

    #[test]
    fn dashboard_quit_on_esc() {
        let mut dash = Dashboard::new();
        let key = ftui::KeyEvent {
            code: KeyCode::Escape,
            kind: ftui::KeyEventKind::Press,
            modifiers: ftui::Modifiers::empty(),
        };
        let cmd = dash.update(DashboardMsg::Input(Event::Key(key)));
        assert!(matches!(cmd, Cmd::Quit));
    }

    #[test]
    fn dashboard_ignores_other_keys() {
        let mut dash = Dashboard::new();
        let key = ftui::KeyEvent {
            code: KeyCode::Char('a'),
            kind: ftui::KeyEventKind::Press,
            modifiers: ftui::Modifiers::empty(),
        };
        let cmd = dash.update(DashboardMsg::Input(Event::Key(key)));
        assert!(matches!(cmd, Cmd::None));
    }

    #[test]
    fn dashboard_view_does_not_panic_on_small_buffer() {
        let mut dash = Dashboard::new();
        dash.update_metrics(DashboardSnapshot {
            cache_hits: 100,
            cache_misses: 50,
            cache_evictions: 10,
            cache_resident: 80,
            cache_capacity: 100,
            cache_t1_len: 30,
            cache_t2_len: 50,
            mvcc_snapshot_seq: 42,
            mvcc_active_snapshots: 3,
            mvcc_watermark: Some(38),
            mvcc_version_count: 200,
            mvcc_versioned_blocks: 50,
            scrub_blocks_scanned: 10000,
            scrub_blocks_corrupt: 2,
            scrub_blocks_io_error: 1,
            scrub_findings_count: 5,
        });

        // Render into a small buffer — should not panic.
        let mut pool = ftui::GraphemePool::new();
        let mut frame = Frame::new(40, 20, &mut pool);
        dash.view(&mut frame);
    }

    #[test]
    fn dashboard_view_does_not_panic_tiny_buffer() {
        let dash = Dashboard::new();
        let mut pool = ftui::GraphemePool::new();
        // Minimum 1x1 — ftui panics on 0x0 buffers.
        let mut frame = Frame::new(1, 1, &mut pool);
        dash.view(&mut frame);
    }
}
