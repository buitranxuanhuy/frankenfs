#![forbid(unsafe_code)]
//! TUI monitoring and management for FrankenFS.
//!
//! Live dashboard showing ARC cache hit rates, MVCC version chain depths,
//! active transaction counts, RaptorQ repair status, I/O throughput, and
//! block group health. Built on frankentui.

use ffs::DegradationLevel;
use ftui::layout::{Constraint, Flex, Rect};
use ftui::render::frame::Frame;
use ftui::text::{Line, Span, Text};
use ftui::widgets::Widget;
use ftui::widgets::block::Block;
use ftui::widgets::paragraph::Paragraph;
use ftui::{Cmd, Event, KeyCode, Model, PackedRgba, Style};

const PRESSURE_BAR_WIDTH: usize = 10;
const MAX_RECENT_EVENTS: usize = 10;
const IO_QUEUE_PRESSURE_CAP: usize = 64;

// ── Metric snapshot ─────────────────────────────────────────────────────────

/// Point-in-time snapshot of all metrics displayed by the dashboard.
///
/// This is a plain data struct with no dependencies on internal subsystem
/// crates (ffs-block, ffs-mvcc, ffs-repair). The caller populates it from
/// whatever metric sources are available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradationEvent {
    pub timestamp: String,
    pub from: DegradationLevel,
    pub to: DegradationLevel,
    pub reason: String,
}

#[derive(Debug, Clone)]
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

    // Degradation / pressure
    pub degradation_level: DegradationLevel,
    /// Fraction in [0.0, 1.0].
    pub cpu_pressure: f64,
    /// Fraction in [0.0, 1.0].
    pub memory_pressure: f64,
    /// Current I/O queue depth (converted to pressure gauge via cap).
    pub io_queue_depth: usize,
    /// Recent transitions (newest is expected at the end of this vector).
    pub degradation_events: Vec<DegradationEvent>,

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

    /// Queue-depth-derived I/O pressure in [0.0, 1.0].
    #[must_use]
    pub fn io_pressure(&self) -> f64 {
        let normalized = self.io_queue_depth as f64 / IO_QUEUE_PRESSURE_CAP as f64;
        normalized_pressure(normalized)
    }
}

impl Default for DashboardSnapshot {
    fn default() -> Self {
        Self {
            cache_hits: 0,
            cache_misses: 0,
            cache_evictions: 0,
            cache_resident: 0,
            cache_capacity: 0,
            cache_t1_len: 0,
            cache_t2_len: 0,
            mvcc_snapshot_seq: 0,
            mvcc_active_snapshots: 0,
            mvcc_watermark: None,
            mvcc_version_count: 0,
            mvcc_versioned_blocks: 0,
            degradation_level: DegradationLevel::Normal,
            cpu_pressure: 0.0,
            memory_pressure: 0.0,
            io_queue_depth: 0,
            degradation_events: Vec::new(),
            scrub_blocks_scanned: 0,
            scrub_blocks_corrupt: 0,
            scrub_blocks_io_error: 0,
            scrub_findings_count: 0,
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
            .constraints([
                Constraint::Percentage(35.0),
                Constraint::Percentage(35.0),
                Constraint::Percentage(30.0),
            ])
            .split(bounds);

        // Top row: cache + MVCC side by side
        let top_cols = Flex::horizontal()
            .constraints([Constraint::Percentage(50.0), Constraint::Percentage(50.0)])
            .split(rows[0]);

        render_cache_panel(&self.snapshot, top_cols[0], frame);
        render_mvcc_panel(&self.snapshot, top_cols[1], frame);

        render_system_health_panel(&self.snapshot, rows[1], frame);
        render_scrub_panel(&self.snapshot, rows[2], frame);
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

fn render_system_health_panel(snap: &DashboardSnapshot, area: Rect, frame: &mut Frame) {
    let block = Block::bordered().title("System Health");
    let inner = block.inner(area);
    block.render(area, frame);
    Paragraph::new(build_system_health_text(snap)).render(inner, frame);
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

fn build_system_health_text(snap: &DashboardSnapshot) -> Text {
    let (level_name, level_num) = degradation_level_label(snap.degradation_level);
    let level_span = Span::styled(
        format!("{level_name} (L{level_num})"),
        degradation_level_style(snap.degradation_level),
    );

    let mut lines = vec![
        Line::from_spans([Span::raw("Degradation: "), level_span]),
        Line::raw(""),
        Line::raw(format!(
            "CPU:    {}",
            render_pressure_gauge(snap.cpu_pressure, PRESSURE_BAR_WIDTH)
        )),
        Line::raw(format!(
            "Memory: {}",
            render_pressure_gauge(snap.memory_pressure, PRESSURE_BAR_WIDTH)
        )),
        Line::raw(format!(
            "I/O:    {} depth={}",
            render_pressure_gauge(snap.io_pressure(), PRESSURE_BAR_WIDTH),
            snap.io_queue_depth
        )),
        Line::raw(""),
        Line::raw("Recent events:"),
    ];

    if snap.degradation_events.is_empty() {
        lines.push(Line::raw("  (none)"));
    } else {
        for event in snap.degradation_events.iter().rev().take(MAX_RECENT_EVENTS) {
            lines.push(Line::raw(format!("  {}", format_degradation_event(event))));
        }
    }

    Text::from_lines(lines)
}

#[must_use]
fn degradation_level_label(level: DegradationLevel) -> (&'static str, u8) {
    match level {
        DegradationLevel::Normal => ("NORMAL", 0),
        DegradationLevel::Warning => ("BACKGROUND PAUSED", 1),
        DegradationLevel::Degraded => ("CACHE REDUCED", 2),
        DegradationLevel::Critical => ("WRITES THROTTLED", 3),
        DegradationLevel::Emergency => ("READ-ONLY", 4),
    }
}

#[must_use]
fn degradation_level_style(level: DegradationLevel) -> Style {
    match level {
        DegradationLevel::Normal => Style::new().fg(PackedRgba::rgb(63, 191, 104)).bold(),
        DegradationLevel::Warning => Style::new().fg(PackedRgba::rgb(241, 196, 15)).bold(),
        DegradationLevel::Degraded => Style::new().fg(PackedRgba::rgb(255, 165, 0)).bold(),
        DegradationLevel::Critical => Style::new().fg(PackedRgba::rgb(255, 69, 58)).bold(),
        DegradationLevel::Emergency => Style::new().fg(PackedRgba::rgb(255, 0, 0)).bold().blink(),
    }
}

#[must_use]
fn format_degradation_event(event: &DegradationEvent) -> String {
    let (_, from_level) = degradation_level_label(event.from);
    let (_, to_level) = degradation_level_label(event.to);
    if event.reason.is_empty() {
        format!("{} L{} -> L{}", event.timestamp, from_level, to_level)
    } else {
        format!(
            "{} L{} -> L{} ({})",
            event.timestamp, from_level, to_level, event.reason
        )
    }
}

#[must_use]
fn normalized_pressure(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[must_use]
fn render_pressure_gauge(value: f64, width: usize) -> String {
    let normalized = normalized_pressure(value);
    let filled = ((normalized * width as f64).round() as usize).min(width);
    let percent = (normalized * 100.0).round() as u32;
    format!(
        "[{}{}] {:>3}%",
        "#".repeat(filled),
        ".".repeat(width - filled),
        percent
    )
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
        assert_eq!(snap.degradation_level, DegradationLevel::Normal);
        assert!((snap.cpu_pressure - 0.0).abs() < f64::EPSILON);
        assert!((snap.memory_pressure - 0.0).abs() < f64::EPSILON);
        assert_eq!(snap.io_queue_depth, 0);
        assert!(snap.degradation_events.is_empty());
        assert_eq!(snap.scrub_blocks_scanned, 0);
        assert_eq!(snap.scrub_findings_count, 0);
    }

    #[test]
    fn pressure_gauge_formats_and_clamps() {
        assert_eq!(render_pressure_gauge(-1.0, 10), "[..........]   0%");
        assert_eq!(render_pressure_gauge(0.5, 10), "[#####.....]  50%");
        assert_eq!(render_pressure_gauge(1.5, 10), "[##########] 100%");
    }

    #[test]
    fn degradation_level_style_matches_expected_color() {
        assert_eq!(
            degradation_level_style(DegradationLevel::Normal).fg,
            Some(PackedRgba::rgb(63, 191, 104))
        );
        assert_eq!(
            degradation_level_style(DegradationLevel::Warning).fg,
            Some(PackedRgba::rgb(241, 196, 15))
        );
        assert_eq!(
            degradation_level_style(DegradationLevel::Degraded).fg,
            Some(PackedRgba::rgb(255, 165, 0))
        );
        assert_eq!(
            degradation_level_style(DegradationLevel::Critical).fg,
            Some(PackedRgba::rgb(255, 69, 58))
        );
        let emergency_style = degradation_level_style(DegradationLevel::Emergency);
        assert_eq!(emergency_style.fg, Some(PackedRgba::rgb(255, 0, 0)));
        assert!(
            emergency_style
                .attrs
                .is_some_and(|attrs| attrs.contains(ftui::StyleFlags::BLINK))
        );
    }

    #[test]
    fn system_health_text_includes_recent_events() {
        let snap = DashboardSnapshot {
            degradation_level: DegradationLevel::Critical,
            cpu_pressure: 0.78,
            memory_pressure: 0.62,
            io_queue_depth: 22,
            degradation_events: vec![
                DegradationEvent {
                    timestamp: "12:34:05".to_owned(),
                    from: DegradationLevel::Normal,
                    to: DegradationLevel::Warning,
                    reason: "cpu".to_owned(),
                },
                DegradationEvent {
                    timestamp: "12:35:22".to_owned(),
                    from: DegradationLevel::Warning,
                    to: DegradationLevel::Normal,
                    reason: String::new(),
                },
            ],
            ..Default::default()
        };

        let text = build_system_health_text(&snap).to_plain_text();
        assert!(text.contains("Degradation: WRITES THROTTLED (L3)"));
        assert!(text.contains("CPU:    [########..]  78%"));
        assert!(text.contains("Memory: [######....]  62%"));
        assert!(text.contains("Recent events:"));
        assert!(text.contains("12:35:22 L1 -> L0"));
        assert!(text.contains("12:34:05 L0 -> L1 (cpu)"));
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
            degradation_level: DegradationLevel::Warning,
            cpu_pressure: 0.4,
            memory_pressure: 0.2,
            io_queue_depth: 6,
            degradation_events: vec![DegradationEvent {
                timestamp: "12:34:05".to_owned(),
                from: DegradationLevel::Normal,
                to: DegradationLevel::Warning,
                reason: "cpu".to_owned(),
            }],
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
