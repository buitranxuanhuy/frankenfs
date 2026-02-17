#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RegressionThreshold {
    pub warn_percent: f64,
    pub fail_percent: f64,
}

impl RegressionThreshold {
    #[must_use]
    pub const fn new(warn_percent: f64, fail_percent: f64) -> Self {
        Self {
            warn_percent,
            fail_percent,
        }
    }
}

impl Default for RegressionThreshold {
    fn default() -> Self {
        Self::new(10.0, 20.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegressionStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RegressionOutcome {
    pub status: RegressionStatus,
    pub delta_percent: f64,
}

/// Compare current p99 latency against a baseline and classify the result.
///
/// Returns `None` when `baseline_ms` is not positive, because a ratio would
/// be undefined for threshold evaluation.
#[must_use]
pub fn classify_latency_regression(
    baseline_ms: f64,
    current_ms: f64,
    threshold: RegressionThreshold,
) -> Option<RegressionOutcome> {
    if baseline_ms <= 0.0 {
        return None;
    }

    let delta_percent = ((current_ms - baseline_ms) / baseline_ms) * 100.0;
    let status = if delta_percent > threshold.fail_percent {
        RegressionStatus::Fail
    } else if delta_percent > threshold.warn_percent {
        RegressionStatus::Warn
    } else {
        RegressionStatus::Ok
    };

    Some(RegressionOutcome {
        status,
        delta_percent,
    })
}

#[cfg(test)]
mod tests {
    use super::{RegressionStatus, RegressionThreshold, classify_latency_regression};

    #[test]
    fn classify_returns_none_for_non_positive_baseline() {
        let threshold = RegressionThreshold::default();
        assert!(classify_latency_regression(0.0, 10.0, threshold).is_none());
        assert!(classify_latency_regression(-1.0, 10.0, threshold).is_none());
    }

    #[test]
    fn classify_ok_when_within_warn_threshold() {
        let threshold = RegressionThreshold::new(10.0, 20.0);
        let outcome = classify_latency_regression(100.0, 108.0, threshold)
            .expect("positive baseline should produce an outcome");
        assert_eq!(outcome.status, RegressionStatus::Ok);
    }

    #[test]
    fn classify_warn_when_above_warn_below_fail() {
        let threshold = RegressionThreshold::new(10.0, 20.0);
        let outcome = classify_latency_regression(100.0, 112.0, threshold)
            .expect("positive baseline should produce an outcome");
        assert_eq!(outcome.status, RegressionStatus::Warn);
    }

    #[test]
    fn classify_fail_when_above_fail_threshold() {
        let threshold = RegressionThreshold::new(10.0, 20.0);
        let outcome = classify_latency_regression(100.0, 130.0, threshold)
            .expect("positive baseline should produce an outcome");
        assert_eq!(outcome.status, RegressionStatus::Fail);
    }
}
