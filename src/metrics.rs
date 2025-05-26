use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Histogram for tracking value distributions
#[derive(Debug, Clone, Default)]
struct Histogram {
    buckets: Vec<u64>,
    min: f64,
    max: f64,
    sum: f64,
    count: u64,
}

impl Histogram {
    fn new(bucket_count: usize) -> Self {
        Self {
            buckets: vec![0; bucket_count],
            min: f64::MAX,
            max: f64::MIN,
            sum: 0.0,
            count: 0,
        }
    }

    fn record(&mut self, value: f64) {
        self.min = self.min.min(value);
        self.max = self.max.max(value);
        self.sum += value;
        self.count += 1;

        let bucket_index = (value / self.max * (self.buckets.len() - 1) as f64) as usize;
        if bucket_index < self.buckets.len() {
            self.buckets[bucket_index] += 1;
        }
    }

    fn percentile(&self, p: f64) -> Option<f64> {
        if self.count == 0 {
            return None;
        }

        let target_count = (self.count as f64 * p) as u64;
        let mut current_count = 0;
        
        for (i, &count) in self.buckets.iter().enumerate() {
            current_count += count;
            if current_count >= target_count {
                let bucket_size = self.max / self.buckets.len() as f64;
                return Some(i as f64 * bucket_size);
            }
        }
        
        Some(self.max)
    }
}

/// Metrics collection for RustZkrypt
#[derive(Debug, Clone, Default)]
pub struct Metrics {
    /// Operation counters
    counters: Arc<RwLock<HashMap<String, u64>>>,
    /// Operation timings
    timings: Arc<RwLock<HashMap<String, Vec<Duration>>>>,
    /// Error counts
    errors: Arc<RwLock<HashMap<String, u64>>>,
    /// Histograms for value distributions
    histograms: Arc<RwLock<HashMap<String, Histogram>>>,
    /// Start time of the metrics collection
    start_time: Instant,
}

/// Metrics snapshot for reporting
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Operation counts
    pub counters: HashMap<String, u64>,
    /// Average operation timings
    pub avg_timings: HashMap<String, Duration>,
    /// Error counts
    pub errors: HashMap<String, u64>,
    /// Histogram statistics
    pub histograms: HashMap<String, HistogramStats>,
    /// Uptime in seconds
    pub uptime: u64,
}

/// Statistics for histogram data
#[derive(Debug, Serialize, Deserialize)]
pub struct HistogramStats {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
}

impl Metrics {
    /// Create new metrics collector
    pub fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            timings: Arc::new(RwLock::new(HashMap::new())),
            errors: Arc::new(RwLock::new(HashMap::new())),
            histograms: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
        }
    }

    /// Increment a counter
    pub fn increment(&self, name: &str) {
        let mut counters = self.counters.write().unwrap();
        *counters.entry(name.to_string()).or_insert(0) += 1;
    }

    /// Record operation timing
    pub fn record_timing(&self, name: &str, duration: Duration) {
        let mut timings = self.timings.write().unwrap();
        timings
            .entry(name.to_string())
            .or_insert_with(Vec::new)
            .push(duration);
    }

    /// Record an error
    pub fn record_error(&self, name: &str) {
        let mut errors = self.errors.write().unwrap();
        *errors.entry(name.to_string()).or_insert(0) += 1;
        warn!("Error recorded for operation: {}", name);
    }

    /// Record a value in a histogram
    pub fn record_histogram(&self, name: &str, value: f64) {
        let mut histograms = self.histograms.write().unwrap();
        let histogram = histograms
            .entry(name.to_string())
            .or_insert_with(|| Histogram::new(100));
        histogram.record(value);
    }

    /// Get current metrics snapshot
    pub fn snapshot(&self) -> MetricsSnapshot {
        let counters = self.counters.read().unwrap().clone();
        let errors = self.errors.read().unwrap().clone();
        
        // Calculate average timings
        let mut avg_timings = HashMap::new();
        let timings = self.timings.read().unwrap();
        
        for (name, durations) in timings.iter() {
            if !durations.is_empty() {
                let avg = durations.iter().sum::<Duration>() / durations.len() as u32;
                avg_timings.insert(name.clone(), avg);
            }
        }

        // Calculate histogram statistics
        let mut histogram_stats = HashMap::new();
        let histograms = self.histograms.read().unwrap();
        
        for (name, histogram) in histograms.iter() {
            if histogram.count > 0 {
                histogram_stats.insert(name.clone(), HistogramStats {
                    min: histogram.min,
                    max: histogram.max,
                    avg: histogram.sum / histogram.count as f64,
                    p50: histogram.percentile(0.5).unwrap_or(0.0),
                    p95: histogram.percentile(0.95).unwrap_or(0.0),
                    p99: histogram.percentile(0.99).unwrap_or(0.0),
                });
            }
        }
        
        MetricsSnapshot {
            counters,
            avg_timings,
            errors,
            histograms: histogram_stats,
            uptime: self.start_time.elapsed().as_secs(),
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        *self.counters.write().unwrap() = HashMap::new();
        *self.timings.write().unwrap() = HashMap::new();
        *self.errors.write().unwrap() = HashMap::new();
        *self.histograms.write().unwrap() = HashMap::new();
        info!("Metrics reset");
    }

    /// Get operation success rate
    pub fn success_rate(&self, operation: &str) -> f64 {
        let counters = self.counters.read().unwrap();
        let errors = self.errors.read().unwrap();
        
        let total = counters.get(operation).copied().unwrap_or(0);
        let error_count = errors.get(operation).copied().unwrap_or(0);
        
        if total == 0 {
            0.0
        } else {
            (total - error_count) as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_metrics_basic() {
        let metrics = Metrics::new();
        
        // Test counter
        metrics.increment("test_op");
        metrics.increment("test_op");
        assert_eq!(metrics.snapshot().counters["test_op"], 2);
        
        // Test timing
        metrics.record_timing("test_timing", Duration::from_millis(100));
        metrics.record_timing("test_timing", Duration::from_millis(200));
        assert_eq!(
            metrics.snapshot().avg_timings["test_timing"],
            Duration::from_millis(150)
        );
        
        // Test errors
        metrics.record_error("test_op");
        assert_eq!(metrics.snapshot().errors["test_op"], 1);
        
        // Test success rate
        assert_eq!(metrics.success_rate("test_op"), 0.5);
    }

    #[test]
    fn test_metrics_thread_safety() {
        let metrics = Arc::new(Metrics::new());
        let mut handles = vec![];
        
        // Spawn multiple threads to modify metrics
        for i in 0..4 {
            let metrics = metrics.clone();
            handles.push(thread::spawn(move || {
                metrics.increment("thread_op");
                metrics.record_timing("thread_timing", Duration::from_millis(100));
                if i % 2 == 0 {
                    metrics.record_error("thread_op");
                }
            }));
        }
        
        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify results
        assert_eq!(metrics.snapshot().counters["thread_op"], 4);
        assert_eq!(metrics.snapshot().errors["thread_op"], 2);
        assert_eq!(metrics.success_rate("thread_op"), 0.5);
    }

    #[test]
    fn test_histogram_metrics() {
        let metrics = Metrics::new();
        
        // Record some values
        metrics.record_histogram("test_hist", 10.0);
        metrics.record_histogram("test_hist", 20.0);
        metrics.record_histogram("test_hist", 30.0);
        
        let snapshot = metrics.snapshot();
        let stats = &snapshot.histograms["test_hist"];
        
        assert_eq!(stats.min, 10.0);
        assert_eq!(stats.max, 30.0);
        assert_eq!(stats.avg, 20.0);
        assert!(stats.p50 > 0.0);
        assert!(stats.p95 > 0.0);
        assert!(stats.p99 > 0.0);
    }
} 