/// This service is to monitor tokio runtime (instead of the whole rust process).
/// The reason is...to monitor! `tokio_unstable` is on by default and I have no reason to refuse that.
/// Disable `tokio_unstable` feature, and maybe override flags if you are too -phobic and ith it's fine.
use std::time::Duration;

use opentelemetry::metrics::{Counter, Gauge};
use tokio_metrics::RuntimeMonitor;

use crate::{telemetry::get_meter, utils::spawn_named};

#[cfg(feature = "tokio_unstable")]
struct UnstableMetrics {
    noop_total: Counter<u64>,
    noop_max: Counter<u64>,
    noop_min: Counter<u64>,
    steal_total: Counter<u64>,
    steal_max: Counter<u64>,
    steal_min: Counter<u64>,
    steal_operations_total: Counter<u64>,
    steal_operations_max: Counter<u64>,
    steal_operations_min: Counter<u64>,
    remote_schedule: Counter<u64>,
    local_schedule_total: Counter<u64>,
    local_schedule_max: Counter<u64>,
    local_schedule_min: Counter<u64>,
    overflow_total: Counter<u64>,
    overflow_max: Counter<u64>,
    overflow_min: Counter<u64>,
    polls_total: Counter<u64>,
    polls_max: Counter<u64>,
    polls_min: Counter<u64>,
    local_queue_depth_total: Gauge<u64>,
    local_queue_depth_max: Gauge<u64>,
    local_queue_depth_min: Gauge<u64>,
    blocking_queue_depth: Gauge<u64>,
    tasks_live: Gauge<u64>,
    threads_blocking: Gauge<u64>,
    threads_blocking_idle: Gauge<u64>,
    budget_forced_yield: Counter<u64>,
    io_driver_ready: Counter<u64>,
    busy_ratio: Gauge<f64>,
    mean_polls_per_park: Gauge<f64>,
}

pub struct ProcessMetricsService {
    // Stable Runtime Metrics
    workers: Gauge<u64>,
    park_total: Gauge<u64>,
    park_max: Gauge<u64>,
    park_min: Gauge<u64>,
    busy_duration_total: Counter<u64>,
    busy_duration_max: Counter<u64>,
    busy_duration_min: Counter<u64>,
    queue_depth: Gauge<u64>,

    // Unstable Runtime Metrics

    // Task Metrics
    // instrumented_count: Counter<u64>,
    // dropped_count: Counter<u64>,
    // first_poll_count: Counter<u64>,
    // total_first_poll_delay: Histogram<f64>,
    // total_idled_count: Counter<u64>,
    // total_idle_duration: Histogram<f64>,
    // total_scheduled_count: Counter<u64>,
    // total_scheduled_duration: Histogram<f64>,
    // total_poll_count: Counter<u64>,
    // total_poll_duration: Histogram<f64>,
    // total_fast_poll_count: Counter<u64>,
    // total_fast_poll_duration: Histogram<f64>,
    // total_slow_poll_count: Counter<u64>,
    // total_slow_poll_duration: Histogram<f64>,
    // total_short_delay_count: Counter<u64>,
    // total_short_delay_duration: Histogram<f64>,
    // total_long_delay_count: Counter<u64>,
    // total_long_delay_duration: Histogram<f64>,
    #[cfg(feature = "tokio_unstable")]
    unstable: UnstableMetrics,

    // Internal monitors
    runtime_monitor: RuntimeMonitor,
    // task_monitor: TaskMonitor,
}

impl Default for ProcessMetricsService {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessMetricsService {
    #[must_use]
    pub fn new() -> Self {
        let meter = get_meter();
        let handle = tokio::runtime::Handle::current();

        #[cfg(feature = "tokio_unstable")]
        let unstable_metrics = UnstableMetrics {
            // Initialize unstable runtime metrics
            noop_total: meter
                .u64_counter("lure_runtime_noop_total")
                .with_unit("{noop}")
                .build(),
            noop_max: meter
                .u64_counter("lure_runtime_noop_max")
                .with_unit("{noop}")
                .build(),
            noop_min: meter
                .u64_counter("lure_runtime_noop_min")
                .with_unit("{noop}")
                .build(),
            steal_total: meter
                .u64_counter("lure_runtime_steal_total")
                .with_unit("{steal}")
                .build(),
            steal_max: meter
                .u64_counter("lure_runtime_steal_max")
                .with_unit("{steal}")
                .build(),
            steal_min: meter
                .u64_counter("lure_runtime_steal_min")
                .with_unit("{steal}")
                .build(),
            steal_operations_total: meter
                .u64_counter("lure_runtime_steal_operations_total")
                .with_unit("{operation}")
                .build(),
            steal_operations_max: meter
                .u64_counter("lure_runtime_steal_operations_max")
                .with_unit("{operation}")
                .build(),
            steal_operations_min: meter
                .u64_counter("lure_runtime_steal_operations_min")
                .with_unit("{operation}")
                .build(),
            remote_schedule: meter
                .u64_counter("lure_runtime_remote_schedule")
                .with_unit("{task}")
                .build(),
            local_schedule_total: meter
                .u64_counter("lure_runtime_local_schedule_total")
                .with_unit("{task}")
                .build(),
            local_schedule_max: meter
                .u64_counter("lure_runtime_local_schedule_max")
                .with_unit("{task}")
                .build(),
            local_schedule_min: meter
                .u64_counter("lure_runtime_local_schedule_min")
                .with_unit("{task}")
                .build(),
            overflow_total: meter
                .u64_counter("lure_runtime_overflow_total")
                .with_unit("{overflow}")
                .build(),
            overflow_max: meter
                .u64_counter("lure_runtime_overflow_max")
                .with_unit("{overflow}")
                .build(),
            overflow_min: meter
                .u64_counter("lure_runtime_overflow_min")
                .with_unit("{overflow}")
                .build(),
            polls_total: meter
                .u64_counter("lure_runtime_polls_total")
                .with_unit("{poll}")
                .build(),
            polls_max: meter
                .u64_counter("lure_runtime_polls_max")
                .with_unit("{poll}")
                .build(),
            polls_min: meter
                .u64_counter("lure_runtime_polls_min")
                .with_unit("{poll}")
                .build(),
            local_queue_depth_total: meter
                .u64_gauge("lure_runtime_local_queue_depth_total")
                .with_unit("{task}")
                .build(),
            local_queue_depth_max: meter
                .u64_gauge("lure_runtime_local_queue_depth_max")
                .with_unit("{task}")
                .build(),
            local_queue_depth_min: meter
                .u64_gauge("lure_runtime_local_queue_depth_min")
                .with_unit("{task}")
                .build(),
            blocking_queue_depth: meter
                .u64_gauge("lure_runtime_blocking_queue_depth")
                .with_unit("{task}")
                .build(),
            tasks_live: meter
                .u64_gauge("lure_runtime_tasks_live")
                .with_unit("{task}")
                .build(),
            threads_blocking: meter
                .u64_gauge("lure_runtime_threads_blocking")
                .with_unit("{thread}")
                .build(),
            threads_blocking_idle: meter
                .u64_gauge("lure_runtime_threads_blocking_idle")
                .with_unit("{thread}")
                .build(),
            budget_forced_yield: meter
                .u64_counter("lure_runtime_budget_forced_yield")
                .with_unit("{yield}")
                .build(),
            io_driver_ready: meter
                .u64_counter("lure_runtime_io_driver_ready")
                .with_unit("{event}")
                .build(),
            busy_ratio: meter
                .f64_gauge("lure_runtime_busy_ratio")
                .with_unit("1")
                .build(),
            mean_polls_per_park: meter
                .f64_gauge("lure_runtime_mean_polls_per_park")
                .with_unit("{poll}")
                .build(),
        };

        Self {
            // Initialize stable runtime metrics
            workers: meter
                .u64_gauge("lure_runtime_workers")
                .with_unit("{thread}")
                .build(),
            park_total: meter
                .u64_gauge("lure_runtime_park_total")
                .with_unit("{park}")
                .build(),
            park_max: meter
                .u64_gauge("lure_runtime_park_max")
                .with_unit("{park}")
                .build(),
            park_min: meter
                .u64_gauge("lure_runtime_park_min")
                .with_unit("{park}")
                .build(),
            busy_duration_total: meter
                .u64_counter("lure_runtime_busy_duration_total")
                .with_unit("us")
                .build(),
            busy_duration_max: meter
                .u64_counter("lure_runtime_busy_duration_max")
                .with_unit("us")
                .build(),
            busy_duration_min: meter
                .u64_counter("lure_runtime_busy_duration_min")
                .with_unit("us")
                .build(),
            queue_depth: meter
                .u64_gauge("lure_runtime_queue_depth")
                .with_unit("{task}")
                .build(),

            #[cfg(feature = "tokio_unstable")]
            unstable: unstable_metrics,
            // Initialize task metrics
            // instrumented_count: meter.u64_counter("lure_runtime_instrumented_count").with_unit("1").build(),
            // dropped_count: meter.u64_counter("lure_runtime_dropped_count").with_unit("1").build(),
            // first_poll_count: meter.u64_counter("lure_runtime_first_poll_count").with_unit("1").build(),
            // total_first_poll_delay: meter.f64_histogram("lure_runtime_total_first_poll_delay").with_unit("s").build(),
            // total_idled_count: meter.u64_counter("lure_runtime_total_idled_count").with_unit("1").build(),
            // total_idle_duration: meter.f64_histogram("lure_runtime_total_idle_duration").with_unit("s").build(),
            // total_scheduled_count: meter.u64_counter("lure_runtime_total_scheduled_count").with_unit("1").build(),
            // total_scheduled_duration: meter
            //     .f64_histogram("lure_runtime_total_scheduled_duration")
            //     .with_unit("s")
            //     .build(),
            // total_poll_count: meter.u64_counter("lure_runtime_total_poll_count").with_unit("1").build(),
            // total_poll_duration: meter.f64_histogram("lure_runtime_total_poll_duration").with_unit("s").build(),
            // total_fast_poll_count: meter.u64_counter("lure_runtime_total_fast_poll_count").with_unit("1").build(),
            // total_fast_poll_duration: meter
            //     .f64_histogram("lure_runtime_total_fast_poll_duration")
            //     .with_unit("s")
            //     .build(),
            // total_slow_poll_count: meter.u64_counter("lure_runtime_total_slow_poll_count").with_unit("1").build(),
            // total_slow_poll_duration: meter
            //     .f64_histogram("lure_runtime_total_slow_poll_duration")
            //     .with_unit("s")
            //     .build(),
            // total_short_delay_count: meter.u64_counter("lure_runtime_total_short_delay_count").with_unit("1").build(),
            // total_short_delay_duration: meter
            //     .f64_histogram("lure_runtime_total_short_delay_duration")
            //     .with_unit("s")
            //     .build(),
            // total_long_delay_count: meter.u64_counter("lure_runtime_total_long_delay_count").with_unit("1").build(),
            // total_long_delay_duration: meter
            //     .f64_histogram("lure_runtime_total_long_delay_duration")
            //     .with_unit("s")
            //     .build(),

            // Initialize monitors
            runtime_monitor: RuntimeMonitor::new(&handle),
            // task_monitor: TaskMonitor::new(),
        }
    }

    fn update_runtime_metrics(&self, metrics: &tokio_metrics::RuntimeMetrics) {
        // Common labels for all metrics
        let common_labels = &[];

        // Update stable runtime metrics with labels
        self.workers
            .record(metrics.workers_count as u64, common_labels);
        self.park_total
            .record(metrics.total_park_count, common_labels);
        self.park_max.record(metrics.max_park_count, common_labels);
        self.park_min.record(metrics.min_park_count, common_labels);
        self.busy_duration_total.add(
            metrics.total_busy_duration.as_micros() as u64,
            common_labels,
        );
        self.busy_duration_max
            .add(metrics.max_busy_duration.as_micros() as u64, common_labels);
        self.busy_duration_min
            .add(metrics.min_busy_duration.as_micros() as u64, common_labels);
        self.queue_depth
            .record(metrics.global_queue_depth as u64, common_labels);

        // Update unstable runtime metrics with labels
        #[cfg(feature = "tokio_unstable")]
        {
            // Noops metrics
            self.unstable
                .noop_total
                .add(metrics.total_noop_count, common_labels);
            self.unstable
                .noop_max
                .add(metrics.max_noop_count, common_labels);
            self.unstable
                .noop_min
                .add(metrics.min_noop_count, common_labels);

            // Steal metrics
            self.unstable
                .steal_total
                .add(metrics.total_steal_count, common_labels);
            self.unstable
                .steal_max
                .add(metrics.max_steal_count, common_labels);
            self.unstable
                .steal_min
                .add(metrics.min_steal_count, common_labels);
            self.unstable
                .steal_operations_total
                .add(metrics.total_steal_operations, common_labels);
            self.unstable
                .steal_operations_max
                .add(metrics.max_steal_operations, common_labels);
            self.unstable
                .steal_operations_min
                .add(metrics.min_steal_operations, common_labels);

            // Schedule metrics
            self.unstable
                .remote_schedule
                .add(metrics.num_remote_schedules, common_labels);
            self.unstable
                .local_schedule_total
                .add(metrics.total_local_schedule_count, common_labels);
            self.unstable
                .local_schedule_max
                .add(metrics.max_local_schedule_count, common_labels);
            self.unstable
                .local_schedule_min
                .add(metrics.min_local_schedule_count, common_labels);

            // Overflow metrics
            self.unstable
                .overflow_total
                .add(metrics.total_overflow_count, common_labels);
            self.unstable
                .overflow_max
                .add(metrics.max_overflow_count, common_labels);
            self.unstable
                .overflow_min
                .add(metrics.min_overflow_count, common_labels);

            // Poll metrics
            self.unstable
                .polls_total
                .add(metrics.total_polls_count, common_labels);
            self.unstable
                .polls_max
                .add(metrics.max_polls_count, common_labels);
            self.unstable
                .polls_min
                .add(metrics.min_polls_count, common_labels);

            self.unstable
                .local_queue_depth_total
                .record(metrics.total_local_queue_depth as u64, common_labels);
            self.unstable
                .local_queue_depth_max
                .record(metrics.max_local_queue_depth as u64, common_labels);
            self.unstable
                .local_queue_depth_min
                .record(metrics.min_local_queue_depth as u64, common_labels);
            self.unstable
                .blocking_queue_depth
                .record(metrics.blocking_queue_depth as u64, common_labels);

            // Task and thread metrics
            self.unstable
                .tasks_live
                .record(metrics.live_tasks_count as u64, common_labels);
            self.unstable
                .threads_blocking
                .record(metrics.blocking_threads_count as u64, common_labels);
            self.unstable
                .threads_blocking_idle
                .record(metrics.idle_blocking_threads_count as u64, common_labels);

            // Performance metrics
            self.unstable
                .budget_forced_yield
                .add(metrics.budget_forced_yield_count, common_labels);
            self.unstable
                .io_driver_ready
                .add(metrics.io_driver_ready_count, common_labels);

            // Derived metrics
            self.unstable
                .busy_ratio
                .record(metrics.busy_ratio(), common_labels);
            self.unstable
                .mean_polls_per_park
                .record(metrics.mean_polls_per_park(), common_labels);
        }
    }

    // fn update_task_metrics(&self, metrics: &tokio_metrics::TaskMetrics) {
    //     let common_labels = &[];
    //
    //     // Base metrics
    //     self.instrumented_count
    //         .add(metrics.instrumented_count, common_labels);
    //     self.dropped_count.add(metrics.dropped_count, common_labels);
    //     self.first_poll_count
    //         .add(metrics.first_poll_count, common_labels);
    //
    //     // Delay metrics
    //     self.total_first_poll_delay
    //         .record(metrics.total_first_poll_delay.as_secs_f64(), common_labels);
    //
    //     // Idle metrics
    //     self.total_idled_count
    //         .add(metrics.total_idled_count, common_labels);
    //     self.total_idle_duration
    //         .record(metrics.total_idle_duration.as_secs_f64(), common_labels);
    //
    //     // Schedule metrics
    //     self.total_scheduled_count
    //         .add(metrics.total_scheduled_count, common_labels);
    //     self.total_scheduled_duration.record(
    //         metrics.total_scheduled_duration.as_secs_f64(),
    //         common_labels,
    //     );
    //
    //     // Poll metrics
    //     self.total_poll_count
    //         .add(metrics.total_poll_count, common_labels);
    //     self.total_poll_duration
    //         .record(metrics.total_poll_duration.as_secs_f64(), common_labels);
    //
    //     // Fast/Slow poll metrics
    //     self.total_fast_poll_count
    //         .add(metrics.total_fast_poll_count, common_labels);
    //     self.total_fast_poll_duration.record(
    //         metrics.total_fast_poll_duration.as_secs_f64(),
    //         common_labels,
    //     );
    //     self.total_slow_poll_count
    //         .add(metrics.total_slow_poll_count, common_labels);
    //     self.total_slow_poll_duration.record(
    //         metrics.total_slow_poll_duration.as_secs_f64(),
    //         common_labels,
    //     );
    //
    //     // Delay count and duration metrics
    //     self.total_short_delay_count
    //         .add(metrics.total_short_delay_count, common_labels);
    //     self.total_short_delay_duration.record(
    //         metrics.total_short_delay_duration.as_secs_f64(),
    //         common_labels,
    //     );
    //     self.total_long_delay_count
    //         .add(metrics.total_long_delay_count, common_labels);
    //     self.total_long_delay_duration.record(
    //         metrics.total_long_delay_duration.as_secs_f64(),
    //         common_labels,
    //     );
    // }

    pub fn start(&'static self) {
        // Spawn runtime metrics collection task
        spawn_named("Runtime metrics", async move {
            for metrics in self.runtime_monitor.intervals() {
                self.update_runtime_metrics(&metrics);
                // currently I have no idea how to change otel report rate
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        })
        .unwrap();

        // Spawn task metrics collection task
        // tokio::spawn(async move {
        //     for metrics in self.task_monitor.intervals() {
        //         self.update_task_metrics(&metrics);
        //         tokio::time::sleep(Duration::from_secs(1)).await;
        //     }
        // });
    }

    // pub fn instrument<T>(&self, task: T) -> impl std::future::Future<Output = T::Output>
    // where
    //     T: std::future::Future,
    // {
    //     self.task_monitor.instrument(task)
    // }
    //
    // pub fn instrument_batch<I, F, Fut>(&self, tasks: I) -> Vec<impl std::future::Future<Output = Fut::Output>>
    // where
    //     I: IntoIterator<Item = F>,
    //     F: FnOnce() -> Fut,
    //     Fut: std::future::Future,
    // {
    //     tasks.into_iter()
    //         .map(|task| self.instrument(task()))
    //         .collect()
    // }
}
