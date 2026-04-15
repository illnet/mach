pub mod inspect;
pub mod metrics;
pub mod oltp;
pub mod process;

use opentelemetry::{global, global::BoxedTracer, metrics::Meter, trace::TracerProvider};

/// Returns named OpenTelemetry meter for Lure runtime metrics.
#[must_use]
pub fn get_meter() -> Meter {
    global::meter_provider().meter("mach")
}

/// Returns named OpenTelemetry tracer for Lure runtime spans.
#[must_use]
pub fn get_tracer() -> BoxedTracer {
    global::tracer_provider().tracer("mach")
}
