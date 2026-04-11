pub mod inspect;
pub mod metrics;
pub mod oltp;
pub mod process;

use opentelemetry::{global, global::BoxedTracer, metrics::Meter, trace::TracerProvider};

#[must_use]
pub fn get_meter() -> Meter {
    global::meter_provider().meter("lure")
}

#[must_use]
pub fn get_tracer() -> BoxedTracer {
    global::tracer_provider().tracer("lure")
}
