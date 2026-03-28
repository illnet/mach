use opentelemetry::{
    KeyValue,
    metrics::{Counter, Gauge, Histogram, Meter},
};

pub struct HandshakeMetrics {
    open: Counter<u64>,
    attempts: Counter<u64>,
    failures: Counter<u64>,
    duration: Histogram<u64>,
}

impl HandshakeMetrics {
    #[must_use]
    pub fn new(meter: &Meter) -> Self {
        Self {
            open: meter
                .u64_counter("lure_socket_open")
                .with_unit("{connection}")
                .build(),
            attempts: meter
                .u64_counter("lure_handshake")
                .with_unit("{handshake}")
                .build(),
            failures: meter
                .u64_counter("lure_handshake_fail")
                .with_unit("{handshake}")
                .build(),
            duration: meter
                .u64_histogram("lure_handshake_duration")
                .with_unit("ms")
                .build(),
        }
    }

    pub fn record_open(&self) {
        self.open.add(1, &[]);
    }

    pub fn record_attempt(&self, state: &str) {
        self.attempts
            .add(1, &[KeyValue::new("state", state.to_string())]);
    }

    pub fn record_failure(&self, state: &str) {
        self.failures
            .add(1, &[KeyValue::new("state", state.to_string())]);
    }

    pub fn record_duration(&self, elapsed_ms: u64, state: &str) {
        self.duration
            .record(elapsed_ms, &[KeyValue::new("state", state.to_string())]);
    }
}

#[derive(Debug)]
pub struct RouterMetrics {
    routes_active: Gauge<u64>,
    routes_resolve: Counter<u64>,
    sessions_active: Gauge<u64>,
    session_create: Counter<u64>,
    session_destroy: Counter<u64>,
}

impl RouterMetrics {
    #[must_use]
    pub fn new(meter: &Meter) -> Self {
        Self {
            routes_active: meter
                .u64_gauge("lure_router_routes")
                .with_unit("{route}")
                .build(),
            routes_resolve: meter
                .u64_counter("lure_router_route_resolve")
                .with_unit("1")
                .build(),
            sessions_active: meter
                .u64_gauge("lure_router_sessions")
                .with_unit("{session}")
                .build(),
            session_create: meter
                .u64_counter("lure_router_session_create")
                .with_unit("{session}")
                .build(),
            session_destroy: meter
                .u64_counter("lure_router_session_destroy")
                .with_unit("{session}")
                .build(),
        }
    }

    pub fn record_routes_active(&self, total: u64) {
        self.routes_active.record(total, &[]);
    }

    pub fn record_routes_resolve(&self) {
        self.routes_resolve.add(1, &[]);
    }

    pub fn record_sessions_active(&self, total: u64) {
        self.sessions_active.record(total, &[]);
    }

    pub fn record_session_create(&self) {
        self.session_create.add(1, &[]);
    }

    pub fn record_session_destroy(&self) {
        self.session_destroy.add(1, &[]);
    }
}
