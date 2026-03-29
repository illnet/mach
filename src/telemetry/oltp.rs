#![allow(dead_code)]

use std::env;

use log::info;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    metrics::SdkMeterProvider,
    trace::{self, RandomIdGenerator, Sampler, SdkTracerProvider},
};

/// Creates an OpenTelemetry Resource from environment variables following semantic conventions,
/// including `OTEL_RESOURCE_ATTRIBUTES` for additional key-value pairs.
/// Fallbacks are provided for required attributes like service.name.
#[must_use]
pub fn create_resource_from_env() -> Resource {
    let mut attributes = Vec::new();

    // Service attributes
    let service_name =
        env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "unknown-service".to_string());
    attributes.push(KeyValue::new("service.name", service_name));

    if let Ok(service_version) = env::var("OTEL_SERVICE_VERSION") {
        attributes.push(KeyValue::new("service.version", service_version));
    }

    if let Ok(service_namespace) = env::var("OTEL_SERVICE_NAMESPACE") {
        attributes.push(KeyValue::new("service.namespace", service_namespace));
    }

    if let Ok(service_instance_id) = env::var("OTEL_SERVICE_INSTANCE_ID") {
        attributes.push(KeyValue::new("service.instance.id", service_instance_id));
    }

    // Deployment attributes
    if let Ok(deployment_environment) = env::var("OTEL_DEPLOYMENT_ENVIRONMENT") {
        attributes.push(KeyValue::new(
            "deployment.environment",
            deployment_environment,
        ));
    }

    // Parse OTEL_RESOURCE_ATTRIBUTES (comma-separated key=value pairs)
    if let Ok(resource_attributes) = env::var("OTEL_RESOURCE_ATTRIBUTES") {
        for kv in resource_attributes.split(',') {
            if let Some((key, value)) = kv.split_once('=') {
                let key = key.trim().to_string();
                let value = value.trim().to_string();
                if !key.is_empty() && !value.is_empty() {
                    // Skip attributes already set explicitly to avoid duplicates
                    if !attributes.iter().any(|kv| kv.key.as_str() == key) {
                        attributes.push(KeyValue::new(key, value.clone()));
                    }
                }
            }
        }
    }

    Resource::builder().with_attributes(attributes).build()
}
fn build_span_exporter() -> opentelemetry_otlp::SpanExporter {
    // SDK reads OTEL_EXPORTER_OTLP_{ENDPOINT,PROTOCOL,TIMEOUT,HEADERS} automatically.
    // Default protocol: http/protobuf. Only override if the signal-specific endpoint var is set.
    let mut builder = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary);
    if let Ok(ep) = env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") {
        info!("Sending traces to {ep}");
        builder = builder.with_endpoint(ep);
    }
    builder.build().expect("failed to build OTLP SpanExporter")
}

fn build_metric_exporter() -> opentelemetry_otlp::MetricExporter {
    // SDK reads OTEL_EXPORTER_OTLP_{ENDPOINT,PROTOCOL,TIMEOUT,HEADERS} automatically.
    // Default protocol: http/protobuf. Only override if the signal-specific endpoint var is set.
    let mut builder = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary);
    if let Ok(ep) = env::var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") {
        info!("Sending metrics to {ep}");
        builder = builder.with_endpoint(ep);
    }
    builder
        .build()
        .expect("failed to build OTLP MetricExporter")
}

#[must_use]
pub fn init_tracer() -> SdkTracerProvider {
    let _ = dotenvy::dotenv();
    let resource = create_resource_from_env();
    let span_exporter = build_span_exporter();

    // SDK reads OTEL_SPAN_EVENT_COUNT_LIMIT, OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT, OTEL_BSP_* automatically
    let tracer_provider = trace::SdkTracerProvider::builder()
        .with_sampler(Sampler::AlwaysOn)
        .with_id_generator(RandomIdGenerator::default())
        .with_batch_exporter(span_exporter)
        .with_resource(resource)
        .build();

    global::set_tracer_provider(tracer_provider.clone());
    tracer_provider
}

#[must_use]
pub fn init_meter() -> SdkMeterProvider {
    let _ = dotenvy::dotenv();
    let metric_exporter = build_metric_exporter();
    let resource = create_resource_from_env();

    // SDK reads OTEL_METRIC_EXPORT_INTERVAL automatically (default 60s)
    let meter_provider = SdkMeterProvider::builder()
        .with_periodic_exporter(metric_exporter)
        .with_resource(resource);

    #[cfg(feature = "verbose")]
    let meter_provider = meter_provider
        .with_periodic_exporter(opentelemetry_stdout::MetricExporter::builder().build());

    let meter_provider = meter_provider.build();
    global::set_meter_provider(meter_provider.clone());
    meter_provider
}
