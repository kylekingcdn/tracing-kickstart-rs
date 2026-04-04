mod trace;

pub use trace::{ExporterBuildError, ServiceAttributeStore, TraceProviders, TracingConfig, TracingOtelConfig};
pub use trace::init;

pub use opentelemetry;
pub use opentelemetry_appender_tracing;
pub use opentelemetry_otlp;
pub use opentelemetry_resource_detectors;
pub use opentelemetry_sdk;
pub use opentelemetry_semantic_conventions;

// shortform exports
pub use opentelemetry as otel;
pub use opentelemetry_appender_tracing as otel_appender_tracing;
pub use opentelemetry_otlp as otel_otlp;
pub use opentelemetry_resource_detectors as otel_resource_detectors;
pub use opentelemetry_sdk as otel_sdk;
pub use opentelemetry_semantic_conventions as otel_semantic_conventions;
