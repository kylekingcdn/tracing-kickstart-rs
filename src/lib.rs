mod trace;

pub use trace::{ExporterBuildError, ServiceAttributeStore, TraceProviders, TracingConfig, TracingOtelConfig};
pub use trace::{init, dump_crate_vars};

pub use opentelemetry;
pub use opentelemetry_appender_tracing;
pub use opentelemetry_otlp;
pub use opentelemetry_resource_detectors;
pub use opentelemetry_sdk;
pub use opentelemetry_semantic_conventions;
