use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use tracing_subscriber::EnvFilter;
#[cfg(feature = "tokio_console")]
use tracing_subscriber::layer::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

// opentelemetry - base
use opentelemetry::KeyValue;
use opentelemetry_sdk::resource::{Resource, TelemetryResourceDetector};
// use opentelemetry_sdk::propagation::TraceContextPropagator; // ?
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_resource_detectors::{
    HostResourceDetector, OsResourceDetector, ProcessResourceDetector,
};
use opentelemetry_semantic_conventions::attribute;

// opentelemetry - traces
use opentelemetry::trace::TracerProvider as _; // for tracer trait
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing_opentelemetry::OpenTelemetryLayer;

// opentelemetry - metrics
use opentelemetry_otlp::MetricExporter;
use opentelemetry_sdk::metrics::SdkMeterProvider;

// opentelemetry - logs
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::LogExporter;
use opentelemetry_sdk::logs::SdkLoggerProvider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingOtelConfig {
    collector_url: String,

    #[serde(default, skip_serializing)]
    collector_auth_header: Option<SecretString>,
}
impl TracingOtelConfig {

    pub fn new(collector_url: String, collector_auth_header: Option<SecretString>) -> Self {
        Self {
            collector_url,
            collector_auth_header,
        }
    }
    pub fn collector_url(&self) -> &str {
        &self.collector_url
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    log_file_path: Option<String>,

    #[serde(default = "TracingConfig::ansi_output_default")]
    ansi_output: bool,

    #[serde(default, flatten)]
    otel_config: Option<TracingOtelConfig>,
}
impl TracingConfig {
    pub fn new(collector_url: Option<String>, collector_auth_header: Option<SecretString>, log_file_path: Option<String>, ansi_output: Option<bool>) -> Self {
        Self {
            log_file_path,
            ansi_output: ansi_output.unwrap_or(Self::ansi_output_default()),
            otel_config: collector_url.map(|url| TracingOtelConfig {
                collector_url: url,
                collector_auth_header,
            }),
        }
    }
    pub fn log_file_path(&self) -> Option<&str> {
        self.log_file_path.as_ref().map(|s| s.as_str())
    }
    pub fn otel_config(&self) -> &Option<TracingOtelConfig> {
        &self.otel_config
    }
    pub fn ansi_output_default() -> bool {
        true
    }
}
impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            ansi_output: Self::ansi_output_default(),
            log_file_path: None,
            otel_config: None,
        }
    }
}
#[rustfmt::skip]
pub fn get_build_env() -> &'static str {
    #[cfg(debug_assertions)]
    { "debug" }
    #[cfg(not(debug_assertions))]
    { "release" }
}

fn build_otel_resource() -> Resource {
    Resource::builder_empty()
        .with_attribute(KeyValue::new(attribute::SERVICE_NAME, env!("CARGO_CRATE_NAME")))
        .with_attribute(KeyValue::new(attribute::SERVICE_VERSION, env!("CARGO_PKG_VERSION")))
        .with_attribute(KeyValue::new(attribute::DEPLOYMENT_ENVIRONMENT_NAME, get_build_env()))
        .with_detector(Box::new(TelemetryResourceDetector)) // telemetry sdk stack attrs
        .with_detector(Box::new(HostResourceDetector::default())) // host id, host arch
        .with_detector(Box::new(ProcessResourceDetector)) // process args, pid
        .with_detector(Box::new(OsResourceDetector)) // os
        .build()
}

fn build_otel_headers(auth_header_val: &Option<SecretString>) -> HashMap<String, String> {
    let mut headers: HashMap<String, String> = HashMap::new();

    // add auth headers if provided
    if let Some(auth_header) = auth_header_val.as_ref() {
        headers.insert("Authorization".into(), auth_header.expose_secret().into());
    }

    headers
}

// Construct TracerProvider for OpenTelemetryLayer
fn init_otel_traces_provider(
    collector_endpoint: &str,
    headers: HashMap<String, String>,
    resource: Resource,
) -> color_eyre::Result<SdkTracerProvider> {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_headers(headers)
        .with_endpoint(format!("{collector_endpoint}/v1/traces"))
        .with_protocol(Protocol::HttpBinary)
        // .with_timeout(std::time::Duration::from_secs(3))
        .build()?;

    let provider = SdkTracerProvider::builder()
        // Customize sampling strategy
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(1.0))))
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    Ok(provider)
}
fn init_otel_logs_provider(
    collector_endpoint: &str,
    headers: HashMap<String, String>,
    resource: Resource,
) -> color_eyre::Result<SdkLoggerProvider> {
    let exporter = LogExporter::builder()
        .with_http()
        .with_headers(headers)
        .with_endpoint(format!("{collector_endpoint}/v1/logs"))
        .with_protocol(Protocol::HttpBinary)
        // .with_timeout(std::time::Duration::from_secs(3))
        .build()?;

    let provider = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    Ok(provider)
}
fn init_otel_metrics_provider(
    collector_endpoint: &str,
    headers: HashMap<String, String>,
    resource: Resource,
) -> color_eyre::Result<SdkMeterProvider> {
    let exporter = MetricExporter::builder()
        .with_http()
        .with_headers(headers)
        .with_endpoint(format!("{collector_endpoint}/v1/metrics"))
        .with_protocol(Protocol::HttpBinary)
        // .with_timeout(std::time::Duration::from_secs(3))
        .build()?;

    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_periodic_exporter(exporter)
        .build();

    Ok(provider)
}

// if tracing config is none, otel providers won't be handled
#[allow(unused_mut)]
pub fn init(config: &TracingConfig) -> color_eyre::Result<TraceProviders> {
    let crate_name = env!("CARGO_CRATE_NAME");
    let mut prepared_env_filter = format!(
        "warn,{crate_name}=debug"
    );

    // add env filters for tokio console subscriber (controller by feature flag)
    #[cfg(feature = "tokio_console")]
    { prepared_env_filter.push_str(",tokio=trace,runtime=trace"); }

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| prepared_env_filter.into());

    // build base layers
    let layer = tracing_subscriber::registry()
        .with(env_filter);
    // stdout layer
    let layer = layer.with(tracing_subscriber::fmt::layer()
        .with_ansi(config.ansi_output)
    );
    // conditionally add log file layer if path is provided in config
    let file_logging_layer = match &config.log_file_path {
        Some(file_path) => {
            let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(file_path)
            .expect("Log file should be writable");
            Some(tracing_subscriber::fmt::layer().with_ansi(false).with_writer(file))
        },
        None => None
    };
    let layer = layer.with(file_logging_layer);

    // conditionally add tokio console layer
    #[cfg(feature = "tokio_console")]
    { let layer = layer.with(console_subscriber::spawn()); }

    // default has all 3 provider field options set to None
    let mut providers_handle = TraceProviders::default();

    // init open telemetry providers
    if let Some(otel_config) = &config.otel_config {
        let endpoint = &otel_config.collector_url;
        let headers = build_otel_headers(&otel_config.collector_auth_header);
        let resource = build_otel_resource();

        // traces
        let traces_provider =
            init_otel_traces_provider(endpoint, headers.clone(), resource.clone())?;
        // - add tracing layer for tracing/span -> otel/trace
        let layer = layer.with(OpenTelemetryLayer::new(traces_provider.tracer(crate_name)));
        providers_handle.traces = Some(traces_provider);

        // logs
        let logs_provider = init_otel_logs_provider(endpoint, headers.clone(), resource.clone())?;
        // - add tracing layer for tracing -> otel/logs
        let layer = layer.with(OpenTelemetryTracingBridge::new(&logs_provider));
        providers_handle.logs = Some(logs_provider);

        // metrics
        let metrics_provider = init_otel_metrics_provider(endpoint, headers, resource)?;
        providers_handle.metrics = Some(metrics_provider);

        layer.init();
        tracing::info!("OTEL tracing configured");
    } else {
        layer.init();
        tracing::warn!("OTEL tracing disabled");
    }

    Ok(providers_handle)
}

// ---- Struct for containing otel providers

// TODO: alternatively use `opentelemetry::global::set_x_provider()` fns
#[derive(Debug, Default, Clone)]
pub struct TraceProviders {
    pub traces: Option<SdkTracerProvider>,
    pub logs: Option<SdkLoggerProvider>,
    pub metrics: Option<SdkMeterProvider>,
}
impl TraceProviders {
    pub fn shutdown(self) {
        // shutdown traces
        if let Some(provider) = self.traces {
            if let Err(error) = provider.shutdown() {
                println!("error shutting down traces provider: {error}");
            }
        }
        // shutdown logs
        if let Some(provider) = self.logs {
            if let Err(error) = provider.shutdown() {
                println!("error shutting down logs provider: {error}");
            }
        }
        // shutdown metrics
        if let Some(provider) = self.metrics {
            if let Err(error) = provider.shutdown() {
                println!("error shutting down metrics provider: {error}");
            }
        }
    }
}



