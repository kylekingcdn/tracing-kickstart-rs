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
    #[serde(default)]
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

// -- custom attributes + attribute helpers

pub mod custom_attribute {
    pub const SERVICE_CRATE_NAME: &str = "service.crate.name";
    pub const SERVICE_VERSION_MAJOR: &str = "service.version.major";
    pub const SERVICE_VERSION_MINOR: &str = "service.version.minor";
    pub const SERVICE_VERSION_PATCH: &str = "service.version.patch";
    pub const SERVICE_ORIGIN_PACKAGE_NAME: &str = "service.origin.package_name";
    pub const SERVICE_ORIGIN_CRATE_NAME: &str = "service.origin.crate_name";
}
#[rustfmt::skip]
pub fn get_build_env() -> &'static str {
    #[cfg(debug_assertions)]
    { "debug" }
    #[cfg(not(debug_assertions))]
    { "release" }
}
pub fn get_service_version() -> Option<String> {
    std::env::var("CARGO_PKG_VERSION").ok()
}
pub fn get_service_version_major() -> Option<String> {
    std::env::var("CARGO_PKG_VERSION_MAJOR").ok()
}
pub fn get_service_version_minor() -> Option<String> {
    std::env::var("CARGO_PKG_VERSION_MINOR").ok()
}
pub fn get_service_version_patch() -> Option<String> {
    std::env::var("CARGO_PKG_VERSION_PATCH").ok()
}
pub fn get_origin_package_name() -> Option<&'static str> {
    let package_name = env!("CARGO_PKG_NAME");
    if package_name.is_empty() {
        None
    } else {
        Some(package_name)
    }
}
pub fn get_origin_crate_name() -> Option<&'static str> {
    let package_name = env!("CARGO_CRATE_NAME");
    if package_name.is_empty() {
        None
    } else {
        Some(package_name)
    }
}

fn build_otel_resource(service_attrs: &ServiceAttributeStore) -> Resource {
    let mut builder = Resource::builder_empty();
    // root/primary service name + package name
    builder = builder.with_attribute(KeyValue::new(attribute::SERVICE_NAME, service_attrs.pkg_name));
    builder = builder.with_attribute(KeyValue::new(custom_attribute::SERVICE_CRATE_NAME, service_attrs.crate_name));

    // version
    if let Some(service_version) = get_service_version() {
        builder = builder.with_attribute(KeyValue::new(attribute::SERVICE_VERSION, service_version));
        if let Some(version_part) = get_service_version_major() {
            builder = builder.with_attribute(KeyValue::new(custom_attribute::SERVICE_VERSION_MAJOR, version_part));
            if let Some(version_part) = get_service_version_minor() {
                builder = builder.with_attribute(KeyValue::new(custom_attribute::SERVICE_VERSION_MINOR, version_part));
                if let Some(version_part) = get_service_version_patch() {
                    builder = builder.with_attribute(KeyValue::new(custom_attribute::SERVICE_VERSION_PATCH, version_part));
                }
            }
        }
    }
    // returns the name of the package that contains the associated tracing call
    if let Some(origin_package_name) = get_origin_package_name() {
        builder = builder.with_attribute(KeyValue::new(custom_attribute::SERVICE_ORIGIN_PACKAGE_NAME, origin_package_name));
    }
    if let Some(origin_crate_name) = get_origin_crate_name() {
        builder = builder.with_attribute(KeyValue::new(custom_attribute::SERVICE_ORIGIN_CRATE_NAME, origin_crate_name));
    }

    builder
        .with_attribute(KeyValue::new(attribute::DEPLOYMENT_ENVIRONMENT_NAME, get_build_env())) // build mode: release/debug
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

/// Compile-time attributes to be provided by the owning application/service.
///
/// Used as a set of parameters to pass to [`init()`]
#[derive(Debug, Clone)]
pub struct ServiceAttributeStore {
    pub crate_name: &'static str,
    pub pkg_name: &'static str,
}
impl ServiceAttributeStore {
    /// Initializes a new [`ServiceAttributeStore`].
    ///
    /// Typically the args passed should be `env!("CARGO_CRATE_NAME")` and `env!("CARGO_PKG_NAME")`, respectively.
    ///
    /// ### Example
    ///
    /// ```rust
    /// use tracing_kickstart::ServiceAttributeStore;
    /// let attrs = ServiceAttributeStore::new(env!("CARGO_CRATE_NAME"), env!("CARGO_PKG_NAME"));
    /// ```
    pub fn new(crate_name: &'static str, pkg_name: &'static str) -> Self {
        Self {
            crate_name,
            pkg_name,
        }
    }
}

// if tracing config is none, otel providers won't be handled
#[allow(unused_mut)]
pub fn init(service_attrs: ServiceAttributeStore, config: &TracingConfig) -> color_eyre::Result<TraceProviders> {
    let mut prepared_env_filter = format!(
        "warn,{}=debug,tracing_kickstart=debug", // include self in default filter
        service_attrs.crate_name
    );

    // add env filters for tokio console subscriber (controller by feature flag)
    #[cfg(feature = "tokio_console")]
    { prepared_env_filter.push_str(",tokio=trace,runtime=trace"); }

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| prepared_env_filter.clone().into());

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
            .write(true)
            .create(true)
            .truncate(true)
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
        println!("Initializing OTEL config");
        let endpoint = &otel_config.collector_url;
        let headers = build_otel_headers(&otel_config.collector_auth_header);
        let resource = build_otel_resource(&service_attrs);

        // traces
        let traces_provider =
            init_otel_traces_provider(endpoint, headers.clone(), resource.clone())?;
        // - add tracing layer for tracing/span -> otel/trace
        let layer = layer.with(OpenTelemetryLayer::new(traces_provider.tracer(service_attrs.crate_name)));
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

    tracing::debug!("Env filter:  {prepared_env_filter:?}");

    Ok(providers_handle)
}

pub fn dump_crate_vars(attrs: &ServiceAttributeStore) {
    let service_name = attrs.pkg_name;
    let crate_name = attrs.crate_name;
    let service_version = get_service_version().unwrap_or("- unset -".into());
    let service_version_major = get_service_version_major().unwrap_or("- unset -".into());
    let service_version_minor = get_service_version_minor().unwrap_or("- unset -".into());
    let service_version_patch = get_service_version_patch().unwrap_or("- unset -".into());
    let origin_pkg_name = get_origin_package_name().unwrap_or("- unset -".into());
    let origin_crate_name = get_origin_crate_name().unwrap_or("- unset -".into());
    let build_env = get_build_env();

    println!("");
    println!("Resolved tracing attributes");
    println!("--------------------");
    println!("service_name (pkg_name): {service_name}");
    println!("service_crate_name:      {crate_name}");
    println!("service_version:         {service_version}");
    println!("service_version_major:   {service_version_major}");
    println!("service_version_minor:   {service_version_minor}");
    println!("service_version_patch:   {service_version_patch}");
    println!("origin_pkg_name:         {origin_pkg_name}");
    println!("origin_crate_name:       {origin_crate_name}");
    println!("build_env:               {build_env}");
    println!("");
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
