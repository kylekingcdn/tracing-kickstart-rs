use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs::OpenOptions;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

// opentelemetry - base
use opentelemetry::KeyValue;
use opentelemetry_sdk::resource::{Resource, TelemetryResourceDetector};
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
use tracing_opentelemetry::MetricsLayer;

// opentelemetry - logs
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::LogExporter;
use opentelemetry_sdk::logs::SdkLoggerProvider;

pub use opentelemetry_otlp::ExporterBuildError;

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
    /// Custom env filter which takes priority over RUST_LOG
    ///
    /// This is beneficial when loading app conf from env,
    /// as it allows overriding the env filter without setting a global RUST_LOG
    #[serde(default)]
    filter: Option<String>,

    #[serde(default)]
    log_file_path: Option<String>,

    #[serde(default = "TracingConfig::ansi_output_default")]
    ansi_output: bool,

    #[serde(default, flatten)]
    otel_config: Option<TracingOtelConfig>,
}
impl TracingConfig {
    pub fn new(collector_url: Option<String>, collector_auth_header: Option<SecretString>, log_file_path: Option<String>, ansi_output: Option<bool>, filter: Option<String>) -> Self {
        Self {
            filter,
            log_file_path,
            ansi_output: ansi_output.unwrap_or(Self::ansi_output_default()),
            otel_config: collector_url.map(|url| TracingOtelConfig {
                collector_url: url,
                collector_auth_header,
            }),
        }
    }
    pub fn log_file_path(&self) -> Option<&str> {
        self.log_file_path.as_deref()
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
            filter: None,
            log_file_path: None,
            otel_config: None,
        }
    }
}

// -- custom attributes + attribute helpers

pub mod custom_attribute {
    pub const SERVICE_CRATE_NAME: &str = "service.crate_name";
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
    // root/primary service name + package name
    let mut builder = Resource::builder_empty()
    .with_attribute(KeyValue::new(attribute::SERVICE_NAME, service_attrs.pkg_name))
    .with_attribute(KeyValue::new(custom_attribute::SERVICE_CRATE_NAME, service_attrs.crate_name));

    // version
    builder = builder
    .with_attribute(KeyValue::new(attribute::SERVICE_VERSION, service_attrs.version))
    .with_attribute(KeyValue::new(custom_attribute::SERVICE_VERSION_MAJOR, service_attrs.version_major))
    .with_attribute(KeyValue::new(custom_attribute::SERVICE_VERSION_MINOR, service_attrs.version_minor))
    .with_attribute(KeyValue::new(custom_attribute::SERVICE_VERSION_PATCH, service_attrs.version_patch));

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
) -> Result<SdkTracerProvider, ExporterBuildError> {
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
) -> Result<SdkLoggerProvider, ExporterBuildError> {
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
) -> Result<SdkMeterProvider, ExporterBuildError> {
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
///
/// Service attributes can be generated and passed in using the `build_attrs` macro, e.g.:
///
/// ```
/// use tracing_kickstart::TracingConfig;
///
/// let attrs = tracing_kickstart::build_attrs!();
/// let conf = TracingConfig::default();
///
/// let tracing_providers = tracing_kickstart::init(attrs, &conf).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct ServiceAttributeStore {
    pub crate_name: &'static str,
    pub pkg_name: &'static str,
    pub version: &'static str,
    pub version_major: &'static str,
    pub version_minor: &'static str,
    pub version_patch: &'static str,
}
impl ServiceAttributeStore {
    pub fn dump(&self) {

        let service_name = self.pkg_name;
        let crate_name = self.crate_name;
        let service_version = self.version;
        let service_version_major = self.version_major;
        let service_version_minor = self.version_minor;
        let service_version_patch = self.version_patch;
        let origin_pkg_name = get_origin_package_name().unwrap_or("- unset -");
        let origin_crate_name = get_origin_crate_name().unwrap_or("- unset -");
        let build_env = get_build_env();

        println!();
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
        println!();
    }
}

/// Generates service attributes using env! calls.
///
/// This is done using a macro to allow for the `env!(..)` calls to be scoped from the
/// parent package/crate, rather than from `tracing-kickstart`.
#[macro_export]
macro_rules! build_attrs {
    // This macro takes an argument of designator `ident` and
    // creates a function named `$func_name`.
    // The `ident` designator is used for variable/function names.
    () => (
        tracing_kickstart::ServiceAttributeStore {
            crate_name: env!("CARGO_CRATE_NAME"),
            pkg_name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            version_major: env!("CARGO_PKG_VERSION_MAJOR"),
            version_minor: env!("CARGO_PKG_VERSION_MINOR"),
            version_patch: env!("CARGO_PKG_VERSION_PATCH"),
        }
    )
}

/// Initialize tracing
///
/// Service attributes can be generated and passed in using the `build_attrs` macro, e.g.:
///
/// ```
/// use tracing_kickstart::TracingConfig;
///
/// let attrs = tracing_kickstart::build_attrs!();
/// let conf = TracingConfig::default();
/// let custom_env_filter = None;
/// // let custom_env_filter = "warn,example_app=debug"
///
/// let tracing_providers = tracing_kickstart::init(attrs, &conf, custom_env_filter).unwrap();
///
/// // Optionally register all configured providers globally
/// tracing_providers.register_globally();
///
/// // do some work..
///
/// tracing_providers.shutdown();
/// ```
///
/// ## `EnvFilter`
///
/// The EnvFilter is resolved using the first available from:
/// - `TracingConfig::filter` (typically set from app config env var, e.g. `APP__TRACING__FILTER=app=warn`)
/// - `RUST_LOG` env var
/// - The `default_env_filter` parameter in this function (used to overide the default fallback)
/// - default fallback (library defined, set to `"warn,{crate_name}=debug,tracing_kickstart=debug`)
/// ---
/// Regardless of how the `EnvFilter` is resolved, all required filters for `console_subscriber` will be added
/// **if the console_subscriber** feature flag is enabled.
// if tracing config is none, otel providers won't be handled
pub fn init(service_attrs: ServiceAttributeStore, config: &TracingConfig, default_env_filter: Option<&str>) -> Result<TraceProviders, ExporterBuildError> {
    // resolve the env filter in the following priority
    let filter: EnvFilter = {
        // config env filter
        if let Some(filter_str) = &config.filter {
            println!("Resolved tracing EnvFilter from provided config: {filter_str:?}");
            filter_str.into()
        }
        // `RUST LOG`
        else if let Ok(filter) = EnvFilter::try_from_default_env() {
            println!("Resolved tracing EnvFilter from `RUST_LOG`: {:?}", filter.to_string());
            filter
        }
        // function parameter (`default_env_filter`)
        else if let Some(filter_str) = default_env_filter {
            println!("Resolving tracing EnvFilter from `tracing_kickstart::init(.., default_env_filter)`: {filter_str:?}");
            filter_str.into()
        }
        // library-defined fallback env filter
        else {
            let filter_str = format!(
                "warn,{}=debug,tracing_kickstart=debug", // include self in default filter
                service_attrs.crate_name
            );
            println!("Using tracing-kickstart fallback EnvFilter: {filter_str:?}");
            filter_str.into()
        }
    };

    // add env filters for tokio console subscriber (controlled by feature flag)
    #[cfg(feature = "tokio_console")]
    let filter = {
        let mut filter_str = filter.to_string();
        if !filter_str.is_empty() {
            filter_str.push(',');
        }
        filter_str.push_str("tokio=trace,runtime=trace");
        EnvFilter::from(filter_str)
    };
    println!("Launching with tracing filter: {}", filter);

    // build base layers
    let layer = tracing_subscriber::registry()
    .with(filter);

    // stdout layer
    let layer = layer.with(
        tracing_subscriber::fmt::layer()
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
    let layer = layer.with(console_subscriber::spawn());

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
        // - add layer for tracing events -> otel/metrics
        let layer = layer.with(MetricsLayer::new(metrics_provider.clone()));
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
#[derive(Default, Clone)]
pub struct TraceProviders {
    pub traces: Option<SdkTracerProvider>,
    pub logs: Option<SdkLoggerProvider>,
    pub metrics: Option<SdkMeterProvider>,
}
impl TraceProviders {
    /// Calls `opentelemetry::global::set_x_provider(..); for all configured providers, where applicable`
    pub fn register_globally(&self) {
        // register traces
        if let Some(provider) = &self.traces {
            tracing::info!("Traces provider registered globally");
            opentelemetry::global::set_tracer_provider(provider.clone());
        }
        // register metrics
        if let Some(provider) = &self.metrics {
            tracing::info!("Metrics provider registered globally");
            opentelemetry::global::set_meter_provider(provider.clone());
        }
    }

    /// Triggers shutdown for each provider that has been set
    pub fn shutdown(self) {
        // shutdown traces
        if let Some(provider) = self.traces && let Err(error) = provider.shutdown() {
            println!("error shutting down traces provider: {error}");
        }
        // shutdown logs
        if let Some(provider) = self.logs && let Err(error) = provider.shutdown() {
            println!("error shutting down logs provider: {error}");
        }
        // shutdown metrics
        if let Some(provider) = self.metrics && let Err(error) = provider.shutdown() {
            println!("error shutting down metrics provider: {error}");
        }
    }
}
impl fmt::Debug for TraceProviders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TraceProviders (")?;
        let mut i = 0;
        if self.traces.is_some() {
            write!(f, "SdkTracerProvider")?;
            i += 1;
        }
        if self.logs.is_some() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "SdkLoggerProvider")?;
            i += 1;
        }
        if self.metrics.is_some() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "SdkMeterProvider")?;
        }
        write!(f, ")")
    }
}
