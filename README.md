# `tracing-kickstart`

Rust module used to bootstrap tracing and reduce code duplication across projects.

Intended for personal use only.

## Example

This example loads the `TracingConfig` from a .env file by deserializing through a nested config struct.

**Example .env file:**

```sh
APP__TRACE__LOG_FILE_PATH="/tmp/tracing-kickstart-example.log"
APP__TRACE__COLLECTOR_URL="https://otel.example.com:4318"
APP__TRACE__COLLECTOR_AUTH_HEADER="Basic aHVudGVyMg=="
APP__TRACE__ANSI_OUTPUT=true
```

**Implementation example**

```rust
use config::{Config, Environment};
use dotenvy::dotenv;
use serde::Deserialize;
use tracing_kickstart::TracingConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct Conf {
    // pulled in automatically from env vars
    trace: TracingConfig,
}

#[tokio::main]
async fn main() {
    // load config
    dotenv().ok(); // load vars from .env file
    let settings = Config::builder()
        .add_source(Environment::with_prefix("APP").separator("__").try_parsing(true))
        .build()
        .unwrap();
    let conf = settings.try_deserialize::<Conf>().unwrap(); // deserialize into Conf struct

    // collect attributes for this crate
    let attrs = tracing_kickstart::build_attrs!();
    attrs.dump(); // log attributes to stdout

    // set an optional override for the fallback env filter set by tracing_kickstart
    let custom_fallback_env_filter = None; //Some("warn,example_app=debug")

    // init tracing, receive a handle for the tracing providers
    let tracing_providers = tracing_kickstart::init(attrs, &conf.trace, custom_fallback_env_filter).unwrap();
    tracing_providers.register_globally(); // optionally register all configured providers globally
    tracing::info!(?conf.trace, "Tracing initialized");

    // app does some important work here
    println!("very important work");

    // graceful shutdown of various tracing providers (logs, metrics, traces) using the provided handle
    tracing::debug!("Shutting down tracing providers: {tracing_providers:?}");
    tracing_providers.shutdown();
}
```

## Feature flags

**Default**: none

**`tokio_console`** - Enables tokio's console feature
  - Pulls `console-subscriber` into dependency tree and handles required env filter updates

**`detector_hostresource`** - enables the [`HostResourceDetector`](https://docs.rs/opentelemetry-resource-detectors/latest/opentelemetry_resource_detectors/struct.HostResourceDetector.html)
  - Added attributes: `host.id`, `host.arch`

**`detector_os`** - enables the [`OsResourceDetector`](https://docs.rs/opentelemetry-resource-detectors/latest/opentelemetry_resource_detectors/struct.OsResourceDetector.html)
  - Added attributes: `os_type`

**`detector_process`**
  - Enables the [`ProcessResourceDetector`](https://docs.rs/opentelemetry-resource-detectors/latest/opentelemetry_resource_detectors/struct.ProcessResourceDetector.html)
  - Added attributes: `process.command_args`, `process.pid`, `process.runtime.version`, `process.runtime.name`, `process.runtime.description`

**`detector_telemetry`** - enables the [`TelemetryResourceDetector`](https://docs.rs/opentelemetry_sdk/latest/opentelemetry_sdk/resource/struct.TelemetryResourceDetector.html)
  - Added attributes: `telemetry.sdk.name`, `telemetry.sdk.language`, `telemetry.sdk.version`

**`attrs_crate_name`**
  - Adds an additional attribute (`service.crate_name`) for the crate name.
  - This will only differ from `service_name` for crates/packages which contain hyphen's in their package name.
  - E.g. for this library:
    - `service.name`: `tracing-kickstart`
    - `service.crate_name`: `tracing_kickstart`

**`attrs_origin`**
  - Adds attributes for info regarding the `tracing-kickstart` package, e.g. the version, crate name, etc

**`attrs_version_expanded`**
  - Adds attributes for each version part: `service.version.major`, `service.version.minor`, `service.version.patch`

**`exponential_histograms`**
  - Adds support for exporting exponential histograms
    - Exponential histograms can be collected and exported to prometheus native histograms

