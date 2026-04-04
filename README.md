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
