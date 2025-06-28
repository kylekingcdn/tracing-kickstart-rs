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
use serde::{Deserialize, Serialize};
use tracing_kickstart::{ServiceAttributeStore, TracingConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conf {
    // pulled in automatically from env vars
    trace: TracingConfig,
}

fn main() {
    // load config
    dotenv().ok(); // load vars from .env file
    let settings = Config::builder()
        .add_source(Environment::with_prefix("APP").separator("__").try_parsing(true))
        .build()
        .unwrap();
    let conf = settings.try_deserialize::<Conf>().unwrap(); // deserialize into Conf struct

    // store compile-time attributes used for tracing_kickstart
    let svc_attrs = ServiceAttributeStore::new(
        env!("CARGO_CRATE_NAME"),
        env!("CARGO_PKG_NAME")
    );
    // dump vars used as attributes in OTEL reporting (for debug purposes)
    tracing_kickstart::dump_crate_vars(&svc_attrs);

    // init tracing, receive a handle for the tracing providers
    let tracing_providers = tracing_kickstart::init(svc_attrs, &conf.trace).unwrap();
    tracing::info!(?conf.trace, "Tracing initialized");

    // app does some important work here
    println!("very important work");

    // graceful shutdown of various tracing providers (logs, metrics, traces) using the provided handle
    tracing_providers.shutdown();
}
```
