#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let error = match lens_sandbox_runtime::linux::config::RuntimeConfig::from_env() {
        Ok(config) => lens_sandbox_runtime::linux::run(config).await,
        Err(error) => error,
    };
    tracing::error!(%error, "the runtime stops");
    std::process::ExitCode::FAILURE
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("lens-sandbox-runtime runs only on Linux");
    std::process::ExitCode::FAILURE
}
