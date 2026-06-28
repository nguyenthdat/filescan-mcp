use std::process;

use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

use filescan_mcp::client::FilescanClient;
use filescan_mcp::config::FilescanConfig;

#[tokio::main]
async fn main() {
    // Init tracing — warn by default, info for our crate.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,filescan_mcp=info")),
        )
        .with_target(false)
        .init();

    // Load config from env.
    let config = match FilescanConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    tracing::info!(
        base_url = %config.base_url(),
        "Filescan MCP server starting"
    );

    let client = FilescanClient::new(&config);
    let service = filescan_mcp::tools::FilescanService::new(client);

    // Serve over stdio.
    let transport = rmcp::transport::stdio();
    match service.serve(transport).await {
        Ok(server) => {
            tracing::info!("Server initialized, waiting for shutdown");
            if let Err(e) = server.waiting().await {
                tracing::error!("Server error: {e}");
            }
        }
        Err(e) => {
            tracing::error!("Failed to start server: {e}");
            process::exit(1);
        }
    }

    tracing::info!("Filescan MCP server stopped");
}
