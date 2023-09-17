use log::info;
use monolith::app::App;
use monolith::config::load_config_from_file;
use monolith::database::connect_to_database;
use monolith::repository::Repo;
use monolith::tcp::TcpTransport;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_file_path = "config.ron";
    let config = load_config_from_file(config_file_path)?;

    let rust_log = "RUST_LOG";

    std::env::set_var(rust_log, config.log_level);
    env_logger::init();

    info!("Starting application.");

    let connection_pool = connect_to_database(config.database).await?;

    let repository = Arc::new(Repo::new(connection_pool));

    repository.migrate().await?;

    let signing_secret = b"secret";
    let app = Arc::new(App::new(repository, signing_secret)?);

    let tcp_listener = TcpTransport::new(app);
    tcp_listener.listen(config.tcp.port).await
}
