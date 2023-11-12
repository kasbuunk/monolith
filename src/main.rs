use log::info;
use monolith::app;
use monolith::config;
use monolith::database;
use monolith::http;
use monolith::repository;
use monolith::tcp;
use monolith::transport::Transport;
use std::process;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let config_file_path = match args.len() {
        1 => "config.ron", // Default configuration file.
        2 => &args[1],
        _ => {
            println!("Please specify the path to the configuration file as the only argument.");

            process::exit(1);
        }
    };

    let config = config::load_config_from_file(config_file_path)?;

    let rust_log = "RUST_LOG";

    std::env::set_var(rust_log, config.log_level);
    env_logger::init();

    info!("Starting application.");

    let connection_pool = database::connect_to_database(config.database).await?;

    let repository = Arc::new(repository::Repo::new(connection_pool));

    repository.migrate().await?;

    let signing_secret = b"secret";
    let app = Arc::new(app::App::new(repository, signing_secret)?);

    match config.transport {
        config::Transport::Tcp(tcp_config) => {
            let tcp_listener = tcp::Listener::new(app);
            tcp_listener.listen(tcp_config.port).await
        }
        config::Transport::Http(http_config) => {
            let http_server = http::Server::new(app);
            http_server.listen(http_config.port).await
        }
    }
}
