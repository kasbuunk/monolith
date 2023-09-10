use monolith::App;
use monolith::Repository;
use monolith::TcpTransport;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

/* TODO
 * Configuration: environment, toml, json, yaml and ron.
 * Transports: tcp, http, grpc, graphql.
 * Serialisation: binary, json, ron, protobuf.
 * Domain layer.
 * Adapter layer: postgres.
 */

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Hardcode configuration for now.
    let port = 8080;
    let max_connections = 5;
    let connection_string = "postgres://postgres:postgres@localhost/test";

    let connection_pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(connection_string)
        .await?;

    let repository = Repository::new(connection_pool);

    repository.migrate().await?;

    let app = Arc::new(App::new(repository));

    let tcp_listener = TcpTransport::new(app);
    tcp_listener.listen(port).await
}
