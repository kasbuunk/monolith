use monolith::App;
use monolith::Repository;
use monolith::RepositoryMethod;
use monolith::TcpTransport;

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
    let repository = Repository::new(RepositoryMethod::InMemory);

    let app = App::new(repository);

    let tcp_listener = TcpTransport::new(app);
    tcp_listener.listen(port).await
}
