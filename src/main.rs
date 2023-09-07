use monolith::App;
use monolith::Repository;
use monolith::RepositoryMethod;
use monolith::TCPListener;

/* TODO
 * Configuration: environment, toml, json, yaml and ron.
 * Transports: tcp, http, grpc, graphql.
 * Serialisation: binary, json, ron, protobuf.
 * Domain layer.
 * Adapter layer: postgres.
 */

fn main() {
    // Hardcode configuration for now.
    let port = 8080;
    let workers: usize = 5;
    let db_connection_string = "user:pass@host:port?ssl=true";

    let repository = Repository::new(RepositoryMethod::Postgres(String::from(
        db_connection_string,
    )));

    let app = App::new(repository);

    let tcp_listener = TCPListener::new(workers, app);
    tcp_listener.listen(port);
}
