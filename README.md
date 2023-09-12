# Modular Monolith in Rust

This project aims to illustrate how a modular monolithic application can be built.

## Usage

Prerequisites:
- The Rust toolchain, with rustc 1.74 or later.
- A running postgres database server, reachable at the `$DATABASE_URL` connection string provided in `.env`.
- `sqlx`: `cargo install sqlx-cli --no-default-features --features rustls,postgres`. (Or create the database manually.)
- `make`

```sh
# Creates the dev database provided at $DATABASE_URL in `.env`.
sqlx database create 

# Compile and run the application.
cargo run

# Or using `make` in a child process:
make run

# Stop the child process running in the background:
make stop

# Run the end-to-end tests:
make test
```
