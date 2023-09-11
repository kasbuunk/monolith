# Modular Monolith in Rust

This project aims to illustrate how a modular monolithic application can be built.

## Usage

Prerequisites:
- Rust
- A running postgres database server, reachable at the `$DATABASE_URL` connection string provided in `.env`.
- `sqlx`: `cargo install sqlx-cli --no-default-features --features rustls,postgres`. (Or create the database manually.)

```sh
# Creates the dev database provided at $DATABASE_URL in `.env`.
sqlx database create 

# Download, compile and run the application.
cargo run
```
