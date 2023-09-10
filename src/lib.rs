use bcrypt::{hash, verify, DEFAULT_COST};
use sqlx::postgres::PgPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

pub struct TcpTransport {
    app: Arc<App>,
}

impl TcpTransport {
    pub fn new(app: Arc<App>) -> TcpTransport {
        TcpTransport { app }
    }

    pub async fn listen(&self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let address = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(address).await?;

        loop {
            let (mut socket, _) = listener.accept().await?;

            tokio::spawn({
                let app = Arc::clone(&self.app);
                async move {
                    let mut buf = [0; 1024];

                    loop {
                        let n = match socket.read(&mut buf).await {
                            Ok(n) if n == 0 => return,
                            Ok(n) => n,
                            Err(e) => {
                                eprintln!("failed to read from socket; err = {:?}", e);
                                return;
                            }
                        };

                        let buffer_str = match std::str::from_utf8(&buf[..n]) {
                            Ok(s) => s,
                            Err(err) => {
                                eprintln!("Error converting buffer to string: {}", err);
                                return;
                            }
                        };

                        if let Err(e) = handle_request(buffer_str, app.clone(), &mut socket).await {
                            eprintln!("Request handling error: {:?}", e);
                            return;
                        }
                    }
                }
            });
        }
    }
}

async fn handle_request(
    buffer: &str,
    app: Arc<App>,
    socket: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = parse_request(buffer)?;

    match result {
        Request::Register(email, password) => {
            let user_result = app.register(email, password).await?;
            println!("user registered: {:?}", user_result);
        }
        Request::LogIn(email, password) => {
            let user_result = app.log_in(email, password).await?;
            println!("user logged in: {:?}", user_result);
        }
    }

    socket.write_all("acknowlegdment".as_bytes()).await?;
    Ok(())
}

enum Request {
    Register(String, String),
    LogIn(String, String),
}

#[derive(Debug)]
enum ParseError {
    EndpointUnmatched,
    LogIn,
    Register,
}
impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParseError::Register => write!(f, "Parsing register request"),
            ParseError::LogIn => write!(f, "Parsing login request"),
            ParseError::EndpointUnmatched => write!(f, "Could not find endpoint"),
        }
    }
}

impl std::error::Error for ParseError {}

fn parse_request(message: &str) -> Result<Request, ParseError> {
    let mut msg = message.trim().split_whitespace();
    match msg.next() {
        Some("Register") => match (msg.next(), msg.next(), msg.next()) {
            (Some(email), Some(password), None) => Ok(Request::Register(
                String::from(email),
                String::from(password),
            )),
            _ => Err(ParseError::Register),
        },
        Some("LogIn") => match (msg.next(), msg.next(), msg.next()) {
            (Some(email), Some(password), None) => {
                Ok(Request::LogIn(String::from(email), String::from(password)))
            }
            _ => Err(ParseError::LogIn),
        },
        _ => Err(ParseError::EndpointUnmatched),
    }
}

#[derive(Debug, sqlx::FromRow)]
struct User {
    id: Uuid,
    email: String,
    password_hash: String,
}

impl User {
    fn new(email: String, password_hash: String) -> Self {
        User {
            id: Uuid::new_v4(),
            email,
            password_hash,
        }
    }
}

#[derive(Clone)]
pub struct Repository {
    conn: PgPool,
}

impl Repository {
    pub fn new(conn: PgPool) -> Repository {
        Repository { conn }
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        let uuid_extension = "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";";

        let table_users = "
            CREATE TABLE IF NOT EXISTS 
            users (
                id UUID PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL, 
                password_hash VARCHAR(255) NOT NULL
            );";

        let query_result = sqlx::query(uuid_extension).execute(&self.conn).await?;
        println!("migration successful: {:?}", query_result);

        let query_result = sqlx::query(table_users).execute(&self.conn).await?;
        println!("migration successful: {:?}", query_result);

        Ok(())
    }

    async fn user_get(&self, email: String) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, email, password_hash FROM users WHERE email = $1;",
            email
        )
        .fetch_one(&self.conn)
        .await?;

        println!("{:?}", user);
        Ok(user)
    }

    async fn user_create(&self, user: User) -> Result<User, sqlx::Error> {
        let result = sqlx::query!(
            "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3);",
            user.id,
            &user.email,
            &user.password_hash,
        )
        .execute(&self.conn)
        .await?;

        println!("{:?}", result);
        Ok(user)
    }

    async fn user_update(&self, user: User) -> Result<(), sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "UPDATE users SET password_hash = $1 WHERE email = $2;",
            user.password_hash,
            user.email
        )
        .execute(&self.conn)
        .await?;

        println!("{:?}", user);
        Ok(())
    }

    async fn user_delete(&self, user: User) -> Result<(), sqlx::Error> {
        let user = sqlx::query_as!(User, "DELETE FROM users WHERE email = $1;", user.email)
            .execute(&self.conn)
            .await?;

        println!("{:?}", user);
        Ok(())
    }
}

#[derive(Debug)]
enum AuthError {
    IncorrectPassword,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthError::IncorrectPassword => write!(f, "Incorrect password"),
        }
    }
}

impl std::error::Error for AuthError {}

#[derive(Clone)]
pub struct App {
    repository: Repository,
}

impl App {
    pub fn new(repository: Repository) -> App {
        App { repository }
    }

    async fn register(
        &self,
        email: String,
        password: String,
    ) -> Result<User, Box<dyn std::error::Error>> {
        let password_hash = hash(password, DEFAULT_COST)?;
        let user = User::new(email, password_hash);
        let _saved_user = self.repository.user_create(user).await?;
        println!("{:?}", _saved_user);
        Ok(_saved_user)
    }

    async fn log_in(
        &self,
        email: String,
        password: String,
    ) -> Result<User, Box<dyn std::error::Error>> {
        let _user = self.repository.user_get(email).await?;
        if verify(&password, &_user.password_hash)? {
            return Ok(_user);
        }
        Err(Box::new(AuthError::IncorrectPassword))
    }
}
