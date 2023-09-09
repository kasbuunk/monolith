use sqlx::postgres::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub struct TcpTransport {
    app: App,
}

impl TcpTransport {
    pub fn new(app: App) -> TcpTransport {
        TcpTransport { app }
    }

    pub async fn listen(&self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let address = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(address).await?;

        loop {
            let (mut socket, _) = listener.accept().await?;

            let app = self.app.clone();

            tokio::spawn(async move {
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

                    let result = parse_request(buffer_str);
                    match result {
                        Ok(Request::Register(email, password)) => {
                            app.register(email, password).await
                        }
                        Ok(Request::LogIn(email, password)) => app.log_in(email, password).await,
                        Err(e) => {
                            eprintln!("failed to parse request: {:?}", e);
                            return;
                        }
                    };

                    if let Err(e) = socket.write_all("acknowledgment".as_bytes()).await {
                        eprintln!("failed to write to socket; err = {:?}", e);
                        return;
                    }
                }
            });
        }
    }
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
    email: String,
    password: String,
}

impl User {
    fn new(email: String, password: String) -> User {
        User { email, password }
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
        let table_users = "
            CREATE TABLE IF NOT EXISTS 
            users (
                email VARCHAR(255) UNIQUE PRIMARY KEY, 
                password VARCHAR(255) NOT NULL
            );";

        let query_result = sqlx::query(table_users).execute(&self.conn).await?;

        println!("migration successful: {:?}", query_result);

        Ok(())
    }

    async fn user_get(&self, email: String) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1;", email)
            .fetch_one(&self.conn)
            .await?;

        println!("{:?}", user);
        Ok(user)
    }

    async fn user_create(&self, user: User) -> Result<User, sqlx::Error> {
        let result = sqlx::query("INSERT INTO users (email, password) VALUES ($1, $2);")
            .bind(&user.email)
            .bind(&user.password)
            .execute(&self.conn)
            .await?;

        println!("{:?}", result);
        Ok(user)
    }
}

#[derive(Clone)]
pub struct App {
    repository: Repository,
}

impl App {
    pub fn new(repository: Repository) -> App {
        App { repository }
    }

    async fn register(&self, email: String, password: String) {
        let user = User::new(email, password);
        let _saved_user = self.repository.user_create(user).await;
        println!("{:?}", _saved_user);
    }

    async fn log_in(&self, email: String, _password: String) {
        let _user = self.repository.user_get(email).await;
    }
}
