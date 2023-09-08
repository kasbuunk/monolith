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
                        Ok(Request::Register(email, password)) => app.register(email, password),
                        Ok(Request::LogIn(email, password)) => app.log_in(email, password),
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

#[derive(Debug)]
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
pub enum RepositoryMethod {
    InMemory,
    FileSystem,
    Postgres(String),
}

#[derive(Clone)]
pub struct Repository {
    method: RepositoryMethod,
}

impl Repository {
    pub fn new(method: RepositoryMethod) -> Repository {
        Repository { method }
    }

    fn user_get(&self, email: String) -> User {
        match self.method {
            RepositoryMethod::InMemory => {
                // Pretend to retrieve from database.
                let user_from_db = User {
                    email,
                    password: String::from("password"),
                };

                println!("user retrieved: {:?}", user_from_db);

                user_from_db
            }
            _ => User {
                email: String::from("refactor to error"),
                password: String::from(""),
            },
        }
    }

    fn user_create(&self, user: User) -> User {
        let created_user = User {
            email: user.email,
            password: user.password,
        };

        println!("user created: {:?}", created_user);

        created_user
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

    fn register(&self, email: String, password: String) {
        let user = User::new(email, password);
        let _saved_user = self.repository.user_create(user);
    }

    fn log_in(&self, email: String, _password: String) {
        let _user = self.repository.user_get(email);
    }
}
