use async_trait::async_trait;
use bcrypt::{hash, verify, DEFAULT_COST};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use jwt::VerifyWithKey;
use log::{debug, error, info, warn};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::postgres::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub log_level: String,
    pub tcp: TcpConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Deserialize)]
pub struct TcpConfig {
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub ssl: bool,
}

pub fn load_config_from_file(file_path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let config: Config = ron::de::from_str(&contents)?;
    Ok(config)
}

pub async fn connect_to_database(
    config: DatabaseConfig,
) -> Result<PgPool, Box<dyn std::error::Error>> {
    let connection_string = format!(
        "postgres://{}:{}@{}/{}",
        config.user, config.password, config.host, config.name
    );

    info!(
        "Connecting to postgres://{}:[redacted]@{}/{}",
        config.user, config.host, config.name
    );

    let connection_pool = PgPoolOptions::new().connect(&connection_string).await?;
    return Ok(connection_pool);
}

#[async_trait]
pub trait Transport {
    async fn listen(&self, port: u16) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct TcpTransport {
    app: Arc<dyn Application>,
}

impl TcpTransport {
    pub fn new(app: Arc<App>) -> Box<dyn Transport> {
        Box::new(TcpTransport { app })
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn listen(&self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let address = format!("127.0.0.1:{}", port);

        info!("Start listening for incoming messages at {}.", address);

        let listener = TcpListener::bind(address).await?;

        loop {
            let (mut socket, _) = listener.accept().await?;

            info!("Accepted new message, registered to a new tcp stream.");

            tokio::spawn({
                let app = Arc::clone(&self.app);
                async move {
                    let mut buf = vec![0; 1024];

                    loop {
                        debug!("Reading from socket to buffer.");

                        let n = match socket.read(&mut buf).await {
                            Ok(n) if n == 0 => return,
                            Ok(n) => n,
                            Err(e) => {
                                error!("Failed to read from socket; err = {:?}", e);
                                return;
                            }
                        };

                        let buffer_str = match std::str::from_utf8(&buf[..n]) {
                            Ok(s) => s,
                            Err(err) => {
                                error!("Error converting buffer to string: {}", err);
                                return;
                            }
                        };

                        if let Err(e) = handle_request(buffer_str, app.clone(), &mut socket).await {
                            error!("Request handling error: {:?}", e);
                            return;
                        }

                        debug!("Shutting down socket.");

                        // For all currently defined messages, a response is sufficient.
                        // If more back-and-forth messaging is required, the socket may
                        // be reused for such endpoints.
                        if let Err(e) = socket.shutdown().await {
                            error!("Error shutting down socket: {:?}", e);
                            return;
                        }
                    }
                }
            });
        }
    }
}

async fn handle_request(
    message: &str,
    app: Arc<dyn Application>,
    socket: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = ron::de::from_str(&message)?;

    let response_serialised = match request {
        Request::Register(request) => {
            info!("Handling incoming register request.");

            let user = app
                .register(request.email, request.first_name, request.password)
                .await?;

            debug!("Successfully handled the register request.");

            let response = UserIDResponse {
                user_id: user.id.to_string(),
            };

            ron::ser::to_string(&response)?
        }
        Request::LogIn(request) => {
            info!("Handling incoming log in request.");

            let token = app.log_in(request.email, request.password).await?;

            debug!("Successfully handled the log in request.");

            let response = TokenResponse { token };
            ron::ser::to_string(&response)?
        }
        Request::ChangeFirstName(request) => {
            info!("Handling incoming change first name request.");

            app.change_first_name(&request.token, request.first_name)
                .await?;

            debug!("Successfully handled the change first name request.");

            let response = AcknowledgmentResponse {};
            ron::ser::to_string(&response)?
        }
        Request::DeleteUser(request) => {
            info!("Handling incoming delete user request.");

            let user_id = uuid::Uuid::parse_str(&request.id)?;

            app.user_delete(&request.token, user_id).await?;

            debug!("Successfully handled the delete user request.");

            let response = AcknowledgmentResponse {};
            ron::ser::to_string(&response)?
        }
    };

    socket.write_all(response_serialised.as_bytes()).await?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
pub enum Request {
    Register(RegisterRequest),
    LogIn(LogInRequest),
    ChangeFirstName(ChangeFirstNameRequest),
    DeleteUser(DeleteUserRequest),
}

#[derive(Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub first_name: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LogInRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct ChangeFirstNameRequest {
    pub token: String,
    pub first_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeleteUserRequest {
    pub token: String,
    pub id: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserIDResponse {
    pub user_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct AcknowledgmentResponse {}

pub struct TcpClient {
    address: String,
}

impl TcpClient {
    pub async fn new(address: String) -> Result<Self, std::io::Error> {
        debug!("Constructing new tcp client to address: {}.", &address);

        Ok(Self { address })
    }

    pub async fn do_request<'a, T, U>(
        &'a mut self,
        request: T,
    ) -> Result<U, Box<dyn std::error::Error>>
    where
        T: Serialize,
        U: DeserializeOwned,
    {
        let response_serialised = self.send_serialised(request).await?;
        let response: U = ron::de::from_bytes(&response_serialised)?;

        Ok(response)
    }

    async fn send_serialised<T>(
        &mut self,
        request: T,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>
    where
        T: Serialize,
    {
        let request_serialised = ron::ser::to_string(&request)?;

        debug!("request_serialised: {}", request_serialised);

        let response_serialised = self
            .exchange_messages(request_serialised.as_bytes())
            .await?;

        debug!(
            "response_serialised: {}",
            String::from_utf8(response_serialised.clone())?,
        );

        Ok(response_serialised)
    }

    async fn exchange_messages(
        &mut self,
        message: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(self.address.clone()).await?;

        debug!("Writing the request to the tcp stream.");
        stream.write_all(message).await?;

        debug!("Reading the server's response from the tcp stream.");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;

        debug!("Closing the tcp stream.");
        stream.shutdown().await?;

        Ok(response)
    }

    pub async fn register(
        &mut self,
        request: RegisterRequest,
    ) -> Result<UserIDResponse, Box<dyn std::error::Error>> {
        Ok(self.do_request(Request::Register(request)).await?)
    }
    pub async fn log_in(
        &mut self,
        request: LogInRequest,
    ) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        Ok(self.do_request(Request::LogIn(request)).await?)
    }
    pub async fn change_first_name(
        &mut self,
        request: ChangeFirstNameRequest,
    ) -> Result<AcknowledgmentResponse, Box<dyn std::error::Error>> {
        Ok(self.do_request(Request::ChangeFirstName(request)).await?)
    }
    pub async fn delete_user(
        &mut self,
        request: DeleteUserRequest,
    ) -> Result<AcknowledgmentResponse, Box<dyn std::error::Error>> {
        Ok(self.do_request(Request::DeleteUser(request)).await?)
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    id: Uuid,
    email: String,
    first_name: String,
    password_hash: String,
}

impl User {
    fn new(email: String, first_name: String, password_hash: String) -> Self {
        let id = Uuid::new_v4();
        debug!("Constructing new user with id: {}, email: {}.", &id, &email);

        User {
            id,
            email,
            first_name,
            password_hash,
        }
    }
}

#[async_trait]
pub trait Repository: Send + Sync {
    async fn user_get(&self, id: &Uuid) -> Result<User, sqlx::Error>;
    async fn user_get_by_email(&self, email: &str) -> Result<User, sqlx::Error>;
    async fn user_create(&self, user: User) -> Result<User, sqlx::Error>;
    async fn user_update(&self, user: &User) -> Result<(), sqlx::Error>;
    async fn user_delete(&self, id: &Uuid) -> Result<(), sqlx::Error>;
}

pub struct Repo {
    conn: PgPool,
}

impl Repo {
    pub fn new(conn: PgPool) -> Repo {
        info!("Constructing new repository.");

        Repo { conn }
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        info!("Running migrations.");

        sqlx::migrate!().run(&self.conn).await?;

        Ok(())
    }
}

#[async_trait]
impl Repository for Repo {
    async fn user_get(&self, id: &Uuid) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, email, first_name, password_hash FROM users WHERE id = $1;",
            id
        )
        .fetch_one(&self.conn)
        .await?;

        debug!("Fetched user: {:?}", &user);

        Ok(user)
    }

    async fn user_get_by_email(&self, email: &str) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, email, first_name, password_hash FROM users WHERE email = $1;",
            email
        )
        .fetch_one(&self.conn)
        .await?;

        debug!("Fetched user by email: {:?}", &user);

        Ok(user)
    }

    async fn user_create(&self, user: User) -> Result<User, sqlx::Error> {
        let result = sqlx::query!(
            "INSERT INTO users (id, email, first_name, password_hash) VALUES ($1, $2, $3, $4);",
            user.id,
            &user.email,
            &user.first_name,
            &user.password_hash,
        )
        .execute(&self.conn)
        .await?;

        debug!("Inserted user: {:?}, result: {:?}", &user, &result);

        Ok(user)
    }

    async fn user_update(&self, user: &User) -> Result<(), sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "UPDATE users SET first_name = $1, password_hash = $2 WHERE id = $3;",
            user.first_name,
            user.password_hash,
            user.id
        )
        .execute(&self.conn)
        .await?;

        debug!("Updated user: {:?}", &user);

        Ok(())
    }

    async fn user_delete(&self, id: &Uuid) -> Result<(), sqlx::Error> {
        sqlx::query_as!(User, "DELETE FROM users WHERE id = $1;", id)
            .execute(&self.conn)
            .await?;

        debug!("User deleted: {:?}", &id);

        Ok(())
    }
}

#[derive(Debug)]
enum AuthError {
    IncorrectPassword,
    UserDoesNotOwnToken,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthError::IncorrectPassword => write!(f, "Incorrect password"),
            AuthError::UserDoesNotOwnToken => write!(
                f,
                "The user that owns the token attempts a privileged operation for a different user"
            ),
        }
    }
}

impl std::error::Error for AuthError {}

#[async_trait]
pub trait Application: Send + Sync {
    async fn register(
        &self,
        email: String,
        first_name: String,
        password: String,
    ) -> Result<User, Box<dyn std::error::Error>>;
    async fn log_in(
        &self,
        email: String,
        password: String,
    ) -> Result<String, Box<dyn std::error::Error>>;
    async fn user_delete(
        &self,
        token: &str,
        id: uuid::Uuid,
    ) -> Result<(), Box<dyn std::error::Error>>;
    async fn change_first_name(
        &self,
        token: &str,
        name: String,
    ) -> Result<(), Box<dyn std::error::Error>>;
    fn verify_claims(&self, token: &str) -> Result<BTreeMap<String, String>, jwt::Error>;
}

pub struct App {
    repository: Arc<dyn Repository>,
    signing_key: Hmac<Sha256>,
}

impl App {
    pub fn new(
        repository: Arc<Repo>,
        signing_secret: &[u8],
    ) -> Result<App, Box<dyn std::error::Error>> {
        info!("Constructing new app.");

        let key = Hmac::new_from_slice(signing_secret)?;

        Ok(App {
            repository,
            signing_key: key,
        })
    }
}

#[async_trait]
impl Application for App {
    async fn register(
        &self,
        email: String,
        first_name: String,
        password: String,
    ) -> Result<User, Box<dyn std::error::Error>> {
        debug!("Registering user: {}", &email);

        let password_hash = hash(password, DEFAULT_COST)?;
        let user = User::new(email, first_name, password_hash);
        let saved_user = self.repository.user_create(user).await?;

        info!("Registered user: {:?}", &saved_user);

        Ok(saved_user)
    }

    async fn log_in(
        &self,
        email: String,
        password: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        debug!("Logging in user: {:?}", &email);

        let user = self.repository.user_get_by_email(&email).await?;
        if !verify(&password, &user.password_hash)? {
            info!("Verification of password failed.");

            return Err(Box::new(AuthError::IncorrectPassword));
        };

        let token = sign_jwt(&user, &self.signing_key)?;
        self.verify_claims(&token)?;

        info!("Logged in user: {:?}", &user);

        Ok(token)
    }

    async fn user_delete(
        &self,
        token: &str,
        id: uuid::Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Deleting user: {:?}", &id);

        let claims: BTreeMap<String, String> = self.verify_claims(token)?;
        if !user_owns_token(&id, &claims) {
            warn!(
                "User attempts a privileged operation for user_id={:?}, but does not own the provided token, subject: {:?}",
                &id,
                &claims["sub"]
            );

            return Err(Box::new(AuthError::UserDoesNotOwnToken));
        }
        self.repository.user_delete(&id).await?;

        info!("Deleted user with id: {:?}", &id);

        Ok(())
    }

    async fn change_first_name(
        &self,
        token: &str,
        name: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Changing first name to {}", &name);

        let claims: BTreeMap<String, String> = self.verify_claims(token)?;
        let subject = String::from("sub");
        let user_id = Uuid::parse_str(claims.get(&subject).unwrap())?;
        let mut user = self.repository.user_get(&user_id).await?;
        user.first_name = name;

        self.repository.user_update(&user).await?;

        debug!("Changed first name of user: {:?}", &user);

        Ok(())
    }

    fn verify_claims(&self, token: &str) -> Result<BTreeMap<String, String>, jwt::Error> {
        let claims: BTreeMap<String, String> = token.verify_with_key(&self.signing_key)?;
        Ok(claims)
    }
}

fn user_owns_token(id: &uuid::Uuid, claims: &BTreeMap<String, String>) -> bool {
    claims["sub"] == id.to_string()
}

fn sign_jwt(user: &User, key: &Hmac<Sha256>) -> Result<String, jwt::Error> {
    debug!("Signing JWT for user: {:?}", user);

    let mut claims = BTreeMap::new();
    claims.insert("sub", String::from(&user.id.to_string()));

    let token_str = claims.sign_with_key(key)?;

    Ok(token_str)
}
