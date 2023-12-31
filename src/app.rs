use crate::model::User;
use crate::repository::{Repo, Repository};
use async_trait::async_trait;
use bcrypt::{hash, verify, DEFAULT_COST};
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug)]
pub enum AuthError {
    IncorrectPassword,
    UserDoesNotOwnToken,
    Unknown(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthError::IncorrectPassword => write!(f, "Incorrect password"),
            AuthError::UserDoesNotOwnToken => write!(
                f,
                "The user that owns the token attempts a privileged operation for a different user"
            ),
            AuthError::Unknown(err) => write!(f, "Unknown error: {}", err),
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
    ) -> Result<User, AuthError>;
    async fn log_in(&self, email: String, password: String) -> Result<String, AuthError>;
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
    ) -> Result<User, AuthError> {
        debug!("Registering user: {}", &email);

        let password_hash = match hash(password, DEFAULT_COST) {
            Ok(hash) => hash,
            Err(err) => return Err(AuthError::Unknown(Box::new(err))),
        };
        let user = User::new(email, first_name, password_hash);
        let saved_user = match self.repository.user_create(user).await {
            Ok(user) => user,
            Err(err) => return Err(AuthError::Unknown(Box::new(err))),
        };

        info!("Registered user: {:?}", &saved_user.id);

        Ok(saved_user)
    }

    async fn log_in(&self, email: String, password: String) -> Result<String, AuthError> {
        debug!("Logging in user: {:?}", &email);

        let user = match self.repository.user_get_by_email(&email).await {
            Ok(user) => user,
            Err(err) => return Err(AuthError::Unknown(Box::new(err))),
        };
        let verified = match verify(&password, &user.password_hash) {
            Ok(verified) => verified,
            Err(err) => return Err(AuthError::Unknown(Box::new(err))),
        };
        if !verified {
            info!("Verification of password failed.");

            return Err(AuthError::IncorrectPassword);
        };

        let token = match sign_jwt(&user, &self.signing_key) {
            Ok(token) => token,
            Err(err) => return Err(AuthError::Unknown(Box::new(err))),
        };
        match self.verify_claims(&token) {
            Ok(_) => (),
            Err(err) => return Err(AuthError::Unknown(Box::new(err))),
        };

        info!("Logged in user: {:?}", &user.id);

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

        debug!("Changed first name of user: {:?}", &user.id);

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
    debug!("Signing JWT for user: {:?}", user.id);

    let mut claims = BTreeMap::new();
    claims.insert("sub", String::from(&user.id.to_string()));

    let token_str = claims.sign_with_key(key)?;

    Ok(token_str)
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
