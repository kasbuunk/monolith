use crate::app::*;
use crate::transport::{Client, Transport};
use async_trait::async_trait;
use log::{error, info};
use reqwest;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use axum::{
    extract::{Json, State},
    http::StatusCode,
    routing::post,
    Router,
};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub port: u16,
}

enum ApiEndpoint {
    Register,
    LogIn,
    ChangeFirstName,
    DeleteUser,
}

impl ApiEndpoint {
    fn to_string(&self) -> &'static str {
        match self {
            ApiEndpoint::Register => "/register",
            ApiEndpoint::LogIn => "/login",
            ApiEndpoint::ChangeFirstName => "/change_first_name",
            ApiEndpoint::DeleteUser => "/delete_user",
        }
    }
}

pub struct Server {
    router: Router,
}

impl Server {
    pub fn new(app: Arc<dyn Application>) -> Server {
        let router = Router::new()
            .route(ApiEndpoint::Register.to_string(), post(register))
            .route(ApiEndpoint::LogIn.to_string(), post(login))
            .route(
                ApiEndpoint::ChangeFirstName.to_string(),
                post(change_first_name),
            )
            .route(ApiEndpoint::DeleteUser.to_string(), post(delete_user))
            .with_state(app);

        Server { router }
    }
}

#[async_trait]
impl Transport for Server {
    async fn listen(self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let address = format!("127.0.0.1:{}", port);

        axum::Server::bind(&address.parse()?)
            .serve(self.router.into_make_service())
            .await?;

        Ok(())
    }
}

async fn register(
    State(app): State<Arc<dyn Application>>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<UserIDResponse>, (StatusCode, String)> {
    let user = match app
        .register(request.email, request.first_name, request.password)
        .await
    {
        Ok(user) => user,
        Err(err) => {
            error!("Failed to register user: {}", err);

            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Unknown error".into()));
        }
    };

    info!("Successfully handled the register request.");

    Ok(Json(UserIDResponse {
        user_id: user.id.to_string(),
    }))
}

async fn login(
    State(app): State<Arc<dyn Application>>,
    Json(request): Json<LogInRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let token = match app.log_in(request.email, request.password).await {
        Ok(token) => token,
        Err(err) => {
            error!("Failed to log in user: {}", err);

            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Unknown error".into()));
        }
    };

    info!("Successfully handled the login request.");

    Ok(Json(TokenResponse { token }))
}

async fn change_first_name(
    State(app): State<Arc<dyn Application>>,
    Json(request): Json<ChangeFirstNameRequest>,
) -> Result<Json<AcknowledgmentResponse>, (StatusCode, String)> {
    match app
        .change_first_name(&request.token, request.first_name)
        .await
    {
        Ok(token) => token,
        Err(err) => {
            error!("Failed to change first name: {}", err);

            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Unknown error".into()));
        }
    };

    info!("Successfully handled the change first name request.");

    Ok(Json(AcknowledgmentResponse {}))
}

async fn delete_user(
    State(app): State<Arc<dyn Application>>,
    Json(request): Json<DeleteUserRequest>,
) -> Result<Json<AcknowledgmentResponse>, (StatusCode, String)> {
    let user_id: Uuid = match request.id.parse::<Uuid>() {
        Ok(id) => id,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Could not parse user id as uuid: {}", e),
            ))
        }
    };

    match app.user_delete(&request.token, user_id).await {
        Ok(token) => token,
        Err(err) => {
            error!("Failed to delete user: {}", err);

            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Unknown error".into()));
        }
    };

    info!("Successfully handled the delete user request.");

    Ok(Json(AcknowledgmentResponse {}))
}

pub struct HttpClient {
    client: reqwest::Client,
    base_url: String,
}

impl HttpClient {
    pub fn new(base_url: String) -> Result<HttpClient, Box<dyn std::error::Error>> {
        let client = reqwest::Client::builder().build()?;
        Ok(HttpClient { client, base_url })
    }

    async fn send_request<T: Serialize, U: DeserializeOwned>(
        &self,
        request: T,
        endpoint: ApiEndpoint,
    ) -> Result<U, Box<dyn std::error::Error>> {
        let url = reqwest::Url::parse(&format!("{}{}", self.base_url, endpoint.to_string()))?;

        let response = self
            .client
            .request(reqwest::Method::POST, url)
            .json(&request)
            .send()
            .await?
            .json::<U>()
            .await?;

        Ok(response)
    }
}

#[async_trait]
impl Client for HttpClient {
    async fn register(
        &self,
        request: RegisterRequest,
    ) -> Result<UserIDResponse, Box<dyn std::error::Error>> {
        self.send_request(request, ApiEndpoint::Register).await
    }
    async fn log_in(
        &self,
        request: LogInRequest,
    ) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        self.send_request(request, ApiEndpoint::LogIn).await
    }
    async fn change_first_name(
        &self,
        request: ChangeFirstNameRequest,
    ) -> Result<AcknowledgmentResponse, Box<dyn std::error::Error>> {
        self.send_request(request, ApiEndpoint::ChangeFirstName)
            .await
    }
    async fn delete_user(
        &self,
        request: DeleteUserRequest,
    ) -> Result<AcknowledgmentResponse, Box<dyn std::error::Error>> {
        self.send_request(request, ApiEndpoint::DeleteUser).await
    }
}
