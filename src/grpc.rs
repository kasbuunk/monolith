use crate::app::{App, Application, AuthError};
use crate::transport::Transport;
use async_trait::async_trait;
use log::{error, info};
use serde::Deserialize;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

use auth::auth_server::{Auth, AuthServer};
use auth::{
    ChangeFirstNameRequest, ChangeFirstNameResponse, DeleteUserRequest, DeleteUserResponse,
    LogInRequest, LogInResponse, RegisterRequest, RegisterResponse,
};

pub mod auth {
    tonic::include_proto!("auth");
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub port: u16,
}

pub struct GrpcServer {
    app: Arc<dyn Application>,
}

impl GrpcServer {
    pub fn new(app: Arc<App>) -> GrpcServer {
        GrpcServer { app }
    }
}

#[async_trait]
impl Transport for GrpcServer {
    async fn listen(self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let address = format!("127.0.0.1:{}", port).parse()?;
        let auth_server = AuthServer::new(self);

        info!("Start listening for incoming messages at {}.", address);

        Server::builder()
            .add_service(auth_server)
            .serve(address)
            .await?;

        Ok(())
    }
}

#[tonic::async_trait]
impl Auth for GrpcServer {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        info!("Got a request: {:?}", request);
        let request = request.into_inner();
        let email = request.email;
        let first_name = request.first_name;
        let password = request.password;

        let result = self.app.register(email.clone(), first_name, password).await;
        match result {
            Ok(user) => {
                let response = auth::RegisterResponse {
                    user_id: user.id.to_string(),
                };
                Ok(Response::new(response))
            }
            Err(err) => match err {
                AuthError::IncorrectPassword => {
                    info!("incorrect password attempt for {}", &email);

                    Err(Status::invalid_argument("email and password do not match"))
                }
                _ => {
                    error!("failed to register: {}", err);

                    Err(Status::internal("Internal server error"))
                }
            },
        }
    }

    async fn log_in(
        &self,
        request: Request<LogInRequest>,
    ) -> Result<Response<LogInResponse>, Status> {
        info!("Got a request: {:?}", request);
        let request = request.into_inner();
        let email = request.email;
        let password = request.password;

        let result = self.app.log_in(email.clone(), password).await;
        match result {
            Ok(token) => {
                let response = auth::LogInResponse { token };
                Ok(Response::new(response))
            }
            Err(err) => match err {
                AuthError::IncorrectPassword => {
                    info!("incorrect password attempt for {}", &email);

                    Err(Status::invalid_argument("email and password do not match"))
                }
                _ => {
                    error!("failed to log in: {}", err);

                    Err(Status::internal("Internal server error"))
                }
            },
        }
    }

    async fn change_first_name(
        &self,
        request: Request<ChangeFirstNameRequest>,
    ) -> Result<Response<ChangeFirstNameResponse>, Status> {
        info!("Got a request: {:?}", request);
        let request = request.into_inner();
        let token = request.token;
        let first_name = request.first_name;

        let result = self.app.change_first_name(&token, first_name).await;
        match result {
            Ok(_) => {
                let response = auth::ChangeFirstNameResponse {};
                Ok(Response::new(response))
            }
            Err(err) => {
                error!("failed to change first name: {}", err);

                Err(Status::internal("Internal server error"))
            }
        }
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        info!("Got a request: {:?}", request);
        let request = request.into_inner();
        let token = request.token;
        let user_id = match uuid::Uuid::parse_str(&request.user_id) {
            Ok(id) => id,
            Err(err) => {
                error!("failed to parse uuid: {}", err);

                return Err(Status::internal("Internal server error"));
            }
        };

        let result = self.app.user_delete(&token, user_id).await;
        match result {
            Ok(_) => {
                let response = auth::DeleteUserResponse {};
                Ok(Response::new(response))
            }
            Err(err) => {
                error!("failed to delete use: {}", err);

                Err(Status::internal("Internal server error"))
            }
        }
    }
}
