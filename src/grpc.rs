use crate::app::{App, Application, AuthError};
use crate::transport::Transport;
use async_trait::async_trait;
use log::{debug, error, info};
use serde::Deserialize;
use std::sync::Arc;
use tonic::{transport::Server, Request, Response, Status};

use auth::auth_server::{Auth, AuthServer};
use auth::{RegisterRequest, RegisterResponse};

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
            Ok(_user) => {
                let response = auth::RegisterResponse {};
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
}
