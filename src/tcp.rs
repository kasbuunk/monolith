use crate::app::*;
use crate::transport::{Client, Transport};
use async_trait::async_trait;
use log::{debug, error, info};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub port: u16,
}

pub struct Listener {
    app: Arc<dyn Application>,
}

impl Listener {
    pub fn new(app: Arc<App>) -> Listener {
        Listener { app }
    }
}

#[async_trait]
impl Transport for Listener {
    async fn listen(self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
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

pub struct TcpClient {
    address: String,
}

impl TcpClient {
    pub async fn new(address: String) -> Result<Self, std::io::Error> {
        debug!("Constructing new tcp client to address: {}.", &address);

        Ok(Self { address })
    }

    pub async fn do_request<T, U>(&self, request: T) -> Result<U, Box<dyn std::error::Error>>
    where
        T: Serialize,
        U: DeserializeOwned,
    {
        let response_serialised = self.send_serialised(request).await?;
        let response: U = ron::de::from_bytes(&response_serialised)?;

        Ok(response)
    }

    async fn send_serialised<T>(&self, request: T) -> Result<Vec<u8>, Box<dyn std::error::Error>>
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
        &self,
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
}

#[async_trait]
impl Client for TcpClient {
    async fn register(
        &self,
        request: RegisterRequest,
    ) -> Result<UserIDResponse, Box<dyn std::error::Error>> {
        Ok(self.do_request(Request::Register(request)).await?)
    }
    async fn log_in(
        &self,
        request: LogInRequest,
    ) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        Ok(self.do_request(Request::LogIn(request)).await?)
    }
    async fn change_first_name(
        &self,
        request: ChangeFirstNameRequest,
    ) -> Result<AcknowledgmentResponse, Box<dyn std::error::Error>> {
        Ok(self.do_request(Request::ChangeFirstName(request)).await?)
    }
    async fn delete_user(
        &self,
        request: DeleteUserRequest,
    ) -> Result<AcknowledgmentResponse, Box<dyn std::error::Error>> {
        Ok(self.do_request(Request::DeleteUser(request)).await?)
    }
}
