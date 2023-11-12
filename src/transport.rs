use crate::app::*;
use async_trait::async_trait;

#[async_trait]
pub trait Transport {
    async fn listen(self, port: u16) -> Result<(), Box<dyn std::error::Error>>;
}

#[async_trait]
pub trait Client {
    async fn register(
        &self,
        request: RegisterRequest,
    ) -> Result<UserIDResponse, Box<dyn std::error::Error>>;
    async fn log_in(
        &self,
        request: LogInRequest,
    ) -> Result<TokenResponse, Box<dyn std::error::Error>>;
    async fn change_first_name(
        &self,
        request: ChangeFirstNameRequest,
    ) -> Result<AcknowledgmentResponse, Box<dyn std::error::Error>>;
    async fn delete_user(
        &self,
        request: DeleteUserRequest,
    ) -> Result<AcknowledgmentResponse, Box<dyn std::error::Error>>;
}
