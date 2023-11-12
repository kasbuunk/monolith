use monolith::app::*;
use monolith::config::{load_config_from_file, Transport::Http, Transport::Tcp};
use monolith::http::HttpClient;
use monolith::tcp::*;
use monolith::transport::Client;

struct TestCase {
    email: String,
    password: String,
    first_name: String,
    changed_first_name: String,
}

#[tokio::test]
async fn test_http_integration() -> Result<(), Box<dyn std::error::Error>> {
    let configs = vec!["tests/http.ron", "tests/tcp.ron"];

    for config_file_path in configs.iter() {
        let config = load_config_from_file(config_file_path)?;

        let host = "127.0.0.1";

        let client: Box<dyn Client> = match config.transport {
            Tcp(transport_config) => {
                let address = format!("{}:{}", host, transport_config.port);
                Box::new(TcpClient::new(address.clone()).await?)
            }
            Http(transport_config) => {
                let scheme = "http";
                let address = format!("{}://{}:{}", scheme, host, transport_config.port);
                Box::new(HttpClient::new(address.clone())?)
            }
        };

        let test_cases: Vec<TestCase> = vec![
            TestCase {
                email: String::from("bill2@example.com"),
                password: String::from("thisPassw0rd!"),
                first_name: String::from("Bill"),
                changed_first_name: String::from("Jane"),
            },
            TestCase {
                email: String::from("william2@example.com"),
                password: String::from("thatPassw0rd!"),
                first_name: String::from("William"),
                changed_first_name: String::from("Wilma"),
            },
        ];

        for test_case in test_cases {
            // Register
            let register_req = RegisterRequest {
                email: test_case.email.clone(),
                password: test_case.password.clone(),
                first_name: test_case.first_name.clone(),
            };
            let user_id_response = client.register(register_req).await?;

            // Log in
            let login_request = LogInRequest {
                email: test_case.email,
                password: test_case.password,
            };
            let token_response = client.log_in(login_request).await?;

            // Change first name
            let change_first_name_request = ChangeFirstNameRequest {
                token: token_response.token.to_string(),
                first_name: test_case.changed_first_name,
            };
            client.change_first_name(change_first_name_request).await?;

            // Delete user
            let delete_user_request = DeleteUserRequest {
                token: token_response.token.to_string(),
                id: user_id_response.user_id.to_string(),
            };
            client.delete_user(delete_user_request).await?;
        }
    }
    Ok(())
}
