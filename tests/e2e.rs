use monolith::app;
use monolith::config::{load_config_from_file, Transport::Grpc, Transport::Http, Transport::Tcp};
use monolith::http::HttpClient;
use monolith::tcp::TcpClient;
use monolith::transport::Client;

struct TestCase {
    email: String,
    password: String,
    first_name: String,
    changed_first_name: String,
}

pub mod proto {
    tonic::include_proto!("auth");
}

use proto::auth_client::AuthClient;
use proto::RegisterRequest;

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
            _ => panic!("Not implemented"),
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
            let register_req = app::RegisterRequest {
                email: test_case.email.clone(),
                password: test_case.password.clone(),
                first_name: test_case.first_name.clone(),
            };
            let user_id_response = client.register(register_req).await?;

            // Log in
            let login_request = app::LogInRequest {
                email: test_case.email,
                password: test_case.password,
            };
            let token_response = client.log_in(login_request).await?;

            // Change first name
            let change_first_name_request = app::ChangeFirstNameRequest {
                token: token_response.token.to_string(),
                first_name: test_case.changed_first_name,
            };
            client.change_first_name(change_first_name_request).await?;

            // Delete user
            let delete_user_request = app::DeleteUserRequest {
                token: token_response.token.to_string(),
                id: user_id_response.user_id.to_string(),
            };
            client.delete_user(delete_user_request).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_grpc() -> Result<(), Box<dyn std::error::Error>> {
    let config_file_path = "tests/grpc.ron";

    let config = load_config_from_file(config_file_path)?;

    let host = "127.0.0.1";

    let mut client = match config.transport {
        Grpc(transport_config) => {
            AuthClient::connect(format!("http://{}:{}", host, transport_config.port)).await?
        }
        _ => panic!("Not implemented"),
    };

    let test_cases: Vec<TestCase> = vec![
        TestCase {
            email: String::from("john@example.com"),
            password: String::from("thisPassw0rd!"),
            first_name: String::from("john"),
            changed_first_name: String::from("Jane"),
        },
        TestCase {
            email: String::from("will@example.com"),
            password: String::from("thatPassw0rd!"),
            first_name: String::from("Will"),
            changed_first_name: String::from("Wilma"),
        },
    ];

    for test_case in test_cases {
        // Register
        let register_req = tonic::Request::new(RegisterRequest {
            email: test_case.email.clone(),
            password: test_case.password.clone(),
            first_name: test_case.first_name.clone(),
        });
        let user_id_response = client.register(register_req).await?.into_inner();

        // Log in
        let login_request = tonic::Request::new(proto::LogInRequest {
            email: test_case.email.into(),
            password: test_case.password.into(),
        });
        let token_response = client.log_in(login_request).await?.into_inner();

        // Change first name
        let change_first_name_request = tonic::Request::new(proto::ChangeFirstNameRequest {
            token: token_response.token.to_string().into(),
            first_name: test_case.changed_first_name.into(),
        });
        client.change_first_name(change_first_name_request).await?;

        // Delete user
        let delete_user_request = tonic::Request::new(proto::DeleteUserRequest {
            token: token_response.token.to_string().into(),
            user_id: user_id_response.user_id.to_string().into(),
        });
        client.delete_user(delete_user_request).await?;
    }

    Ok(())
}
