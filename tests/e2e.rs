use monolith::*;

struct TestCase {
    email: String,
    password: String,
    first_name: String,
    changed_first_name: String,
}

#[tokio::test]
async fn test_tcp_integration() -> Result<(), Box<dyn std::error::Error>> {
    let port = 8080;
    let host = "127.0.0.1";
    let address = format!("{}:{}", host, port);

    let mut client = TcpClient::new(address.clone()).await?;

    let test_cases: Vec<TestCase> = vec![
        TestCase {
            email: String::from("john@example.com"),
            password: String::from("thisPassw0rd!"),
            first_name: String::from("John"),
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

    Ok(())
}
