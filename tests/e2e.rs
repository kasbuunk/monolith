use monolith::Request;
use ron;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

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
        let register_request = Request::Register(
            test_case.email.clone(),
            test_case.first_name,
            test_case.password.clone(),
        );
        let request_serialised = ron::ser::to_string(&register_request)?;

        let register_response = send_tcp_message(&address, request_serialised.as_bytes()).await?;
        let mut uuid_bytes: [u8; 16] = Default::default();
        uuid_bytes.copy_from_slice(&register_response);
        let user_id = Uuid::from_bytes(uuid_bytes);

        // Log in
        let login_request = Request::LogIn(test_case.email, test_case.password);
        let login_request_serialised = ron::ser::to_string(&login_request)?;
        let token_vec = send_tcp_message(&address, login_request_serialised.as_bytes()).await?;
        let token = String::from_utf8_lossy(&token_vec);

        // Change first name
        let change_first_name_request =
            Request::ChangeFirstName(token.to_string(), test_case.changed_first_name);
        let change_first_name_request_serialised = ron::ser::to_string(&change_first_name_request)?;
        let acknowledgment =
            send_tcp_message(&address, change_first_name_request_serialised.as_bytes()).await?;
        let acknowledgment_str = String::from_utf8_lossy(&acknowledgment);

        assert_eq!(acknowledgment_str, "ok");

        // Delete user
        let delete_request = Request::DeleteUser(token.to_string(), user_id.to_string());
        let delete_request_serialised = ron::ser::to_string(&delete_request)?;
        let acknowledgment =
            send_tcp_message(&address, delete_request_serialised.as_bytes()).await?;
        let acknowledgment_str = String::from_utf8_lossy(&acknowledgment);

        assert_eq!(acknowledgment_str, "ok");
    }

    Ok(())
}

async fn send_tcp_message(
    address: &str,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Establish a connection to the application's TCP server.
    let mut stream = TcpStream::connect(address).await?;
    // Send a request to the server.
    stream.write_all(request).await?;

    // Read the response from the server.
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    Ok(response)
}
