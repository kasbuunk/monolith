use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct TestCase<T, U> {
    input: T,
    expected_output: U,
}

#[tokio::test]
async fn test_tcp_integration() -> Result<(), Box<dyn std::error::Error>> {
    let port = 8080;
    let host = "127.0.0.1";
    let address = format!("{}:{}", host, port);

    // Establish a connection to the application's TCP server.
    let mut stream = TcpStream::connect(&address).await?;

    let test_cases: Vec<TestCase<&[u8], String>> = vec![TestCase {
        input: b"Register john@example.com John myPassw0rd!",
        expected_output: String::from("acknowledgment"),
    }];

    for test_case in test_cases {
        // Send a request to the server.
        stream.write_all(&test_case.input).await?;

        // Read the response from the server.
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;

        // Perform assertions on the response.
        let response_str = String::from_utf8_lossy(&response);
        assert_eq!(response_str, test_case.expected_output);
    }

    Ok(())
}
