use monolith::do_request;
use monolith::{Request, Response};
use std::str::FromStr;
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

        let register_response = do_request(&address, register_request).await?;
        let user_id = match register_response {
            Response::UserID(id_string) => Uuid::from_str(&id_string)?,
            _ => return Err("unexpected response type doing register request".into()),
        };

        // Log in
        let login_request = Request::LogIn(test_case.email, test_case.password);
        let login_response = do_request(&address, login_request).await?;
        let token = match login_response {
            Response::Token(token) => token,
            _ => return Err("unexpected response type doing login request".into()),
        };

        // Change first name
        let change_first_name_request =
            Request::ChangeFirstName(token.to_string(), test_case.changed_first_name);
        let change_first_name_response = do_request(&address, change_first_name_request).await?;
        match change_first_name_response {
            Response::Acknowledgment => (),
            _ => return Err("unexpected response type doing change first name request".into()),
        }

        // Delete user
        let delete_user_request = Request::DeleteUser(token.to_string(), user_id.to_string());
        let delete_user_response = do_request(&address, delete_user_request).await?;
        match delete_user_response {
            Response::Acknowledgment => (),
            _ => return Err("unexpected response type doing delete user request".into()),
        }
    }

    Ok(())
}
