use log::debug;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub password_hash: String,
}

impl User {
    pub fn new(email: String, first_name: String, password_hash: String) -> Self {
        let id = Uuid::new_v4();
        debug!("Constructing new user with id: {}, email: {}.", &id, &email);

        User {
            id,
            email,
            first_name,
            password_hash,
        }
    }
}
