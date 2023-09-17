use crate::model::User;
use async_trait::async_trait;
use log::{debug, info};
use sqlx::postgres::PgPool;
use uuid::Uuid;

#[async_trait]
pub trait Repository: Send + Sync {
    async fn user_get(&self, id: &Uuid) -> Result<User, sqlx::Error>;
    async fn user_get_by_email(&self, email: &str) -> Result<User, sqlx::Error>;
    async fn user_create(&self, user: User) -> Result<User, sqlx::Error>;
    async fn user_update(&self, user: &User) -> Result<(), sqlx::Error>;
    async fn user_delete(&self, id: &Uuid) -> Result<(), sqlx::Error>;
}

pub struct Repo {
    conn: PgPool,
}

impl Repo {
    pub fn new(conn: PgPool) -> Repo {
        info!("Constructing new repository.");

        Repo { conn }
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        info!("Running migrations.");

        sqlx::migrate!().run(&self.conn).await?;

        Ok(())
    }
}

#[async_trait]
impl Repository for Repo {
    async fn user_get(&self, id: &Uuid) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, email, first_name, password_hash FROM users WHERE id = $1;",
            id
        )
        .fetch_one(&self.conn)
        .await?;

        debug!("Fetched user: {:?}", &user);

        Ok(user)
    }

    async fn user_get_by_email(&self, email: &str) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "SELECT id, email, first_name, password_hash FROM users WHERE email = $1;",
            email
        )
        .fetch_one(&self.conn)
        .await?;

        debug!("Fetched user by email: {:?}", &user);

        Ok(user)
    }

    async fn user_create(&self, user: User) -> Result<User, sqlx::Error> {
        let result = sqlx::query!(
            "INSERT INTO users (id, email, first_name, password_hash) VALUES ($1, $2, $3, $4);",
            user.id,
            &user.email,
            &user.first_name,
            &user.password_hash,
        )
        .execute(&self.conn)
        .await?;

        debug!("Inserted user: {:?}, result: {:?}", &user, &result);

        Ok(user)
    }

    async fn user_update(&self, user: &User) -> Result<(), sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            "UPDATE users SET first_name = $1, password_hash = $2 WHERE id = $3;",
            user.first_name,
            user.password_hash,
            user.id
        )
        .execute(&self.conn)
        .await?;

        debug!("Updated user: {:?}", &user);

        Ok(())
    }

    async fn user_delete(&self, id: &Uuid) -> Result<(), sqlx::Error> {
        sqlx::query_as!(User, "DELETE FROM users WHERE id = $1;", id)
            .execute(&self.conn)
            .await?;

        debug!("User deleted: {:?}", &id);

        Ok(())
    }
}
