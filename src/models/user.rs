use super::clean_html;
use super::our_date_time::OurDateTime;
use super::pagination::{Pagination, DEFAULT_LIMIT};
use super::user_status::UserStatus;
use crate::fairings::db::DBConnection;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{NaiveDateTime, TimeZone, Utc};
use mysql_async::{params, prelude::*, Pool};
use regex::Regex;
use rocket::form::{self, Error as FormError, FromForm};
use std::error::Error;
use uuid::Uuid;
use zxcvbn::zxcvbn;

#[derive(Debug, PartialEq, Eq, FromForm)]
pub struct User {
    pub uuid: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub description: String,
    pub status: UserStatus,
    pub created_at: OurDateTime,
    pub updated_at: OurDateTime,
}

impl User {
    pub async fn find(pool: &Pool, uuid: &str) -> Result<Self, Box<dyn Error>> {
        // Acquire an async connection from the pool
        let mut conn = pool.get_conn().await?;

        // SELECT only the fields you need
        let row: Option<(String, String, String, String, String, i32, NaiveDateTime, NaiveDateTime)> = conn
            .exec_first(
                "SELECT uuid, username, email, password_hash, description, status, created_at, updated_at FROM users2 WHERE uuid = :uuid LIMIT 1",
                params! { "uuid" => uuid },
            )
            .await?;

        // Convert the row (tuple) into your `User` struct
        match row {
            Some((
                uuid,
                username,
                email,
                password_hash,
                description,
                status_i32,
                created_naive,
                updated_naive,
            )) => {
                // Convert i32 -> i8 -> UserStatus
                let user_status = match UserStatus::try_from(status_i32 as i8) {
                    Ok(s) => s,
                    Err(_) => UserStatus::Inactive, // or handle error differently
                };

                let created_at = OurDateTime(Utc.from_utc_datetime(&created_naive));
                let updated_at = OurDateTime(Utc.from_utc_datetime(&updated_naive));

                Ok(User {
                    uuid,
                    username,
                    email,
                    password_hash,
                    description,
                    status: user_status,
                    // If your table has datetime columns, fetch them & convert to OurDateTime
                    created_at,
                    updated_at,
                })
            }
            None => Err("User not found".into()),
        }
    }

    pub async fn find_all(pool: &Pool) -> Result<Vec<Self>, Box<dyn Error>> {
        // Acquire an async connection from the pool
        // We'll ignore the pagination for now
        return Self::find_all_without_pagination(pool).await;
    }

    async fn find_all_without_pagination(pool: &Pool) -> Result<(Vec<Self>), Box<dyn Error>> {
        // Acquire an async connection from the pool
        let mut conn = pool.get_conn().await?;

        let query_str = "SELECT * FROM users2 ORDER BY created_at DESC LIMIT :limit";
        // let mut new_pagination: Option<Pagination> = None;

        // get all users from users2 table
        let users: Vec<(
            String,
            String,
            String,
            String,
            String,
            i32,
            NaiveDateTime,
            NaiveDateTime,
        )> = conn
            .exec(query_str, params! { "limit" => DEFAULT_LIMIT })
            .await?;

        // converts users to an array of User structs
        let users: Vec<User> = users
            .into_iter()
            .map(
                |(
                    uuid,
                    username,
                    email,
                    password_hash,
                    description,
                    status_i32,
                    created_naive,
                    updated_naive,
                )| {
                    // Convert i32 -> i8 -> UserStatus
                    let user_status = match UserStatus::try_from(status_i32 as i8) {
                        Ok(s) => s,
                        Err(_) => UserStatus::Inactive, // or handle error differently
                    };

                    let created_at = OurDateTime(Utc.from_utc_datetime(&created_naive));
                    let updated_at = OurDateTime(Utc.from_utc_datetime(&updated_naive));

                    User {
                        uuid,
                        username,
                        email,
                        password_hash,
                        description,
                        status: user_status,
                        // If your table has datetime columns, fetch them & convert to OurDateTime
                        created_at,
                        updated_at,
                    }
                },
            )
            .collect();

        Ok((users))
    }

    pub async fn update(
        pool: &Pool,
        uuid: &str,
        edited_user: &EditedUser<'_>,
    ) -> Result<Self, Box<dyn Error>> {
        // Acquire an async connection from the pool
        let mut conn = pool.get_conn().await?;
        let old_user = Self::find(pool, uuid).await?;

        let now = chrono::Utc::now().naive_utc();

        // Clean user-supplied HTML
        let username = clean_html(edited_user.username);
        let description = edited_user
            .description
            .map(|desc| clean_html(desc))
            .unwrap_or_default();

        // Because we can change the password or skip changing the password depending on whether or not we have old_password or not, prepare the query items
        let mut set_strings = vec![
            "username = :username",
            "email = :email",
            "description = :description",
            "updated_at = :updated_at",
        ];
        let mut where_string = ":uuid";
        let mut password_string = String::new();
        let is_with_password = !edited_user.old_password.is_empty();

        // Hash the password
        if is_with_password {
            let old_password_hash = PasswordHash::new(&old_user.password_hash)
                .map_err(|_| "cannot read password hash")?;
            let argon2 = Argon2::default();
            argon2
                .verify_password(edited_user.password.as_bytes(), &old_password_hash)
                .map_err(|_| "cannot confirm old password")?;
            let salt = SaltString::generate(&mut OsRng);
            let new_hash = argon2
                .hash_password(edited_user.password.as_bytes(), &salt)
                .map_err(|_| "cannot create password hash")?;
            password_string.push_str(new_hash.to_string().as_ref());
            set_strings.push("password_hash = $5");
            where_string = "$6";
        }

        // Update the user in the MySQL database
        // first create the query string
        let query_str = format!(
            "UPDATE users2 SET {}
            WHERE uuid = {}",
            set_strings.join(", "),
            where_string
        );

        // then execute the query
        // we only want to update the password if is_with_password is true
        let params = if is_with_password {
            params! {
                "username" => username,
                "email" => edited_user.email,
                "description" => description,
                "updated_at" => now,
                "password_hash" => password_string,
                "uuid" => uuid,
            }
        } else {
            params! {
                "username" => username,
                "email" => edited_user.email,
                "description" => description,
                "updated_at" => now,
                "uuid" => uuid,
            }
        };

        conn.exec_drop(&query_str, params).await?;

        // Re-select the updated row by uuid
        let row_opt: Option<(
            String,         // uuid
            String,         // username
            String,         // email
            String,         // password_hash
            String,         // description
            i8,             // status
            chrono::NaiveDateTime,  // created_at
            chrono::NaiveDateTime,  // updated_at
        )> = conn
            .exec_first(
                "SELECT uuid, username, email, password_hash, description, status, created_at, updated_at
                 FROM users2
                 WHERE uuid = :uuid
                 LIMIT 1",
                params! {
                    "uuid" => uuid,
                },
            )
            .await?;

        match row_opt {
            Some((
                uuid_str,
                username,
                email,
                password_hash,
                description,
                status_i8,
                created_naive,
                updated_naive,
            )) => {
                // Convert i8 -> UserStatus
                let user_status = UserStatus::try_from(status_i8).unwrap_or(UserStatus::Inactive);

                // Convert NaiveDateTime -> DateTime<Utc>
                let created_at = OurDateTime(chrono::Utc.from_utc_datetime(&created_naive));
                let updated_at = OurDateTime(chrono::Utc.from_utc_datetime(&updated_naive));

                Ok(User {
                    uuid: uuid_str,
                    username,
                    email,
                    password_hash,
                    description,
                    status: user_status,
                    created_at,
                    updated_at,
                })
            }
            None => Err("Failed to re-select updated user".into()),
        }
    }

    pub async fn create(pool: &Pool, new_user: &NewUser<'_>) -> Result<Self, Box<dyn Error>> {
        println!("new_user received by fn create: {:?}", new_user);

        // Generate a new UUID
        let uuid = Uuid::new_v4();

        // Clean user-supplied HTML
        let username = clean_html(new_user.username);
        let description = new_user
            .description
            .map(|desc| clean_html(desc))
            .unwrap_or_default();

        // Hash the password
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(new_user.password.as_bytes(), &salt)
            .map_err(|_| "cannot create password hash")?
            .to_string();

        // Insert into the MySQL database
        // MySQL does not support "RETURNING *", so we do an INSERT first...
        println!("Inserting new user into the database");
        {
            let mut conn = match pool.get_conn().await {
                Ok(conn) => conn,
                Err(e) => {
                    println!("Failed to get database connection: {}", e);
                    return Err(Box::new(e));
                }
            };

            match conn
        .exec_drop(
            r"INSERT INTO users2 (uuid, username, email, password_hash, description, status, created_at, updated_at)
              VALUES (:uuid, :username, :email, :password_hash, :description, :status, :created_at, :updated_at)",
            params! {
                "uuid" => uuid.to_string(),
                "username" => username,
                "email" => new_user.email,
                "password_hash" => password_hash,
                "description" => description,
                "status" => i8::from(UserStatus::Inactive), // Convert enum -> i8
                "created_at" => chrono::Utc::now().naive_utc(),
                "updated_at" => chrono::Utc::now().naive_utc(),
            },
        )
        .await
    {
        Ok(_) => println!("Insert successful"),
        Err(mysql_async::Error::Server(err)) => {
            // Handle MySQL server-side errors (like duplicate entries)
            if err.code == 1062 {
                println!("Insert failed: Duplicate entry error - {}", err.message);
            } else {
                println!("Insert failed: Server error - {}", err.message);
            }
            return Err(Box::new(err));
        }
        Err(e) => {
            // Handle other kinds of errors
            println!("Insert failed: Unexpected error - {}", e);
            return Err(Box::new(e));
        }
    }
        }

        // ...then re-select the newly inserted row by uuid
        let mut conn = pool.get_conn().await?;
        let row_opt: Option<(
            String,         // uuid
            String,         // username
            String,         // email
            String,         // password_hash
            String,         // description
            i8,             // status
            chrono::NaiveDateTime,  // created_at
            chrono::NaiveDateTime,  // updated_at
        )> = conn
            .exec_first(
                "SELECT uuid, username, email, password_hash, description, status, created_at, updated_at
                 FROM users2
                 WHERE uuid = :uuid
                 LIMIT 1",
                params! {
                    "uuid" => uuid.to_string(),
                },
            )
            .await?;

        match row_opt {
            Some((
                uuid_str,
                username,
                email,
                password_hash,
                description,
                status_i8,
                created_naive,
                updated_naive,
            )) => {
                // Convert i8 -> UserStatus
                let user_status = UserStatus::try_from(status_i8).unwrap_or(UserStatus::Inactive);

                // Convert NaiveDateTime -> DateTime<Utc>
                let created_at = OurDateTime(chrono::Utc.from_utc_datetime(&created_naive));
                let updated_at = OurDateTime(chrono::Utc.from_utc_datetime(&updated_naive));

                Ok(User {
                    uuid: uuid_str,
                    username,
                    email,
                    password_hash,
                    description,
                    status: user_status,
                    created_at,
                    updated_at,
                })
            }
            None => Err("Failed to re-select created user".into()),
        }
    }

    // delete user
    pub async fn destroy(pool: &Pool, uuid: &str) -> Result<(), Box<dyn Error>> {
        // Acquire an async connection from the pool
        let mut conn = pool.get_conn().await?;

        // Delete the user from the MySQL database
        conn.exec_drop(
            "DELETE FROM users2 WHERE uuid = :uuid",
            params! {
                "uuid" => uuid,
            },
        )
        .await?;

        Ok(())
    }


    pub fn to_html_string(&self) -> String {
        format!(
            r#"<div>UUID: {uuid}</div>
                <div>Username: {username}</div>
                <div>Email: {email}</div>
                <div>Description: {description}</div>
                <div>Status: {status}</div>
                <div>Created At: {created_at}</div>
                <div>Updated At: {updated_at}</div>"#,
            uuid = self.uuid,
            username = self.username,
            email = self.email,
            description = self.description,
            status = self.status.to_string(),
            created_at = self.created_at.0.to_rfc3339(),
            updated_at = self.updated_at.0.to_rfc3339(),
        )
    }
}


#[derive(Debug, FromForm)]
pub struct NewUser<'r> {
    #[field(validate = len(5..20).or_else(msg!("name cannot be empty or less than 5 characters")))]
    pub username: &'r str,
    #[field(validate = validate_email().or_else(msg!("invalid email")))]
    pub email: &'r str,
    #[field(validate = validate_password().or_else(msg!("weak password")))]
    pub password: &'r str,
    #[field(validate = eq(self.password).or_else(msg!("password confirmation mismatch")))]
    pub password_confirmation: &'r str,
    #[field(default = "")]
    pub description: Option<&'r str>,
}
fn validate_email(email: &str) -> form::Result<'_, ()> {
    const EMAIL_REGEX: &str = r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#;
    let email_regex = Regex::new(EMAIL_REGEX).unwrap();
    if !email_regex.is_match(email) {
        return Err(FormError::validation("invalid email").into());
    }
    Ok(())
}

fn validate_password(password: &str) -> form::Result<'_, ()> {
    let entropy = zxcvbn(password, &[]);
    if entropy.is_err() || entropy.unwrap().score() < 3 {
        return Err(FormError::validation("weak password").into());
    }
    Ok(())
}

#[derive(Debug, FromForm)]
pub struct EditedUser<'r> {
    #[field(name = "_METHOD")]
    pub method: &'r str,
    #[field(validate = len(5..20).or_else(msg!("name
cannot be empty")))]
    pub username: &'r str,
    #[field(validate = validate_email()
.or_else(msg!("invalid email")))]
    pub email: &'r str,
    pub old_password: &'r str,
    #[field(validate = skip_validate_password(self.old_password, self.password_confirmation))]
    pub password: &'r str,
    pub password_confirmation: &'r str,
    #[field(default = "")]
    pub description: Option<&'r str>,
}

fn skip_validate_password<'v>(
    password: &'v str,
    old_password: &'v str,
    password_confirmation: &'v str,
) -> form::Result<'v, ()> {
    if old_password.is_empty() {
        return Ok(());
    }
    validate_password(password)?;
    if password.ne(password_confirmation) {
        return Err(FormError::validation(
            "password
confirmation mismatch",
        )
        .into());
    }
    Ok(())
}
