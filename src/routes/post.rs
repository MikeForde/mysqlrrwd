use super::HtmlResponse;
use crate::fairings::db::DBConnection;
use crate::models::post::Post;
use rocket::form::Form;
use mysql_async::{prelude::*, Pool};
use rocket::State;

#[get("/users/<_user_uuid>/posts/<_uuid>", format = "text/html")]
pub async fn get_post(_db_conn: &State<DBConnection>, _user_uuid: &str, _uuid: &str) -> HtmlResponse {
    todo!("will implement later")
}

#[get("/users/<_user_uuid>/posts", format = "text/html", rank = 2)]
pub async fn get_posts(_db_conn: &State<DBConnection>, _user_uuid: &str) -> HtmlResponse {
    todo!("will implement later")
}

#[post("/users/<_user_uuid>/posts", format = "text/html", data = "<_upload>")]
pub async fn create_post(
    _db_conn: &State<DBConnection>,
    _user_uuid: &str,
    _upload: Form<Post>,
) -> HtmlResponse {
    todo!("will implement later")
}

#[post("/users/<_user_uuid>/posts/<_uuid>", format = "text/html")]
pub async fn delete_post(
    _db_conn: &State<DBConnection>,
    _user_uuid: &str,
    _uuid: &str,
) -> HtmlResponse {
    todo!("will implement later")
}

