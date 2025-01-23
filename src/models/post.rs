use super::our_date_time::OurDateTime;
use super::post_type::PostType;
use rocket::form::FromForm;

#[derive(Debug, PartialEq, Eq, FromForm)]
pub struct Post {
    pub uuid: String,
    pub user_uuid: String,
    pub post_type: PostType,
    pub content: String,
    pub created_at: OurDateTime,
}