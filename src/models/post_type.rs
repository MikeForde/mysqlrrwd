use rocket::form::FromFormField;

#[repr(i32)]
#[derive(Debug, PartialEq, Eq, FromFormField)]
pub enum PostType {
    Text = 0,
    Photo = 1,
    Video = 2,
}

impl TryFrom<i8> for PostType {
    type Error = &'static str;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PostType::Text),
            1 => Ok(PostType::Photo),
            2 => Ok(PostType::Video),
            _ => Err("Invalid PostType"),
        }
    }
}

impl From<PostType> for i8 {
    fn from(post_type: PostType) -> Self {
        post_type as i8
    }
}