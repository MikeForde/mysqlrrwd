use ammonia::Builder;
use std::collections::hash_set::HashSet;

pub mod our_date_time;
pub mod pagination;
pub mod post;
pub mod post_type;
pub mod photo_post;
pub mod video_post;
pub mod text_post;
pub mod user;
pub mod user_status;

pub fn clean_html(src: &str) -> String {
    Builder::default()
        .tags(HashSet::new())
        .clean(src)
        .to_string()
}