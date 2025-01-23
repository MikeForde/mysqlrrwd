use super::our_date_time::OurDateTime;

pub const DEFAULT_LIMIT: usize = 10;

#[derive(FromForm, Debug, Clone)]
pub struct Pagination {
    pub next: Option<OurDateTime>,
    pub limit: Option<usize>,
}