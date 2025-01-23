use mysql_async::Pool;

// --------------------------
//  DATABASE CONNECTION
// --------------------------
pub struct DBConnection {
    pub pool: Pool,
}