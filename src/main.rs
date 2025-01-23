#[macro_use]
extern crate rocket;

use dotenv::dotenv;
use mysqlsimple::catchers;
use mysqlsimple::fairings::db::DBConnection;
use mysqlsimple::routes::{self, post, user};
use rocket::{Build, Rocket};

// -- mysql_async imports --
use mysql_async::{Pool, Opts};

// --------------------------
//  ROCKET LAUNCH
// --------------------------
#[launch]
async fn rocket() -> Rocket<Build> {
    dotenv().ok();
    let mysql_url = std::env::var("DATABASE_URL").expect("DATABASE_URL environment variable not set");
    let opts = Opts::from_url(&mysql_url).expect("Could not parse DATABASE_URL as a valid MySQL URL");

    // Create the async MySQL pool
    let pool = Pool::new(opts);

    // Create the DBConnection struct with the pool
    let db_conn = DBConnection { pool };

    rocket::build()
        // Manage the DBConnection so routes can access it with `&State<DBConnection>`
        .manage(db_conn)
        .mount(
            "/",
            routes![
                user::get_user,
                user::get_users,
                user::new_user,
                user::create_user,
                user::edit_user,
                user::update_user,
                user::put_user,
                user::patch_user,
                user::delete_user,
                user::delete_user_entry_point,
                post::get_post,
                post::get_posts,
                post::create_post,
                post::delete_post,
            ],
        )
        .mount("/assets", routes![routes::assets])
        .register(
            "/",
            catchers![
                catchers::not_found,
                catchers::unprocessable_entity,
                catchers::internal_server_error
            ],
        )
}
