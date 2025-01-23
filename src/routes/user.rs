use super::HtmlResponse;
use crate::fairings::db::DBConnection;
use crate::models::user::{EditedUser, NewUser, User};
//use mysql_async::{params, prelude::*, Pool};
use rocket::form::{Contextual, Form};
use rocket::http::Status;
use rocket::request::FlashMessage;
use rocket::response::{content::RawHtml, Flash, Redirect};
use rocket::State;

const USER_HTML_PREFIX: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Users</title>
</head>
<body>
    <h1>Users</h1>
"#;

const USER_HTML_SUFFIX: &str = r#"</body>
</html>"#;

#[get("/user/<uuid>", format = "text/html")]
pub async fn get_user(
    uuid: &str,
    db_conn: &State<DBConnection>,
    flash: Option<FlashMessage<'_>>,
) -> HtmlResponse {
    // Query for the user using your `User::find` method
    let user = User::find(&db_conn.pool, uuid)
        .await
        .map_err(|_| Status::NotFound)?;

    // Build the HTML output
    let mut html_string = String::from(USER_HTML_PREFIX);
    if flash.is_some() {
        html_string.push_str(flash.unwrap().message());
    }
    html_string.push_str(&user.to_html_string());
    html_string.push_str(&format!(
        r#"<a href="/users/edit/{}">Edit User</a><br/>"#,
        user.uuid
    ));
    html_string.push_str(
        format!(
            r#"<form accept-charset="UTF-8" action="/users/delete/{}" 
            autocomplete="off"
            method="POST"><button type="submit"
            value="Submit">Delete</button></form>"#,
            user.uuid
        )
        .as_ref(),
    );
    html_string.push_str(r#"<a href="/users">User List</a>"#);
    html_string.push_str(USER_HTML_SUFFIX);

    Ok(RawHtml(html_string))
}

#[get("/users", format = "text/html")]
pub async fn get_users(db_conn: &State<DBConnection>) -> HtmlResponse {
    // we have created a new method `User::find_all` that returns a tuple of Vec<User> and Option<Pagination>
    let (users) = User::find_all(&db_conn.pool)
        .await
        .map_err(|_| Status::NotFound)?;

    // Build the HTML output
    let mut html_string = String::from(USER_HTML_PREFIX);
    for user in users {
        html_string.push_str(&user.to_html_string());
        html_string
            .push_str(format!(r#"<a href="/user/{}">See User</a><br/>"#, user.uuid).as_ref());
        html_string.push_str(&format!(
            r#"<a href="/users/edit/{}">Edit User</a><br/>"#,
            user.uuid
        ));
    }
    html_string.push_str(r#"<a href="/users/new">New User</a>"#);
    html_string.push_str(USER_HTML_SUFFIX);

    Ok(RawHtml(html_string))
}

#[get("/users/new", format = "text/html")]
pub async fn new_user(flash: Option<FlashMessage<'_>>) -> HtmlResponse {
    let mut html_string = String::from(USER_HTML_PREFIX);
    if flash.is_some() {
        html_string.push_str(flash.unwrap().message());
    }
    html_string.push_str(
        r#"<form accept-charset="UTF-8" action="/users" autocomplete="off" method="POST">
    <div>
        <label for="username">Username:</label>
        <input name="username" type="text"/>
    </div>
    <div>
        <label for="email">Email:</label>
        <input name="email" type="email"/>
    </div>
    <div>
        <label for="password">Password:</label>
        <input name="password" type="password"/>
    </div>
    <div>
        <label for="password_confirmation">Password Confirmation:</label>
        <input name="password_confirmation" type="password"/>
    </div>
    <div>
        <label for="description">Tell us a little bit more about yourself:</label>
        <textarea name="description"></textarea>
    </div>
    <button type="submit" value="Submit">Submit</button>
</form>"#,
    );
    html_string.push_str(USER_HTML_SUFFIX);
    Ok(RawHtml(html_string))
}

#[post(
    "/users",
    format = "application/x-www-form-urlencoded",
    data = "<user_context>"
)]
pub async fn create_user<'r>(
    db_conn: &State<DBConnection>,
    user_context: Form<Contextual<'r, NewUser<'r>>>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    println!("user_context: {:?}", user_context);
    if user_context.value.is_none() {
        let error_message = format!(
            "<div>{}</div>",
            user_context
                .context
                .errors()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("<br/>")
        );
        return Err(Flash::error(Redirect::to("/users/new"), error_message));
    }

    println!("user_context again: {:?}", user_context);
    let new_user = user_context.value.as_ref().unwrap();
    // Attempt to create the user and capture any error
    let create_result = User::create(&db_conn.pool, new_user).await;

    match create_result {
        Ok(user) => Ok(Flash::success(
            Redirect::to(format!("/user/{}", user.uuid)),
            "<div>Successfully created user</div>",
        )),
        Err(e) => {
            // Include the error message in the flash response
            let error_message = format!(
                "Failed to create user:<br/><div>Error: {}</div>",
                e.to_string()
            );
            Err(Flash::error(Redirect::to("/users/new"), error_message))
        }
    }
}

#[get("/users/edit/<uuid>", format = "text/html", rank = 1)]
pub async fn edit_user(
    db_conn: &State<DBConnection>,
    uuid: &str,
    flash: Option<FlashMessage<'_>>,
) -> HtmlResponse {
    let user = User::find(&db_conn.pool, uuid)
        .await
        .map_err(|_| Status::NotFound)?;

    let mut html_string = String::from(USER_HTML_PREFIX);
    if flash.is_some() {
        html_string.push_str(flash.unwrap().message());
    }
    html_string.push_str(
        format!(
            r#"<form accept-charset="UTF-8" action="/users/{}" autocomplete="off" method="POST">
        <input type="hidden" name="_METHOD" value="PUT"/>
        <div>
        <label for="username">Username:</label>
        <input name="username" type="text" value="{}"/>
        </div>
        <div>
        <label for="email">Email:</label>
        <input name="email" type="email" value="{}"/>
        </div>
        <div>
        <label for="old_password">Old password:</label>
        <input name="old_password" type="password"/>
        </div>
        <div>
        <label for="password">New password:</label>
        <input name="password" type="password"/>
        </div>
        <div>
        <label for="password_confirmation">Password Confirmation:</label>
        <input name="password_confirmation" type="password"/>
        </div>
        <div>
        <label for="description">Tell us a little bit more about yourself:</label>
        <textarea name="description">{}</textarea>
        </div>
        <button type="submit" value="Submit">Submit</button>
        </form>"#,
            &user.uuid, &user.username, &user.email, &user.description,
        )
        .as_ref(),
    );
    html_string.push_str(USER_HTML_SUFFIX);
    Ok(RawHtml(html_string))
}

#[post(
    "/users/<uuid>",
    format = "application/x-www-form-urlencoded",
    data = "<user_context>"
)]
pub async fn update_user<'r>(
    db_conn: &State<DBConnection>,
    uuid: &str,
    user_context: Form<Contextual<'r, EditedUser<'r>>>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    if user_context.value.is_none() {
        let error_message = format!(
            "<div>{}</div>",
            user_context
                .context
                .errors()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("<br/>")
        );
        return Err(Flash::error(
            Redirect::to(format!("/users/edit/{}", uuid)),
            error_message,
        ));
    }

    let user_value = user_context.value.as_ref().unwrap();
    match user_value.method {
        "PUT" => put_user(db_conn, uuid, user_context).await,
        "PATCH" => patch_user(db_conn, uuid, user_context).await,
        _ => Err(Flash::error(
            Redirect::to(format!("/users/edit/{}", uuid)),
            "Invalid method".to_string(),
        )),
    }
}

#[put(
    "/users/<uuid>",
    format = "application/x-www-form-urlencoded",
    data = "<user_context>"
)]
pub async fn put_user<'r>(
    db_conn: &State<DBConnection>,
    uuid: &str,
    user_context: Form<Contextual<'r, EditedUser<'r>>>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    let user_value = user_context.value.as_ref().unwrap();
    let user = User::update(&db_conn.pool, uuid, user_value)
        .await
        .map_err(|_| {
            Flash::error(
                Redirect::to(format!("/users/edit/{}", uuid)),
                "<div>Something went wrong when updating user</div>",
            )
        })?;
    Ok(Flash::success(
        Redirect::to(format!("/user/{}", user.uuid)),
        "<div>Successfully updated user</div>",
    ))
}

#[patch(
    "/users/<uuid>",
    format = "application/x-www-form-urlencoded",
    data = "<user_context>"
)]
pub async fn patch_user<'r>(
    db_conn: &State<DBConnection>,
    uuid: &str,
    user_context: Form<Contextual<'r, EditedUser<'r>>>,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    put_user(db_conn, uuid, user_context).await
}

#[post("/users/delete/<uuid>", format = "application/x-www-form-urlencoded")]
pub async fn delete_user_entry_point(
    db_conn: &State<DBConnection>,
    uuid: &str,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    delete_user(db_conn, uuid).await
}

#[delete("/users/<uuid>", format = "application/x-www-form-urlencoded")]
pub async fn delete_user(
    db_conn: &State<DBConnection>,
    uuid: &str,
) -> Result<Flash<Redirect>, Flash<Redirect>> {
    User::destroy(&db_conn.pool, uuid).await.map_err(|_| {
        Flash::error(
            Redirect::to(format!("/user/{}", uuid)),
            "<div>Something went wrong when deleting user</div>",
        )
    })?;
    Ok(Flash::success(
        Redirect::to("/users"),
        format!("<div>Successfully deleted user</div>"),
    ))
}
