#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]

extern crate rocket;
extern crate rocket_contrib;
extern crate serde;
extern crate serde_json;
extern crate serde_derive;

use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};
use rocket::response::status;
use rocket_contrib::json::Json;
use serde_json::{json, Value};

struct Token;

impl<'a, 'r> FromRequest<'a, 'r> for Token {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> request::Outcome<Token, ()> {
        let auth: Vec<&str> = request.headers().get("Authorization").collect();
        if auth != vec!["Bearer mock"] {
            return Outcome::Failure((Status::Forbidden, ()));
        };
        Outcome::Success(Token)
    }
}

#[post("/oauth/token")]
fn oauth<'a>() -> Json<Value> {
    Json(json!({
        "access_token": "mock",
        "expires_in": 3200,
        "token_type": "Bearer",
    }))
}

#[get("/userinfo")]
fn userinfo(_token: Token) -> Json<Value> {
    Json(json!({
        "sub": "1",
    }))
}

#[catch(403)]
fn forbidden() -> status::Custom<Json<Value>> {
    status::Custom(Status::Forbidden, Json(json!({
       "error": "not-authorized"
    })))
}

fn main() {
    rocket::ignite()
        .mount("/", routes![
            oauth,
            userinfo,
        ]).register(catchers![
            forbidden
        ]).launch();
}
