#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;
extern crate rocket_contrib;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};
use rocket::response::status;
use rocket_contrib::json::Json;
use serde_json::{json, Value};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct CertificateRequest {
    #[serde(rename = "public-key")]
    pub public_key: String,
    pub principals: Vec<String>,
    pub environment : String,
    #[serde(rename = "host-name")]
    pub host: Option<String>,
}

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

#[get("/environment/public-keys/<_environment>")]
fn keys(_token: Token, _environment: String) -> Json<Value> {
    Json(json!({
        "public-keys": [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDl3utyfULwKVU4t1GYjLOCsF0Bd+azg80ViJFpQR3TRLJW8d59KcQ3iMxSvaGAI/dat8owZLygGQHjX88Zbb4luFTWsEXGaewbjSvTdo3Im3XfL6aZJNtMVMfUJ0norLuBv3OHuUDnigwYJJ1IuyHZND0B6QU9F9I7dOkxgakNThmoWXReqQIKK1ZC9p5eRMy+tGxOpfnTwXEgGXlTpoa5EuJV10mWJS6CyDVdMp+qLHk/YohzHb4l7gq7B4vVkPT8rc13ouig9CpP22sLR9NCiwgObTunnKslXTDQn6LAQ0WKVGQhD+MLzh2rO5xoYZUmzB9Z3D+0sa/9YLY5VhwlbTc7UMxoNMK0jDrL9imEsl6523TinUeKpRW3asJ9YXJxdAgQHlbu6eY7OgQqW3uZUo/EipqQjGauOcI7nWG1M7n56UtqzkLAIhHU3T9oq2kAVQP2tdMhxS466WR+cOO4l0yIn/Q3CGhecxXlA/0ILKgIN4G5jx95uoa4okMhVlVpeazYlz0OIxp2noKwcWbMlld6OvdM9bSGYNUsg9ao8DFFta6pQ7XaSWzHriV2rrsVKl7Uw7T7v0z/oQXYaevIJB7dRNYnlK8jcwJu2VOcRCcqK0gXNalnMMvcGYTn6I5Vm6cykbiUfASAe5df8sHEVmiudkXl8Z3JGPZyRz4NpQ== SSH CA Key",
        ],
    }))
}

#[post("/issue", data = "<_request>")]
fn issue(_token: Token, _request: Json<CertificateRequest>) -> Json<Value> {
    Json(json!({
        "certificate": "ssh-rsa-cert-v01@openssh.com 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 test-cert",
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
            keys,
            issue,
        ]).register(catchers![
            forbidden
        ]).launch();
}
