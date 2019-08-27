use crate::configuration::Configuration;
use crate::data::{
    AuthorityPublicKeys,
    Certificate,
    Environment,
    HostName,
    PublicKey,
    Principal,
    UserInfo,
};
use crate::oauth2;
use reqwest::header;
use serde_json::{Value, json};
use std::fmt;

pub struct Api {
    pub configuration: Configuration,
    pub oauth2: oauth2::Store,
    pub client: reqwest::Client,
}


#[derive(Debug)]
pub enum Error {
    RequestError(reqwest::Error),
    InvalidStatusCode(reqwest::StatusCode),
    ServerError(reqwest::StatusCode, ServerError),
    CouldNotParseErrorResponse(reqwest::StatusCode, reqwest::Error),
    CouldNotParseResponse(reqwest::Error),
    GrantError(oauth2::GrantError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::RequestError(_) =>
              write!(f, "Request error trying to contact the server, please check connectivity to Smith and retry request."),
            Error::InvalidStatusCode(_) =>
              write!(f, "Server responded with an invalid status code, please check connectivity to Smith and retry request."),
            Error::ServerError(_, _) =>
              write!(f, "Request failed, please check connectivity to Smith and retry request."),
            Error::CouldNotParseErrorResponse(_, _) =>
              write!(f, "Invalid error response from server, request failed but we couldn't decode the error, please check connectivity to Smith and retry request."),
            Error::CouldNotParseResponse(_) =>
              write!(f, "Invalid response from server, please check connectivity to Smith and retry request."),
            Error::GrantError(_) =>
              write!(f, "OAuth2 grant failed, check your API credentials are valid."),
        }
    }
}


#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ServerError {
    error: String,
}


impl Api {
    pub fn new(configuration: Configuration) -> Api {
        let client = reqwest::Client::new();
        // FUTURE: support sharing client between oauth and api.
        let oauth2 = configuration.oauth2.initialise();
        Api { configuration, oauth2, client }
    }

    pub fn get(&mut self, url: &str) -> Result<reqwest::Response, Error> {
        let token = self.oauth2.grant().map_err(|e| Error::GrantError(e))?;
        let mut response = self.client
            .get(&format!("{}/{}", self.configuration.endpoint, url))
            .bearer_auth(&token.value)
            .header(header::ACCEPT, "application/json")
            .send()
            .map_err(|e| Error::RequestError(e))?;
        match response.status() {
            reqwest::StatusCode::OK => Ok(response),
            reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                let error: ServerError = response
                    .json()
                    .map_err(|e| Error::CouldNotParseErrorResponse(response.status(), e))?;
                Err(Error::ServerError(response.status(), error))
            },
            s => Err(Error::InvalidStatusCode(s)),
        }
    }

    pub fn post(&mut self, url: &str, body: &Value) -> Result<reqwest::Response, Error> {
        let token = self.oauth2.grant().map_err(|e| Error::GrantError(e))?;
        let mut response = self.client
            .post(&format!("{}/{}", self.configuration.endpoint, url))
            .bearer_auth(&token.value)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .json(body)
            .send()
            .map_err(|e| Error::RequestError(e))?;
        match response.status() {
            reqwest::StatusCode::OK => Ok(response),
            reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                let error: ServerError = response
                    .json()
                    .map_err(|e| Error::CouldNotParseErrorResponse(response.status(), e))?;
                Err(Error::ServerError(response.status(), error))
            },
            s => Err(Error::InvalidStatusCode(s)),
        }
    }

    pub fn whoami(&mut self) -> Result<UserInfo, Error> {
        self.get("userinfo")?
            .json()
            .map_err(|e| Error::CouldNotParseResponse(e))

    }

    pub fn keys(&mut self, environment: &Environment) -> Result<AuthorityPublicKeys, Error> {
        self.get(&format!("environment/public-keys/{}", environment.name))?
            .json()
            .map_err(|e| Error::CouldNotParseResponse(e))
    }

    pub fn issue(&mut self, environment: &Environment, public_key: &PublicKey, principals: &[Principal], host: &Option<HostName>) -> Result<Certificate, Error> {
        self.post("issue", &json!({
            "public-key": public_key.encoded,
            "principals": principals.iter().map(|p| &p.name).collect::<Vec<_>>(),
            "environment": environment.name,
            "host-name": host.as_ref().map(|h| &h.host),
        }))?
            .json()
            .map_err(|e| Error::CouldNotParseResponse(e))
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2;
    use crate::configuration::IdentityId;

    use biscuit::jwk::JWK;
    use std::fs::File;
    use std::io::prelude::*;
    use std::path::Path;


    fn read_jwk(credentials: &Path) -> JWK<IdentityId> {
        let mut file = File::open(credentials).expect("Credentials path should exist.");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Should be able to read credentials file.");
        serde_json::from_str(&contents).expect("Should be able to deserialise credentials file.")
    }

    fn test_api() -> Api {
        let server = std::env::var("SERVER").unwrap_or("http://localhost:8000".to_string());
        let jwk = read_jwk(Path::new("test/data/credentials.json"));
        let oauth2 = oauth2::Configuration {
            key: oauth2::Configuration::build_secret(&jwk).expect("Should be able to build signing secret"),
            endpoint: format!("{}/oauth/token", server),
            issuer: "me".to_string(),
            audience: "mock".to_string(),
            scopes: vec!["scope".to_string()],
        };
        let configuration = Configuration {
            endpoint: server,
            jwk,
            oauth2,
        };
        Api::new(configuration)
    }

    #[test]
    fn test_whoami() {
        let mut api = test_api();
        let userinfo = api.whoami().expect("Should be able to make userinfo call.");
        assert_eq!(userinfo, UserInfo { user_id: "1".to_string() } );
    }

    #[test]
    fn test_keys() {
        let environment = Environment { name: "mock".to_string() };
        let mut api = test_api();
        let keys = api.keys(&environment).expect("Should be able to make keys call.");
        assert!(keys.keys.len() > 0);
    }

    #[test]
    fn test_issue() {
        let environment = Environment { name: "mock".to_string() };
        let public_key = PublicKey { encoded: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDI6z6dBtqnv2F0kqD8gnRMPkAoOdNpaa5qnx3UyXM8RApmBY180RKTSLzTRcrFFYxDfHLOFWw/V0JM4bLwNaHhhuYGllYqb2qHlVs7KgoytBGy//xtRMemkX2BY5UwD8iqw+5a45xqoddL8hTRk77ploFa7ItgTVVPD30l3hZHWWQr2/eINI9G41nLfQZkOYjkNf1s8DJsHI8FunKgp8lwGMUZaAq9mnYpVHBQX6LSjZiBUN9pIkoDO5+08AN6RIUIgJ9Q0T0AGLRcMQKTx1fkeV7wkreJF2TmBVUE0ZOIDQEOOis1+YigT4JAqrDI0+OYGzEGu2tHFRemjs3uvQLb test".to_string() };
        let principals = vec![Principal { name: "root".to_string() }];
        let host = Some(HostName { host: "host".to_string() });
        let mut api = test_api();
        let certificate = api.issue(&environment, &public_key, &principals, &host).expect("Should be able to make keys call.");
        assert!(certificate.encoded.len() > 0);
    }

}
