use crate::configuration::Configuration;
use crate::data::UserInfo;
use crate::oauth2;
use reqwest::header;
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
        write!(f, "error thing")
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

    pub fn whoami(&mut self) -> Result<UserInfo, Error> {
        self.get("userinfo")?
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

    #[test]
    fn test_whoami() {
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
        let mut api = Api::new(configuration);
        let userinfo = api.whoami().expect("Should be able to make userinfo call.");
        assert_eq!(userinfo, UserInfo { user_id: "1".to_string() } );
    }
}
