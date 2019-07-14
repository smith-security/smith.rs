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
    #[serde(rename = "sub")]
    code: String,
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
