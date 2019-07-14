use biscuit::{ClaimsSet, RegisteredClaims, JWT, SingleOrMultiple, StringOrUri};
use biscuit::jwa::SignatureAlgorithm;
use biscuit::jws::{RegisteredHeader, Secret};
use biscuit::jwk::{AlgorithmParameters, RSAKeyParameters};
use reqwest::{Client, Url};
use reqwest::header::ACCEPT;
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct PrivateClaims {
    scope: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AccessTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AccessTokenError {
    pub error: String,
}


#[derive(Debug, PartialEq, Clone)]
pub struct AccessToken {
    pub value: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct AccessTokenState {
    pub token: AccessToken,
    pub requested_at: Instant,
    pub expires_in: Duration
}

pub struct Store {
    pub client: Client,
    pub endpoint: String,
    pub key: Secret,
    pub issuer: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub state: Option<AccessTokenState>,
}

#[derive(Debug)]
pub enum GrantError {
    JwtSignError(biscuit::errors::Error),
    JwtEncodeError(biscuit::errors::Error),
    NetworkError(reqwest::Error),
    InvalidStatusCodeError(reqwest::StatusCode),
    AccessTokenError(AccessTokenError),
    Json400ParseError(reqwest::Error),
    Json200ParseError(reqwest::Error),
}

impl Store {
    pub fn grant(&mut self) -> Result<AccessToken, GrantError> {
        match self.local() {
            Some(token) => Ok(token.clone()),
            None => {
                let state = self.refresh()?;
                let token = state.token.clone();
                self.state = Some(state);
                Ok(token)
            },
        }
    }

    pub fn local(&self) -> Option<AccessToken> {
        self.state.as_ref().and_then(|state| {
            let now = Instant::now();
            if now.duration_since(state.requested_at) > state.expires_in {
               None
            } else {
               Some(state.token.clone())
            }
        })
    }

    pub fn refresh(&self) -> Result<AccessTokenState, GrantError> {
        let requested_at = Instant::now();
        let assertion = self.sign()?;
        let parameters = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string()),
            ("assertion", assertion)
        ];

        let mut response: reqwest::Response = self.client
            .post(&self.endpoint)
            .header(ACCEPT, "application/json")
            .form(&parameters)
            .send()
            .map_err(|e| GrantError::NetworkError(e))?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let response: AccessTokenResponse = response
                    .json()
                    .map_err(|e| GrantError::Json200ParseError(e))?;

                Ok(AccessTokenState {
                    token: AccessToken { value: response.access_token },
                    requested_at: requested_at,
                    expires_in: Duration::new(response.expires_in, 0),
                })
            },
            reqwest::StatusCode::BAD_REQUEST => {
                let response: AccessTokenError = response
                    .json()
                    .map_err(|e| GrantError::Json400ParseError(e))?;
                Err(GrantError::AccessTokenError(response))
              },
            s => {
                Err(GrantError::InvalidStatusCodeError(s))
            },
        }
    }

    pub fn sign(&self) -> Result<String, GrantError> {
        let claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(StringOrUri::String(self.issuer.clone())),
                subject: None,
                audience: Some(SingleOrMultiple::Single(StringOrUri::String(self.audience.clone()))),
               ..Default::default()
            },
            private: PrivateClaims {
                scope: self.scopes.join(" "),
            },
        };
        let jwt: JWT<PrivateClaims, biscuit::Empty> = JWT::new_decoded(From::from(
            RegisteredHeader {
                algorithm: SignatureAlgorithm::RS256,
               ..Default::default()
            }),
            claims.clone(),
        );
        let assertion = jwt.encode(&self.key)
            .map_err(|e| GrantError::JwtSignError(e))?
            .encoded()
            .map_err(|e| GrantError::JwtEncodeError(e))?
            .encode();
        Ok(assertion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::Configuration;

    #[test]
    fn test_oauth_token() {
        let mut configuration = Configuration::from_env();
        let token = configuration.oauth2.grant();
        println!("token = {:?}", token);
    }
}
