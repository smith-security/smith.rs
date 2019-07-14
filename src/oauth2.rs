use biscuit::{ClaimsSet, RegisteredClaims, JWT, SingleOrMultiple, StringOrUri};
use biscuit::jwa::SignatureAlgorithm;
use biscuit::jws::{RegisteredHeader, Secret};
use biscuit::jwk::{JWK, AlgorithmParameters, RSAKeyParameters};
use reqwest::Client;
use reqwest::header::ACCEPT;
use ring::signature::RsaKeyPair;
use std::sync::Arc;
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
    pub state: Option<AccessTokenState>,
    pub configuration: Configuration,
}

#[derive(Clone)]
pub struct Configuration {
    pub key: Arc<Secret>,
    pub endpoint: String,
    pub issuer: String,
    pub audience: String,
    pub scopes: Vec<String>,
}

impl Configuration {
    pub fn initialise(&self) -> Store {
        Store::new(reqwest::Client::new(), self.clone())
    }

    pub fn initialise_with(&self, client: reqwest::Client) -> Store {
        Store::new(client, self.clone())
    }

    pub fn build_secret<A>(jwk: &JWK<A>) -> Result<Arc<Secret>, KeyError> {
        match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                let secret = build_secret(&rsa)?;
                Ok(Arc::new(secret))
             },
            AlgorithmParameters::EllipticCurve(_ec) => Err(KeyError::UnsupportedKeyError),
            AlgorithmParameters::OctectKey { key_type: _, value: _ } => Err(KeyError::UnsupportedKeyError),
        }
    }
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

#[derive(Debug)]
pub enum KeyError {
    UnsupportedKeyError,
    IncompleteKeyError,
}

impl Store {
    pub fn new(client: reqwest::Client, configuration: Configuration) -> Store {
        Store {
            client: client,
            state: None,
            configuration: configuration,
        }
    }

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
            .post(&self.configuration.endpoint)
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
                issuer: Some(StringOrUri::String(self.configuration.issuer.clone())),
                subject: None,
                audience: Some(SingleOrMultiple::Single(StringOrUri::String(self.configuration.audience.clone()))),
               ..Default::default()
            },
            private: PrivateClaims {
                scope: self.configuration.scopes.join(" "),
            },
        };
        let jwt: JWT<PrivateClaims, biscuit::Empty> = JWT::new_decoded(From::from(
            RegisteredHeader {
                algorithm: SignatureAlgorithm::RS256,
               ..Default::default()
            }),
            claims.clone(),
        );
        let assertion = jwt.encode(&self.configuration.key)
            .map_err(|e| GrantError::JwtSignError(e))?
            .encoded()
            .map_err(|e| GrantError::JwtEncodeError(e))?
            .encode();
        Ok(assertion)
    }
}

fn build_secret(key: &RSAKeyParameters) -> Result<Secret, KeyError> {
    // https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    let n = &key.n;
    let e = &key.e;
    let d = key.d.as_ref().ok_or(KeyError::IncompleteKeyError)?;
    let p = key.p.as_ref().ok_or(KeyError::IncompleteKeyError)?;
    let q = key.q.as_ref().ok_or(KeyError::IncompleteKeyError)?;
    let dp = key.dp.as_ref().ok_or(KeyError::IncompleteKeyError)?;
    let dq = key.dq.as_ref().ok_or(KeyError::IncompleteKeyError)?;
    let qi = key.qi.as_ref().ok_or(KeyError::IncompleteKeyError)?;
    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u8(0);
            writer.next().write_biguint(n);
            writer.next().write_biguint(e);
            writer.next().write_biguint(d);
            writer.next().write_biguint(p);
            writer.next().write_biguint(q);
            writer.next().write_biguint(dp);
            writer.next().write_biguint(dq);
            writer.next().write_biguint(qi);
        });
    });
    let key = RsaKeyPair::from_der(untrusted::Input::from(&der)).map_err(|_e| KeyError::IncompleteKeyError)?;
    Ok(Secret::RsaKeyPair(Arc::new(key)))
}

#[cfg(test)]
mod tests {
    use crate::configuration::Configuration;

    #[test]
    fn test_oauth_token() {
        let configuration = Configuration::from_env();
        let mut store = configuration.oauth2.initialise();
        let token = store.grant();
        println!("token = {:?}", token);
    }
}
