use crate::configuration::Configuration;
use crate::codec;
use crate::oauth2;

use biscuit::{ClaimsSet, RegisteredClaims, JWT, SingleOrMultiple, StringOrUri};
use biscuit::jwa::SignatureAlgorithm;
use biscuit::jws::{RegisteredHeader, Secret};
use biscuit::jwk::{AlgorithmParameters, RSAKeyParameters};
use reqwest::header::ACCEPT;


use std::io::Cursor;

pub struct Api {
    pub configuration: Configuration,
}


impl Api {
    pub fn new(configuration: Configuration) -> Api {
        Api { configuration }
    }
}
