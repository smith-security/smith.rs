use crate::configuration::Configuration;
use crate::codec;

use biscuit::{ClaimsSet, RegisteredClaims, JWT, SingleOrMultiple, StringOrUri};
use biscuit::jwa::SignatureAlgorithm;
use biscuit::jws::{RegisteredHeader, Secret};
use biscuit::jwk::{AlgorithmParameters, RSAKeyParameters};
use reqwest::header::ACCEPT;
use ring::signature::RsaKeyPair;
use std::sync::Arc;
use std::io::Cursor;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct PrivateClaims {
}

pub struct Api {
    pub configuration: Configuration,
    pub token: Option<String>,
}


// FIX: Error handling.
fn build_secret(key: &RSAKeyParameters) -> Secret {
    // https://tools.ietf.org/html/rfc3447#appendix-A.1.2
    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u8(0);
            writer.next().write_biguint(&key.n);
            writer.next().write_biguint(&key.e);
            writer.next().write_biguint(&key.d.clone().expect("d"));
            writer.next().write_biguint(&key.p.clone().expect("p"));
            writer.next().write_biguint(&key.q.clone().expect("q"));
            writer.next().write_biguint(&key.dp.clone().expect("dp"));
            writer.next().write_biguint(&key.dq.clone().expect("dq"));
            writer.next().write_biguint(&key.qi.clone().expect("qi"));
        });
    });
    let key = RsaKeyPair::from_der(untrusted::Input::from(&der)).expect("from_der");
    Secret::RsaKeyPair(Arc::new(key))
}

impl Api {
    pub fn new(configuration: Configuration) -> Api {
        Api { configuration, token: None }
    }

    pub fn oauth_token(&self) -> Result<String, reqwest::Error> {
        let secret = match &self.configuration.jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => build_secret(rsa),
            AlgorithmParameters::EllipticCurve(_ec) => panic!("todo"),
            AlgorithmParameters::OctectKey { key_type: _, value: _ } => panic!("todo"),
        };
        let claims = ClaimsSet::<PrivateClaims> {
            registered: RegisteredClaims {
                issuer: Some(StringOrUri::String(format!("{}", self.configuration.jwk.additional.value))),
                subject: None,
                audience: Some(SingleOrMultiple::Single(StringOrUri::String("https://smith.st".to_string()))),
               ..Default::default()
            },
            private: PrivateClaims {
            },
        };
        let jwt: JWT<PrivateClaims, biscuit::Empty> = JWT::new_decoded(From::from(
            RegisteredHeader {
                algorithm: SignatureAlgorithm::RS256,
               ..Default::default()
            }),
            claims.clone(),
        );
        let ss = match secret {
           Secret::None => "none",
           Secret::Bytes(_) => "bytes",
           Secret::RsaKeyPair(_) => "rsa",
           Secret::EcdsaKeyPair(_) => "ecdsa",
           Secret::PublicKey(_) => "pub",
           Secret::RSAModulusExponent { n: _, e: _ } => "rsamod",
        };
        println!("secret is {:?} / {:?}", ss, &self.configuration.jwk);
        let assertion = jwt.encode(&secret).expect("1").encoded().expect("2").encode();
        let parameters = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string()),
            ("assertion", assertion)
        ];
        let _resp: serde_json::Value = reqwest::Client::new()
            .post(&format!("{}/oauth/token", &self.configuration.endpoint))
            .header(ACCEPT, "application/json")
            .form(&parameters)
            .send()?
            .json()?;
        Ok("foo".to_string())
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::Configuration;

    #[test]
    fn test_oauth_token() {
        let configuration = Configuration::from_env();
        println!("configuration = {:?}", configuration);
        let api = Api::new(configuration);
        let token = api.oauth_token();
        println!("token = {:?}", token);
    }
}
