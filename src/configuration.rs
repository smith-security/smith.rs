use crate::oauth2;

use biscuit::jws::Secret;
use biscuit::jwk::{AlgorithmParameters, RSAKeyParameters};
use biscuit::jwk::JWK;
use ring::signature::RsaKeyPair;
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityId {
    #[serde(rename = "smith.st/identity-id")]
    pub value: u64,
}

pub struct Configuration {
    pub home: PathBuf,
    pub endpoint: String,
    pub jwk: JWK<IdentityId>,
    pub oauth2: oauth2::Store,
}

impl Configuration {
    pub fn from_env() -> Configuration {
        let home = std::env::var("SMITH_HOME")
            .map(|h| Path::new(&h).to_path_buf())
            .unwrap_or_else(|_| {
                dirs::home_dir().map(|home| home.join(".smith").to_path_buf()).unwrap_or_else(|| {
                    eprintln!("Could not determine home directory, please set SMITH_HOME explicity.");
                    std::process::exit(1);
                })
            });
        let endpoint = std::env::var("SMITH_ENDPOINT").unwrap_or("https://api.smith.st".to_string());
        let jwk: JWK<IdentityId> = std::env::var("SMITH_JWK")
            .map(|jwk| {
                serde_json::from_str(&jwk).unwrap_or_else(|err| {
                     eprintln!("JWK could not be parsed from environment variable SMITH_JWK, check it is a well formatted JWK from https://smith.st: {:?}", err);
                     std::process::exit(1);
                })
            })
            .unwrap_or_else(|_| {
                let credentials = home.join("credentials.json");
                let mut file = match File::open(&credentials) {
                    Ok(file) => file,
                    Err(err) =>
                        if err.kind() == ErrorKind::NotFound {
                            eprintln!("credentials.json could not be found, check it exists, tried: {:?}", credentials);
                            std::process::exit(1);
                        } else {
                            eprintln!("credentials.json could not be accessed, check permissions, tried: {:?}", credentials);
                            std::process::exit(1);
                        }
                };
                let mut contents = String::new();
                file.read_to_string(&mut contents).unwrap_or_else(|_| {
                    eprintln!("credentials.json could not be read, check file, tried: {:?}", credentials);
                    std::process::exit(1);
                });
                serde_json::from_str(&contents).unwrap_or_else(|err| {
                     eprintln!("JWK could not be parsed from file ['{:?}']: {:?}", credentials, err);
                     std::process::exit(1);
                })
            });
        let key = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => build_secret(&rsa),
            AlgorithmParameters::EllipticCurve(_ec) => {
                eprintln!("Smith JWK only support RS256, and requires an RSA JWK.");
                std::process::exit(1);
            },
            AlgorithmParameters::OctectKey { key_type: _, value: _ } => {
                eprintln!("Smith JWK only support RS256, and requires an RSA JWK.");
                std::process::exit(1);
            },
        };
        let oauth2 = oauth2::Store {
            client: reqwest::Client::new(),
            endpoint: format!("{}/oauth/token", &endpoint),
            key: key,
            issuer: format!("{}", jwk.additional.value),
            audience: "https://smith.st".to_string(),
            scopes: vec!["profile".to_string(), "ca".to_string()],
            state: None,
        };
        Configuration { home, endpoint, jwk, oauth2 }
    }
}

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
