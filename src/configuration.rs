use biscuit::jwk::JWK;
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityId {
    #[serde(rename = "smith.st/identity-id")]
    pub value: u64,
}

#[derive(Clone, Debug)]
pub struct Configuration {
    pub home: PathBuf,
    pub endpoint: String,
    pub jwk: JWK<IdentityId>,
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
        let jwk = std::env::var("SMITH_JWK")
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
        Configuration { home, endpoint, jwk }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration() {
        let configuration = Configuration::from_env();
        println!("configuration = {:?}", configuration);
    }
}
