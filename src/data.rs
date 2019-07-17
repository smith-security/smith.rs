
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    #[serde(rename = "sub")]
    pub user_id: String
}

#[derive(Debug, PartialEq, Clone)]
pub struct Environment {
    pub name: String
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct AuthorityPublicKeys {
    #[serde(rename = "public-keys")]
    pub keys: Vec<String>
}

#[derive(Debug, PartialEq, Clone)]
pub struct PublicKey {
    pub encoded: String
}

#[derive(Debug, PartialEq, Clone)]
pub struct Principal {
    pub name: String
}

#[derive(Debug, PartialEq, Clone)]
pub struct HostName {
    pub host: String
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Certificate {
    #[serde(rename = "certificate")]
    pub encoded: String,
}

#[derive(Debug, PartialEq, Clone)]
pub struct DeconstructedCertificate {
    pub key_type: String,
    pub blob: Vec<u8>,
    pub comment: Option<String>,
}

impl Certificate {
    pub fn deconstruct(&self) -> Option<DeconstructedCertificate> {
        let parts = self.encoded.split(' ').collect::<Vec<_>>();
        if parts.len() < 2 || parts.len() > 3 {
            return None;
        }
        let key_type = parts[0].to_string();
        let blob = base64::decode(&parts[1]).ok()?;
        let comment = if parts.len() == 3 {
            Some(parts[2].to_string())
        } else {
            None
        };
        Some(DeconstructedCertificate { key_type, blob, comment })
    }
}
