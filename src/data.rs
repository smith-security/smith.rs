
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
