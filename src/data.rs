
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
