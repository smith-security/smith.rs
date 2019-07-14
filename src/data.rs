
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    #[serde(rename = "sub")]
    pub user_id: String
}
