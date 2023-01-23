use std::collections::HashMap;

use serde::Deserialize;
use regex::Regex;

#[derive(Deserialize, Debug, PartialEq, Clone)]
pub enum PathType {
    #[serde(rename(deserialize = "static"))]
    Static,
    #[serde(rename(deserialize = "authenticator"))]
    Authenticator,
    #[serde(rename(deserialize = "rest"))]
    Rest,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub enum AuthorizationType {
    #[serde(rename(deserialize = "jwt"))]
    #[default]
    Jwt,
}

#[derive(Deserialize, Debug, Default, Clone)]
pub struct AuthConfig {
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub audience: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct WebPath {
    pub path: String,
    pub path_type: PathType,
    pub method: String,
    #[serde(default)]
    pub auth_required: bool,
    #[serde(default)]
    pub return_code: u16,
    #[serde(default)]
    pub return_text: String,
    #[serde(default)]
    pub authorization: AuthorizationType,
    #[serde(default)]
    pub auth_config: AuthConfig,
    #[serde(default)]
    pub accounts: Vec<HashMap<String, String>>,
}

impl WebPath {
    pub fn is_match(&self, method: String, path_type: PathType, path: &str) -> bool {
        let s = "^".to_string() + &self.path + ".*";
        if let Ok(re) = Regex::new(&s) {
            let res =
                re.is_match(path) &&
                self.method.to_ascii_uppercase() == method.to_ascii_uppercase() &&
                self.path_type == path_type;
            return res;
        }
        false
    }
}