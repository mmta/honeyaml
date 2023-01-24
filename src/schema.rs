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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_deserialize_and_match() {
        let yaml =
            r"
      - path: /auth
        path_type: authenticator
        method: POST
        authorization: jwt
        auth_config:
          issuer: Org
          subject: MyApp
          audience: MyApp
        accounts:
          - username: user
            password: passwd1
          - username: user2
            password: passwd2
        ";

        let web_paths: Vec<WebPath> = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(web_paths.len(), 1);

        let p = WebPath {
            path: "/end-point1".to_owned(),
            path_type: PathType::Rest,
            method: "get".to_owned(),
            auth_required: false,
            return_code: 200,
            return_text: "".to_owned(),
            authorization: AuthorizationType::Jwt,
            auth_config: AuthConfig::default(),
            accounts: vec![],
        };
        assert!(p.is_match("GET".to_owned(), PathType::Rest, "/end-point1/foo"));
        assert!(p.is_match("GET".to_owned(), PathType::Rest, "/end-point1/foo?q=bar"));
        assert!(!p.is_match("GET".to_owned(), PathType::Authenticator, "/end-point1"));
        assert!(!p.is_match("post".to_owned(), PathType::Rest, "/end-point1/foo"));
        assert!(!p.is_match("get".to_owned(), PathType::Rest, "/end-point2"));
        assert!(!p.is_match("get".to_owned(), PathType::Rest, "/end-point"));
    }
}