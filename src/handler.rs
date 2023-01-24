use std::collections::{ HashMap, HashSet };

use actix_web::{ web, HttpRequest, HttpResponse, http, HttpResponseBuilder, Responder };
use actix_web_httpauth::extractors::bearer::BearerAuth;
use jwt_simple::{ prelude::*, reexports::serde_json };

use anyhow::Result;
use tracing::{ error, info };

use crate::{ schema, state::AppState };

fn check_token(data: &web::Data<AppState>, token: &str) -> Result<()> {
    let options = VerificationOptions {
        allowed_issuers: Some(HashSet::from_strings(&[data.jwt_issuer.clone()])),
        allowed_audiences: Some(HashSet::from_strings(&[data.jwt_audience.clone()])),
        required_subject: Some(data.jwt_subject.clone()),
        ..Default::default()
    };
    data.key.verify_token::<NoCustomClaims>(token, Some(options))?;
    Ok(())
}

pub async fn handler(
    data: web::Data<AppState>,
    req: HttpRequest,
    body: String,
    auth: Option<BearerAuth>
) -> HttpResponse {
    let mut cfg: Option<schema::WebPath> = None;
    for p in &data.paths {
        if p.is_match(req.method().to_string(), schema::PathType::Rest, req.path()) {
            cfg = Some(p.clone());
            break;
        }
    }
    if cfg.is_none() {
        data.logger.record(req, body, http::StatusCode::NOT_FOUND);
        return HttpResponse::NotFound().force_close().finish();
    }

    let c = cfg.unwrap();
    if c.auth_required {
        if auth.is_none() {
            data.logger.record(req, body, http::StatusCode::UNAUTHORIZED);
            return HttpResponse::Unauthorized().force_close().finish();
        }
        if let Err(e) = check_token(&data, auth.unwrap().token()) {
            info!("failed authentication: {}", e);
            data.logger.record(req, body, http::StatusCode::UNAUTHORIZED);
            return HttpResponse::Unauthorized().force_close().finish();
        }
    }
    let mut ret_code: Option<http::StatusCode> = None;
    if let Ok(v) = actix_web::http::StatusCode::from_u16(c.return_code) {
        if v.canonical_reason().is_some() {
            ret_code = Some(v);
        }
    }
    if ret_code.is_none() {
        error!("configuration error: {} is not a valid status code", c.return_code);
        data.logger.record(req, body, http::StatusCode::INTERNAL_SERVER_ERROR);
        return HttpResponse::InternalServerError().force_close().finish();
    }

    data.logger.record(req, body, ret_code.unwrap());
    HttpResponseBuilder::new(ret_code.unwrap())
        .force_close()
        .body(c.return_text + "\n")
}

fn authenticate(
    auth_param: HashMap<String, String>,
    data: actix_web::web::Data<AppState>,
    req: HttpRequest,
    body: String
) -> HttpResponse {
    let mut all_fields: Vec<String> = vec![];
    let mut found_fields: Vec<String> = vec![];
    for a in &data.accounts {
        let mut field_count = 0;
        let mut found_count = 0;
        for field in a {
            all_fields.push(field.0.clone());
            field_count += 1;

            for q in auth_param.clone() {
                if *field.0 == q.0 && *field.1 == q.1 {
                    found_count += 1;
                    found_fields.push(q.0);
                }
            }
        }
        if field_count != 0 && field_count == found_count {
            let claims = Claims::create(Duration::from_hours(2))
                .with_issuer(&data.jwt_issuer)
                .with_audience(&data.jwt_audience)
                .with_subject(&data.jwt_subject);
            data.logger.record(req, body, http::StatusCode::OK);
            return HttpResponse::Ok().body(
                data.key.authenticate(claims).unwrap_or_else(|_| "".to_string())
            );
        }
    }
    let mut diff: Vec<String> = all_fields
        .into_iter()
        .filter(|item| !found_fields.contains(item))
        .collect();
    diff.sort_unstable();
    diff.dedup();

    data.logger.record(req, body, http::StatusCode::UNAUTHORIZED);
    HttpResponse::Unauthorized().body(format!("incorrect/missing parameter {:?}\n", diff))
}

pub async fn authenticate_get(
    data: web::Data<AppState>,
    req: HttpRequest,
    body: String,
    qs: web::Query<HashMap<String, String>>
) -> impl Responder {
    authenticate(qs.0, data, req, body)
}

pub async fn authenticate_post(
    data: web::Data<AppState>,
    req: HttpRequest,
    body: String
) -> impl Responder {
    if let Ok(v) = serde_json::from_str(&body) {
        return authenticate(v, data, req, body);
    }
    HttpResponse::Unauthorized().finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_web::test]
    async fn test_handlers() {
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
      - path: /end-point1
        path_type: rest
        method: GET
        auth_required: true
        return_code: 201
        return_text: Hello world
      - path: /end-point3
        path_type: rest
        method: GET
        auth_required: true
        return_code: 700
        return_text: Wrong http code       
        ";

        let web_paths: Vec<schema::WebPath> = serde_yaml::from_str(yaml).unwrap();

        let mut state = crate::state::AppState {
            paths: web_paths.clone(),
            ..Default::default()
        };

        for p in web_paths {
            if p.path_type == schema::PathType::Authenticator {
                state.jwt_issuer = p.auth_config.issuer.to_string();
                state.jwt_subject = p.auth_config.subject.to_string();
                state.jwt_audience = p.auth_config.audience.to_string();
                state.accounts = p.accounts;
                break;
            }
        }

        let app = test::init_service(
            actix_web::App
                ::new()
                .app_data(web::Data::new(state))
                .route("/auth-get", web::get().to(authenticate_get))
                .route("/auth-post", web::post().to(authenticate_post))
                .route("/{tail:.*}", web::get().to(handler))
                .route("/{tail:.*}", web::post().to(handler))
        ).await;

        // path that doesn't exist
        let mut uri = "/x00x00".to_string();
        let req = test::TestRequest::get().uri(&uri.clone()).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 404);

        // successful login
        uri = "/auth-get?username=user&password=passwd1".to_string();
        let req = test::TestRequest::get().uri(&uri.clone()).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);

        // unsuccessful login
        uri = "/auth-get?username=user&password=passwd2".to_string();
        let req = test::TestRequest::get().uri(&uri.clone()).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 401);

        // unsuccessful login through POST
        uri = "/auth-post".to_string();
        let req = test::TestRequest::post().uri(&uri.clone()).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 401);

        // successful login through POST
        let mut data = HashMap::new();
        data.insert("username".to_owned(), "user".to_owned());
        data.insert("password".to_owned(), "passwd1".to_owned());

        let req = test::TestRequest::post().uri(&uri.clone()).set_json(data).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);

        // successful resource access
        uri = "/end-point1/foo".to_string();
        let b = test::read_body(resp).await;
        let s = std::str::from_utf8(&b).unwrap();

        let req = test::TestRequest
            ::get()
            .uri(&uri.clone())
            .insert_header(("Authorization", format!("Bearer {}", s)))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);

        // successful resource access to an incorrectly configured path
        uri = "/end-point3/bar".to_string();
        let req = test::TestRequest
            ::get()
            .uri(&uri.clone())
            .insert_header(("Authorization", format!("Bearer {}", s)))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 500);

        // resource access with incorrect token
        let req = test::TestRequest
            ::get()
            .uri(&uri.clone())
            .insert_header(("Authorization", "Bearer foobar"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 401);

        // resource access without token
        uri = "/end-point1/foo".to_string();
        let req = test::TestRequest::get().uri(&uri.clone()).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 401);
    }
}