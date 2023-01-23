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