mod schema;
mod logger;
mod handler;
mod state;

use actix_web::{ App, web, HttpServer, rt::time::sleep };
use clap::{ command, Parser };
use schema::WebPath;
use std::fs;
use actix_cors::Cors;
use anyhow::{ Result, Context };

#[derive(Parser)]
#[command(
    author("https://github.com/mmta"),
    version,
    about = "Honeyaml",
    long_about = "Honeyaml server\n\nAn API server honeypot configurable through YAML file"
)]
struct Args {
    /// TCP listening port
    #[arg(short('p'), long, env, value_name = "port", default_value_t = 8080)]
    port: u16,
    /// Number of workers
    #[arg(short('w'), long, env, value_name = "workers", default_value_t = 2)]
    workers: u8,
    /// Directory path to write log files
    #[arg(short('d'), long, env, value_name = "path", default_value = ".")]
    directory: String,
    /// Path to YAML config file
    #[arg(short('f'), long, env, value_name = "path", default_value = "./api.yml")]
    file: String,
    /// Increase logging verbosity
    #[arg(short('v'), long, action = clap::ArgAction::Count)]
    verbosity: u8,
}

fn extract_methods(web_paths: Vec<schema::WebPath>) -> Vec<String> {
    let mut methods = vec![];
    for p in web_paths {
        methods.push(p.method.clone());
    }
    methods.sort_unstable();
    methods.dedup();
    methods
}

fn parse_yaml(yaml: String) -> Result<Vec<schema::WebPath>> {
    let web_paths: Vec<schema::WebPath> = serde_yaml::from_str(&yaml)?;
    Ok(web_paths)
}

struct AuthSpec {
    method: String,
    path: Option<String>,
}

fn parse_authspec(web_paths: Vec<WebPath>) -> AuthSpec {
    let mut auth_spec = AuthSpec { method: "GET".to_string(), path: None };
    for p in &web_paths {
        if p.path_type == schema::PathType::Authenticator {
            auth_spec.method = p.method.to_ascii_uppercase();
            auth_spec.path = Some(p.path.clone());
            break;
        }
    }
    auth_spec
}

fn data_factory(web_paths: Vec<WebPath>, key: jwt_simple::prelude::HS256Key) -> state::AppState {
    let mut state = state::AppState {
        paths: web_paths.clone(),
        key: state::key_from_bytes(&key.to_bytes()),
        ..Default::default()
    };

    for p in &web_paths {
        if p.path_type == schema::PathType::Authenticator {
            state.jwt_issuer = p.auth_config.issuer.to_string();
            state.jwt_subject = p.auth_config.subject.to_string();
            state.jwt_audience = p.auth_config.audience.to_string();
            state.accounts = p.accounts.clone();
            break;
        }
    }
    state
}

async fn run(args: Args, listen: bool, require_logging: bool) -> Result<()> {
    let log_severity = logger::verbosity_to_level_filter(args.verbosity);

    let sub = logger
        ::setup_logger(args.directory.clone(), "honeyaml.log".to_owned(), log_severity)
        .context(format!("cannot setup logger on {}", args.directory))?;

    let log_result = tracing::subscriber
        ::set_global_default(sub)
        .context("cannot set global subscriber for logging");
    if require_logging && log_result.is_err() {
        return Err(log_result.unwrap_err());
    }

    let s = fs::read_to_string(args.file.clone()).context(format!("cannot read {}", args.file))?;
    let web_paths = parse_yaml(s).context(format!("cannot parse {}", args.file))?;

    // all threads get the same key
    let key = state::generate_key();

    let server = HttpServer::new(move || {
        let bindings = extract_methods(web_paths.clone());
        let methods: Vec<&str> = bindings.iter().map(String::as_str).collect();
        let app = App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_header()
                    .allowed_methods(methods)
                    .disable_vary_header()
            )
            .app_data(web::Data::new(data_factory(web_paths.clone(), key.clone())));

        let auth_spec = parse_authspec(web_paths.clone());
        if let Some(v) = auth_spec.path {
            let r = if auth_spec.method == "GET" {
                web::get().to(handler::authenticate_get)
            } else {
                web::post().to(handler::authenticate_post)
            };

            app.route(&v, r)
                .route("/{tail:.*}", web::get().to(handler::handler))
                .route("/{tail:.*}", web::post().to(handler::handler))
                .route("/{tail:.*}", web::put().to(handler::handler))
                .route("/{tail:.*}", web::delete().to(handler::handler))
        } else {
            app.route("/{tail:.*}", web::get().to(handler::handler))
                .route("/{tail:.*}", web::post().to(handler::handler))
                .route("/{tail:.*}", web::put().to(handler::handler))
                .route("/{tail:.*}", web::delete().to(handler::handler))
        }
    });
    let server = server.workers(args.workers.into()).bind(("0.0.0.0", args.port))?.run();
    let handle = server.handle();
    if !listen {
        actix_web::rt::spawn(async move {
            sleep(std::time::Duration::from_secs(1)).await;
            handle.stop(true).await;
        });
    }
    server.await?;
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<()> {
    run(Args::parse(), true, true).await
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use super::*;

    #[test]
    fn test_helpers() {
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
        let s = parse_yaml(yaml.to_string());
        assert!(s.is_ok());
        let paths = s.unwrap();
        assert_eq!(paths.len(), 3);
        let m = extract_methods(paths.clone());
        assert_eq!(m, ["GET", "POST"]);
        let a = parse_authspec(paths.clone());
        assert_eq!(a.path.unwrap(), "/auth".to_string());
        let args = Args::parse();
        assert_eq!(args.file, "./api.yml");

        let state = data_factory(paths, state::generate_key());
        assert_eq!(state.jwt_audience, "MyApp");
    }

    #[actix_web::test]
    async fn test_run() {
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
    ";
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "{}", yaml).unwrap();
        let path = tmpfile.path();
        let args = Args {
            port: 9101,
            directory: "/tmp".to_string(),
            file: path.to_string_lossy().to_string(),
            workers: 1,
            verbosity: 0,
        };
        let r = run(args, false, false).await;
        assert!(r.is_ok());

        // no auth section
        let yaml =
            r"
          - path: /end-point1
            path_type: rest
            method: GET
            auth_required: true
            return_code: 201
            return_text: Hello world
        ";
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "{}", yaml).unwrap();
        let path = tmpfile.path();
        let args = Args {
            port: 9102,
            directory: "/tmp".to_string(),
            file: path.to_string_lossy().to_string(),
            workers: 1,
            verbosity: 0,
        };
        let r = run(args, false, false).await;
        assert!(r.is_ok())
    }
}