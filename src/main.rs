mod schema;
mod logger;
mod handler;
mod state;

use actix_web::{ App, web, HttpServer };
use clap::{ command, Parser };
use tracing::metadata::LevelFilter;
use tracing_subscriber::{ fmt, prelude::__tracing_subscriber_SubscriberExt, Registry, Layer };
use std::fs;
use actix_cors::Cors;

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let log_severity = match args.verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    fs::create_dir_all(args.directory.clone())?;
    let file_appender = tracing_appender::rolling::daily(args.directory, "honeyaml.log");
    let (non_blocking, _guard1) = tracing_appender::non_blocking(file_appender);
    let file_layer = fmt::Layer::new().json().with_writer(non_blocking).with_filter(log_severity);

    let stdout_log = tracing_subscriber::fmt::layer().with_filter(log_severity);
    let subscriber = Registry::default().with(stdout_log).with(file_layer);

    tracing::subscriber::set_global_default(subscriber).unwrap();

    let yaml = fs::read_to_string("api.yaml")?;
    let web_paths: Vec<schema::WebPath> = serde_yaml::from_str(&yaml).unwrap();

    let mut methods: Vec<String> = vec![];
    for p in web_paths.clone() {
        methods.push(p.method.clone());
    }
    methods.sort_unstable();
    methods.dedup();

    // all threads get the same key
    let key = state::generate_key();

    HttpServer::new(move || {
        let mut state = state::AppState {
            paths: web_paths.clone(),
            key: state::key_from_bytes(&key.to_bytes()),
            ..Default::default()
        };

        let mut auth_method = "GET".to_string();
        let mut auth_path: Option<String> = None;

        for p in &web_paths {
            if p.path_type == schema::PathType::Authenticator {
                state.jwt_issuer = p.auth_config.issuer.to_string();
                state.jwt_subject = p.auth_config.subject.to_string();
                state.jwt_audience = p.auth_config.audience.to_string();
                state.accounts = p.accounts.clone();
                auth_method = p.method.to_ascii_uppercase();
                auth_path = Some(p.path.clone());
                break;
            }
        }

        let v: Vec<&str> = methods
            .iter()
            .map(|s| &**s)
            .collect();

        let app = App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_header()
                    .allowed_methods(v)
                    .disable_vary_header()
            )
            .app_data(web::Data::new(state));
        if let Some(v) = auth_path {
            let r = if auth_method == "GET" {
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
    })
        .workers(args.workers.into())
        .bind(("0.0.0.0", args.port))?
        .run().await
}