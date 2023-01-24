use actix_web::{ HttpRequest, http::StatusCode };
use tracing::{ warn, metadata::LevelFilter, Subscriber };
use tracing_subscriber::{ fmt, Layer, Registry, prelude::__tracing_subscriber_SubscriberExt };

pub struct Logger {}
impl Logger {
    pub fn new() -> Logger {
        Logger {}
    }
    pub fn record(&self, req: HttpRequest, body: String, status_code: StatusCode) {
        let binding = req.connection_info();
        let remote_ip = binding.realip_remote_addr().unwrap_or_default();
        let mut headers: Vec<String> = vec![];
        for h in req.headers().clone() {
            let name = h.0.to_string();
            let value = h.1.to_str().unwrap_or_default();
            let s = name + "=" + value;
            headers.push(s);
        }
        let path = req.path();
        let qs = req.query_string();
        let h = headers
            .iter()

            .map(|x| x.to_string() + ",")
            .collect::<String>();
        warn!(target: "honeyaml::access-log", 
        remote_ip= remote_ip, 
        path= path, method= req.method().to_string(),
        query_string=qs,
        body=body, 
        status_code=status_code.as_u16(),
        headers=h)
    }
}

pub fn setup_logger(
    directory: String,
    file_name_prefix: String,
    log_severity: LevelFilter
) -> std::io::Result<impl Subscriber> {
    std::fs::create_dir_all(directory.clone())?;
    let file_appender = tracing_appender::rolling::daily(directory, file_name_prefix);
    // enable non_blocking if necessary
    // let (non_blocking, _guard1) = tracing_appender::non_blocking(file_appender);
    let file_layer = fmt::Layer::new().json().with_writer(file_appender).with_filter(log_severity);

    let stdout_log = tracing_subscriber::fmt::layer().with_filter(log_severity);
    let subscriber = Registry::default().with(stdout_log).with(file_layer);
    Ok(subscriber)
}

pub fn verbosity_to_level_filter(severity: u8) -> LevelFilter {
    match severity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use glob::glob;
    #[test]
    fn test_logging() {
        let level = verbosity_to_level_filter(10);
        assert!(level == LevelFilter::TRACE);
        let level = verbosity_to_level_filter(0);
        assert!(level == LevelFilter::WARN);
        let level = verbosity_to_level_filter(1);
        assert!(level == LevelFilter::INFO);
        let level = verbosity_to_level_filter(2);
        assert!(level == LevelFilter::DEBUG);

        let req = actix_web::test::TestRequest
            ::default()
            .insert_header(actix_web::http::header::ContentType::plaintext())
            .to_http_request();
        let body = "F00oo00oo".to_string();
        let status_code = actix_web::http::StatusCode::OK;

        let sub = setup_logger("/tmp".to_string(), "honeyaml.log".to_string(), level).unwrap();

        tracing::subscriber::set_global_default(sub).unwrap();

        let l = Logger::new();
        l.record(req, body.clone(), status_code);

        if let Ok(paths) = glob("/tmp/honeyaml.log*") {
            for path in paths.flatten() {
                let s = std::fs::read_to_string(path.clone()).unwrap();
                assert!(s.contains(&body));
                _ = std::fs::remove_file(path);
            }
        } else {
            assert_eq!("cannot find matching pattern", "doesnt matter")
        }
    }
}