use actix_web::{ HttpRequest, http::StatusCode };
use tracing::warn;

#[derive(Default)]
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