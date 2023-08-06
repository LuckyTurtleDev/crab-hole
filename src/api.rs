use actix_web::{dev::Server, get, middleware, rt, web, App, HttpRequest, HttpServer};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
	port: u16,
	listen: String,
}

#[get("/")]
async fn index(req: HttpRequest) -> &'static str {
	println!("REQ: {:?}", req);
	"Hello world!\r\n"
}

pub(crate) async fn actix_main() -> anyhow::Result<()> {
	HttpServer::new(|| {
		App::new().service(web::resource("/").to(|| async { "hello world" }))
	})
	.bind(("127.0.0.1", 8080))?
	.run()
	.await?;
	Ok(())
}
