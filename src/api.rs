use actix_web::{get, App, middleware::Logger, HttpServer};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
	port: u16,
	listen: String
}

#[get("/")]
async fn index() -> &'static str {
	concat!("🦀 ", env!("CARGO_PKG_NAME"), " v", env!("CARGO_PKG_VERSION"), " is running")
}

pub(crate) async fn actix_main(config: Option<Config>) -> anyhow::Result<()> {
	if let Some(config) = config {
		HttpServer::new(|| {
			App::new().service(index)
			.wrap(Logger::new("%U by %{User-Agent}i -> %s in %T second"))
		})
		.bind((config.listen, config.port))?
		.run()
		.await?;
	}
	Ok(())
}
