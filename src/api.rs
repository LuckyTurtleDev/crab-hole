use log::info;
use poem::{listener::TcpListener, Route, Server};
use poem_openapi::{
	payload::{Html, Json},
	Object, OpenApi, OpenApiService
};
use serde::Deserialize;

use crate::{CARGO_PKG_NAME, CARGO_PKG_VERSION};

#[derive(Debug, Deserialize, Object)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
	port: u16,
	listen: String,
	#[serde(default)]
	show_doc: bool
}

#[derive(Debug, Object)]
struct Info {
	#[oai(rename = "crate")]
	krate: String,
	version: String
}

struct Api {
	doc_enable: bool
}

#[OpenApi]
impl Api {
	/// provide basic info about the running server
	#[oai(path = "/info.json", method = "get")]
	async fn info(&self) -> Json<Info> {
		Json(Info {
			krate: CARGO_PKG_NAME.to_owned(),
			version: CARGO_PKG_VERSION.to_owned()
		})
	}

	/// landing page
	#[oai(path = "/", method = "get")]
	async fn index(&self) -> Html<String> {
		let doc_hint = if self.doc_enable {
			"<br>OpenApi doc is available <a href=\"/doc\">here</a>."
		} else {
			Default::default()
		};
		Html(format!(
			"🦀 {CARGO_PKG_NAME} v{CARGO_PKG_VERSION} is running. {doc_hint}"
		))
	}
}

/// start api/web server if config is Some
pub(crate) async fn init(config: Option<Config>) -> anyhow::Result<()> {
	if let Some(config) = config {
		let address = format!("{}:{}", config.listen, config.port);
		let api_data = Api {
			doc_enable: config.show_doc
		};
		let api_service =
			OpenApiService::new(api_data, CARGO_PKG_NAME, CARGO_PKG_VERSION)
				.server(&address);
		let doc = api_service.redoc();
		let server = Route::new().nest("/", api_service);
		let server = if config.show_doc {
			server.nest("/doc", doc)
		} else {
			server
		};
		info!("start api/web server at {address:?}");
		Server::new(TcpListener::bind(address)).run(server).await?;
	}
	Ok(())
}
