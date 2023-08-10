use log::info;
use poem::{http::StatusCode, listener::TcpListener, Route, Server};
use poem_openapi::{
	auth::ApiKey,
	payload::{Html, Json},
	types::Example,
	Object, OpenApi, OpenApiService, SecurityScheme
};
use serde::Deserialize;
use std::sync::{
	atomic::{AtomicUsize, Ordering},
	Arc
};
use time::OffsetDateTime;

use crate::{CARGO_PKG_NAME, CARGO_PKG_VERSION};

#[derive(Debug, Deserialize, Object)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
	port: u16,
	listen: String,
	#[serde(default)]
	show_doc: bool,
	admin_key: Option<String>
}

#[derive(Debug, Object)]
#[oai(example = true)]
struct Info {
	#[oai(rename = "crate")]
	krate: String,
	version: String
}
impl Example for Info {
	fn example() -> Self {
		Self {
			krate: CARGO_PKG_NAME.to_owned(),
			version: CARGO_PKG_VERSION.to_owned()
		}
	}
}

#[derive(SecurityScheme)]
#[oai(ty = "api_key", key_in = "query", key_name = "key")]
struct Key(ApiKey);

impl Key {
	fn validate(&self, api: &Api) -> poem::Result<()> {
		if let Some(key) = &api.key {
			if key == &self.0.key {
				return Ok(());
			}
		}
		Err(poem::Error::from_status(StatusCode::UNAUTHORIZED))
	}
}

#[derive(Debug, Object)]
struct PubStats {
	blocked_ratio: f32,
	blocklist_len: usize,
	running_since: OffsetDateTime
}

#[derive(Debug, Object)]
struct Stats {
	/// total dns request since start
	total_request: u64,
	/// blocked dns request since start
	blocked_request: u64,
	blocklist_len: usize,
	running_since: OffsetDateTime
}

struct Api {
	doc_enable: bool,
	stats: crate::Stats,
	blocklist_len: Arc<AtomicUsize>,
	key: Option<String>
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

	/// basic statistics
	#[oai(path = "/stats.json", method = "get")]
	async fn stats(&self) -> Json<PubStats> {
		let total_request = self.stats.total_request.load(Ordering::Relaxed);
		let blocked_ratio = if total_request == 0 {
			0.0
		} else {
			self.stats.blocked_request.load(Ordering::Relaxed) as f32
				/ total_request as f32
		};
		// privacy: round to three digs
		let blocked_ratio = (blocked_ratio * 100.0).round() / 100.0;
		Json(PubStats {
			blocked_ratio,
			blocklist_len: self.blocklist_len.load(Ordering::Relaxed),
			running_since: self.stats.running_since
		})
	}

	/// private statistics
	#[oai(path = "/all_stats.json", method = "get")]
	async fn all_stats(&self, key: Key) -> poem::Result<Json<Stats>> {
		key.validate(self)?;
		Ok(Json(Stats {
			total_request: self.stats.total_request.load(Ordering::Relaxed),
			blocked_request: self.stats.blocked_request.load(Ordering::Relaxed),
			blocklist_len: self.blocklist_len.load(Ordering::Relaxed),
			running_since: self.stats.running_since
		}))
	}

	/// landing page
	#[oai(path = "/", method = "get", hidden = true)]
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
pub(crate) async fn init(
	config: Option<Config>,
	stats: crate::Stats,
	blocklist_len: Arc<AtomicUsize>
) -> anyhow::Result<()> {
	if let Some(config) = config {
		let address = format!("{}:{}", config.listen, config.port);
		let api_data = Api {
			doc_enable: config.show_doc,
			stats,
			blocklist_len,
			key: config.admin_key
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
