use crate::{
	blocklist::{BlockList, FailedList, ListType, QueryInfo},
	CARGO_PKG_NAME, CARGO_PKG_VERSION
};
use anyhow::Context;
use log::info;
use poem::{http::StatusCode, listener::TcpListener, Route, Server};
use poem_openapi::{
	auth::ApiKey,
	param::Query,
	payload::{Html, Json},
	types::Example,
	Object, OpenApi, OpenApiService, SecurityScheme
};
use serde::Deserialize;
use std::{
	collections::HashMap,
	path::{Path, PathBuf},
	sync::{atomic::Ordering, Arc}
};
use time::OffsetDateTime;

#[derive(Debug, Deserialize, Object)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
	pub listener: String,
	#[serde(default)]
	pub show_doc: bool,
	pub admin_key: Option<String>
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
	key: Option<String>,
	blocklist: Arc<BlockList>
}

#[derive(Clone, Debug, poem_openapi::Object)]
pub(crate) struct OkList {
	/// count of domains inside this List
	pub(crate) len: u64,
	pub(crate) url: String,
	#[oai(rename = "type")]
	pub(crate) tipe: ListType
}

#[derive(Clone, Debug, poem_openapi::Object)]
/// updating the list has failed.
/// But an old cached version can still be used
pub(crate) struct UpdateFailedList {
	/// count of domains inside this List
	pub(crate) len: u64,
	pub(crate) url: String,
	#[oai(rename = "type")]
	pub(crate) tipe: ListType,
	/// reason why updating list failed
	pub(crate) error: String
}

#[derive(Clone, Debug, poem_openapi::Union)]
#[oai(discriminator_name = "state", rename_all = "lowercase")]
pub(crate) enum List {
	Ok(OkList),
	UpdateFailed(UpdateFailedList),
	Error(FailedList)
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
			blocklist_len: self.blocklist.len().await,
			running_since: self.stats.running_since
		})
	}

	/// query a domain, to test if it is blocked.
	/// Return all blocklists that contain this domain.
	#[oai(path = "/query.json", method = "get")]
	async fn query(
		&self,
		key: Key,
		domain: Query<String>
	) -> poem::Result<Json<HashMap<String, QueryInfo>>> {
		key.validate(self)?;
		let lists = self.blocklist.query(&domain).await;
		Ok(Json(lists))
	}

	/// Return all blocklists.
	#[oai(path = "/lists.json", method = "get")]
	async fn lists(&self, key: Key) -> poem::Result<Json<Vec<List>>> {
		key.validate(self)?;
		Ok(Json(self.blocklist.list().await))
	}

	/// private statistics
	#[oai(path = "/all_stats.json", method = "get")]
	async fn all_stats(&self, key: Key) -> poem::Result<Json<Stats>> {
		key.validate(self)?;
		Ok(Json(Stats {
			total_request: self.stats.total_request.load(Ordering::Relaxed),
			blocked_request: self.stats.blocked_request.load(Ordering::Relaxed),
			blocklist_len: self.blocklist.len().await,
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
	blocklist: Arc<BlockList>
) -> anyhow::Result<()> {
	if let Some(config) = config {
		let api_data = Api {
			blocklist,
			doc_enable: config.show_doc,
			stats,
			key: config.admin_key
		};
		let api_service =
			OpenApiService::new(api_data, CARGO_PKG_NAME, CARGO_PKG_VERSION)
				.server(&config.listener);
		let doc = if config.show_doc {
			Some(api_service.redoc())
		} else {
			None
		};
		let server = Route::new().nest("/", api_service);
		let server = if let Some(doc) = doc {
			server.nest("/doc", doc)
		} else {
			server
		};
		info!("start api/web server at {:?}", config.listener);
		if let Some(listener) = config.listener.strip_prefix("unix://") {
			#[cfg(not(unix))]
			{
				anyhow::bail!("unix sockets is only supported on unix systems");
			}
			#[cfg(unix)]
			{
				use poem::listener::UnixListener;
				use std::fs::remove_file;

				/// Delete the given file on drop
				struct FileDeleter(PathBuf);
				impl Drop for FileDeleter {
					fn drop(&mut self) {
						info!("delete socket: {:?}", self.0);
						if let Err(err) = remove_file(&self.0).with_context(|| {
							format!("failed to remove file {:?}", self.0)
						}) {
							eprintln!("{err:?}");
						}
					}
				}

				let path = Path::new(listener);
				// If the socket doesn't exist yet, we want to delete it after exiting the program.
				// If it already existed, it was probally created by a service like systemd, so we want to keep it.
				let delete_file = if path.exists() {
					None
				} else {
					Some(FileDeleter(path.to_owned()))
				};
				Server::new(UnixListener::bind(listener))
					.run(server)
					.await?;
				drop(delete_file);
			}
		} else {
			Server::new(TcpListener::bind(config.listener))
				.run(server)
				.await?;
		}
	}
	Ok(())
}
