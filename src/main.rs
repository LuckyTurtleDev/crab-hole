#![warn(rust_2018_idioms, unreachable_pub)]
#![forbid(elided_lifetimes_in_paths, unsafe_code)]

mod api;
mod blocklist;
mod parser;
mod trie;

use anyhow::Context;
use async_trait::async_trait;
use blocklist::BlockList;
use directories::ProjectDirs;
use log::{debug, info};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use std::{
	env::var,
	fs, iter,
	path::PathBuf,
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc
	},
	time::Duration
};
use time::OffsetDateTime;
use tokio::{net::UdpSocket, time::sleep};
use trust_dns_proto::{
	op::{header::Header, response_code::ResponseCode},
	rr::Name
};
use trust_dns_server::{
	authority::{Catalog, MessageResponseBuilder, ZoneType},
	server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
	store::forwarder::{ForwardAuthority, ForwardConfig},
	ServerFuture as Server
};
use url::Url;

const CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");
const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

static PROJECT_DIRS: Lazy<ProjectDirs> = Lazy::new(|| {
	ProjectDirs::from("dev", "luckyturtle", CARGO_PKG_NAME)
		.expect("failed to get project dirs")
});
static LIST_DIR: Lazy<PathBuf> = Lazy::new(|| {
	if let Ok(var) = var(format!(
		"{}_DIR",
		CARGO_PKG_NAME.to_uppercase().replace('-', "_")
	)) {
		PathBuf::from(var).join("lists")
	} else {
		PROJECT_DIRS.cache_dir().to_owned()
	}
});

static CONFIG_PATH: Lazy<PathBuf> = Lazy::new(|| {
	if let Ok(var) = var(format!(
		"{}_DIR",
		CARGO_PKG_NAME.to_uppercase().replace('-', "_")
	)) {
		PathBuf::from(var)
	} else {
		#[cfg(not(debug_assertions))]
		{
			let path = PROJECT_DIRS.config_dir().join("config.toml");
			#[cfg(target_family = "unix")]
			if !path.exists() {
				let alternative_path: String = format!("/etc/{CARGO_PKG_NAME}.toml");
				info!(
					"{:?} does not exist use {alternative_path:?} instead",
					path.to_string_lossy()
				);
				return alternative_path.into();
			}
			return path;
		}
		#[cfg(debug_assertions)]
		PathBuf::new()
	}
	.join("config.toml")
});

static CLIENT: Lazy<Client> = Lazy::new(Client::new);

struct CrabHole {
	blocklist: BlockList,
	include_subdomains: bool,

	running_since: OffsetDateTime,
	blocklist_len: AtomicUsize,
	queries_all: AtomicUsize,
	queries_blocked: AtomicUsize
}

impl CrabHole {
	async fn update_blocklist(&self, adlist: &[Url], restore_from_cache: bool) {
		self.blocklist.update(adlist, restore_from_cache).await;
		self.blocklist_len
			.store(self.blocklist.len().await, Ordering::Relaxed);
	}

	async fn new(config: &Config) -> Self {
		let this = Self {
			blocklist: BlockList::new(),
			include_subdomains: config.blocklist.include_subdomains,

			running_since: OffsetDateTime::now_utc(),
			blocklist_len: 0.into(),
			queries_all: 0.into(),
			queries_blocked: 0.into()
		};
		this.update_blocklist(&config.blocklist.lists, true).await;
		this
	}

	/// Test if a domain is blocked
	async fn is_blocked(&self, domain: &str) -> bool {
		self.blocklist
			.contains(domain.trim_end_matches('.'), self.include_subdomains)
			.await
	}

	/// Increase queries count
	fn inc_queries_counter(&self) {
		self.queries_all.fetch_add(1, Ordering::Relaxed);
	}

	/// Increase queries blocked count
	fn inc_queries_blocked_counter(&self) {
		self.queries_blocked.fetch_add(1, Ordering::Relaxed);
	}
}

struct Handler {
	catalog: Catalog,
	crabhole: Arc<CrabHole>
}

impl Handler {
	fn new(config: &Config, crabhole: Arc<CrabHole>) -> Self {
		let zone_name = Name::root();
		let authority = ForwardAuthority::try_from_config(
			zone_name.clone(),
			ZoneType::Forward,
			&config.upstream
		)
		.expect("Failed to create forwarder");

		let mut catalog = Catalog::new();
		catalog.upsert(zone_name.into(), Box::new(Arc::new(authority)));

		Self { catalog, crabhole }
	}
}

#[async_trait]
impl RequestHandler for Handler {
	async fn handle_request<R: ResponseHandler>(
		&self,
		request: &Request,
		mut response_handler: R
	) -> ResponseInfo {
		self.crabhole.inc_queries_counter();
		let lower_query = request.request_info().query;
		if self
			.crabhole
			.is_blocked(&lower_query.name().to_string())
			.await
		{
			self.crabhole.inc_queries_blocked_counter();
			debug!("blocked: {lower_query:?}");
			let mut header = Header::response_from_request(request.header());
			header.set_response_code(ResponseCode::NXDomain);
			return response_handler
				.send_response(
					MessageResponseBuilder::from_message_request(request).build(
						header,
						iter::empty(),
						iter::empty(),
						iter::empty(),
						iter::empty()
					)
				)
				.await
				.unwrap_or_else(|_| {
					let mut header = Header::new();
					header.set_response_code(ResponseCode::ServFail);
					header.into()
				});
		} else {
			debug!("{lower_query:?}");
		}

		self.catalog.handle_request(request, response_handler).await
	}
}

#[tokio::main]
async fn async_main(config: Config) {
	let crabhole = Arc::new(CrabHole::new(&config).await);
	let handler = Handler::new(&config, crabhole.clone());
	let mut server = Server::new(handler);
	for downstream in config.downstream {
		info!("add downstream {:?}", downstream);
		match downstream {
			DownstreamConfig::Udp(downstream) => {
				let socket_addr = downstream.socket_addr();
				let udp_socket = UdpSocket::bind(&socket_addr)
					.await
					.with_context(|| format!("failed to bind udp socket {}", socket_addr))
					.unwrap_or_else(|err| panic!("{err:?}"));
				server.register_socket(udp_socket);
			},

			DownstreamConfig::HttpApi(HttpConfig { downstream, url }) => {
				tokio::spawn(gotham::init_server(
					downstream.socket_addr(),
					api::build_api_router(&url, crabhole.clone())
				));
			}
		}
	}

	tokio::spawn(async {
		let crabhole = crabhole;
		let lists = config.blocklist.lists;
		loop {
			crabhole.update_blocklist(&lists, false).await;
			sleep(Duration::from_secs(7200)).await; //2h
		}
	});

	info!("🚀 start dns server");
	server
		.block_until_done()
		.await
		.expect("failed to run dns server");
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
	upstream: ForwardConfig,
	downstream: Vec<DownstreamConfig>,
	blocklist: BlockConfig
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockConfig {
	lists: Vec<Url>,
	include_subdomains: bool
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "protocol")]
enum DownstreamConfig {
	Udp(UdpConfig),
	HttpApi(HttpConfig)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UdpConfig {
	port: u16,
	listen: String
}

impl UdpConfig {
	fn socket_addr(&self) -> String {
		format!("{}:{}", self.listen, self.port)
	}
}

#[derive(Debug, Deserialize)]
struct HttpConfig {
	#[serde(flatten)]
	downstream: UdpConfig,
	url: String
}

fn main() {
	my_env_logger_style::get_set_max_module_len(20);
	my_env_logger_style::just_log();
	info!("🦀 {CARGO_PKG_NAME}  v{CARGO_PKG_VERSION} 🦀");
	Lazy::force(&CONFIG_PATH);
	Lazy::force(&LIST_DIR);

	info!("load config from {:?}", &*CONFIG_PATH);
	let config = fs::read(&*CONFIG_PATH)
		.with_context(|| format!("Failed to read {:?}", CONFIG_PATH.as_path()))
		.unwrap_or_else(|err| panic!("{err:?}"));
	let config: Config = toml::from_slice(&config)
		.with_context(|| "Failed to deserialize config")
		.unwrap_or_else(|err| panic!("{err:?}"));
	debug!("{:#?}", config);
	async_main(config);
}
