#![warn(rust_2018_idioms, unreachable_pub)]
#![forbid(elided_lifetimes_in_paths, unsafe_code)]

mod parser;

use anyhow::Context;
use async_trait::async_trait;
use directories::ProjectDirs;
use log::{debug, info};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use std::{env::var, fs, iter, path::PathBuf, sync::Arc, time::Duration};
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

mod trie;

mod blocklist;
use blocklist::BlockList;

struct Handler {
	catalog: Catalog,
	blocklist: Arc<BlockList>,
	include_subdomains: bool
}

impl Handler {
	async fn new(config: &Config) -> Self {
		let zone_name = Name::root();
		let authority = ForwardAuthority::try_from_config(
			zone_name.clone(),
			ZoneType::Forward,
			&config.upstream
		)
		.expect("Failed to create forwarder");

		let mut catalog = Catalog::new();
		catalog.upsert(zone_name.into(), Box::new(Arc::new(authority)));

		let blocklist = BlockList::new();
		blocklist.update(&config.blocklist.lists, true).await;

		Self {
			catalog,
			blocklist: Arc::new(blocklist),
			include_subdomains: config.blocklist.include_subdomains
		}
	}
}

#[async_trait]
impl RequestHandler for Handler {
	async fn handle_request<R: ResponseHandler>(
		&self,
		request: &Request,
		mut response_handler: R
	) -> ResponseInfo {
		let lower_query = request.request_info().query;
		if self
			.blocklist
			.contains(
				lower_query.name().to_string().trim_end_matches('.'),
				self.include_subdomains
			)
			.await
		{
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
	let handler = Handler::new(&config).await;
	let blocklist = handler.blocklist.clone();
	let mut server = Server::new(handler);
	for downstream in config.downstream {
		info!("add downstream {:?}", downstream);
		match downstream {
			DownstreamConfig::Udp(downstream) => {
				let socket_addr = format!("{}:{}", downstream.listen, downstream.port);
				let udp_socket = UdpSocket::bind(&socket_addr)
					.await
					.with_context(|| format!("failed to bind udp socket {}", socket_addr))
					.unwrap_or_else(|err| panic!("{err:?}"));
				server.register_socket(udp_socket);
			}
		}
	}
	tokio::spawn(async {
		let blocklist = blocklist;
		let lists = config.blocklist.lists;
		loop {
			blocklist.update(&lists, false).await;
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
#[serde(deny_unknown_fields, rename_all = "lowercase", tag = "protocol")]
enum DownstreamConfig {
	Udp(UdpConfig)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UdpConfig {
	port: u16,
	listen: String
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

#[cfg(test)]
mod tests {
	#[test]
	fn config_file() {
		let config = include_bytes!("../config.toml");
		let _: super::Config = toml::from_slice(config).unwrap();
	}
}
