#![warn(rust_2018_idioms, unreachable_pub)]
#![forbid(elided_lifetimes_in_paths, unsafe_code)]

mod api;
mod parser;

use anyhow::{bail, Context};
use async_trait::async_trait;
use directories::ProjectDirs;
use log::{debug, info};
use once_cell::sync::Lazy;
use reqwest::Client;
use rustls::{Certificate, PrivateKey};
use serde::Deserialize;
use std::{
	env::var,
	fs::{self, File},
	io::BufReader,
	iter,
	path::PathBuf,
	sync::{
		atomic::{AtomicU64, AtomicUsize, Ordering},
		Arc
	},
	time::Duration
};
use time::OffsetDateTime;
use tokio::{
	net::{TcpListener, UdpSocket},
	time::sleep,
	try_join
};
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

#[derive(Debug, Clone)]
struct Stats {
	total_request: Arc<AtomicU64>,
	blocked_request: Arc<AtomicU64>,
	running_since: OffsetDateTime
}

impl Default for Stats {
	fn default() -> Self {
		Self {
			total_request: Default::default(),
			blocked_request: Default::default(),
			running_since: OffsetDateTime::now_utc()
		}
	}
}

struct Handler {
	catalog: Catalog,
	blocklist: Arc<BlockList>,
	include_subdomains: bool,
	stats: Stats
}

impl Handler {
	async fn new(config: &Config, stats: Stats, blocklist_len: Arc<AtomicUsize>) -> Self {
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
		blocklist
			.update(&config.blocklist.lists, true, blocklist_len)
			.await;

		Self {
			catalog,
			blocklist: Arc::new(blocklist),
			include_subdomains: config.blocklist.include_subdomains,
			stats
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
		self.stats.total_request.fetch_add(1, Ordering::Relaxed);
		if self
			.blocklist
			.contains(
				lower_query.name().to_string().trim_end_matches('.'),
				self.include_subdomains
			)
			.await
		{
			debug!("blocked: {lower_query:?}");
			self.stats.blocked_request.fetch_add(1, Ordering::Relaxed);
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

async fn load_cert_and_key(
	cert_path: PathBuf,
	key_path: PathBuf
) -> anyhow::Result<(Vec<Certificate>, PrivateKey)> {
	let certificates: Vec<_> = rustls_pemfile::read_all(&mut BufReader::new(
		File::open(&cert_path)
			.with_context(|| format!("failed to open {:?}", cert_path))?
	))
	.with_context(|| format!("failed to parse {:?}", cert_path))?
	.iter()
	.filter_map(|cert| match cert {
		rustls_pemfile::Item::X509Certificate(cert) => Some(Certificate(cert.to_owned())),
		_ => None
	})
	.collect();
	if certificates.is_empty() {
		bail!(format!("no x509 certificate found in {:?}", cert_path));
	}
	let key = rustls_pemfile::read_all(&mut BufReader::new(
		File::open(&key_path)
			.with_context(|| format!("failed to open {:?}", key_path))?
	))
	.with_context(|| format!("failed to parse {:?}", key_path))?
	.iter()
	.find_map(|item| match item {
		rustls_pemfile::Item::ECKey(key) => Some(key),
		rustls_pemfile::Item::RSAKey(key) => Some(key),
		rustls_pemfile::Item::PKCS8Key(key) => Some(key),
		_ => None
	})
	.map(|key| PrivateKey(key.to_owned()))
	.ok_or_else(|| {
		anyhow::Error::msg("no private RSA/PKCS8/ECKey key found in {key_path:?}")
	})?;
	Ok((certificates, key))
}

#[tokio::main]
async fn async_main(config: Config) {
	let stats = Stats::default();
	let blocklist_len = Arc::new(AtomicUsize::new(0));
	let handler = Handler::new(&config, stats.clone(), blocklist_len.clone()).await;
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
			},
			DownstreamConfig::Tls(downstream) => {
				let cert_and_key =
					load_cert_and_key(downstream.certificate, downstream.key)
						.await
						.expect("failed to load certificate or private key");
				let socket_addr = format!("{}:{}", downstream.listen, downstream.port);
				let tcp_listener = TcpListener::bind(&socket_addr)
					.await
					.with_context(|| format!("failed to bind tcp socket {}", socket_addr))
					.unwrap_or_else(|err| panic!("{err:?}"));
				server
					.register_tls_listener(
						tcp_listener,
						Duration::from_millis(downstream.timeout_ms),
						cert_and_key
					)
					.expect("failed to register tls downstream")
			},
			DownstreamConfig::Https(downstream) => {
				let cert_and_key =
					load_cert_and_key(downstream.certificate, downstream.key)
						.await
						.expect("failed to load certificate or private key");
				let socket_addr = format!("{}:{}", downstream.listen, downstream.port);
				let tcp_listener = TcpListener::bind(&socket_addr)
					.await
					.with_context(|| format!("failed to bind tcp socket {}", socket_addr))
					.unwrap_or_else(|err| panic!("{err:?}"));
				server
					.register_https_listener(
						tcp_listener,
						Duration::from_millis(downstream.timeout_ms),
						cert_and_key,
						downstream.dns_hostname
					)
					.expect("failed to register tls downstream")
			},
			DownstreamConfig::Quic(downstream) => {
				let cert_and_key =
					load_cert_and_key(downstream.certificate, downstream.key)
						.await
						.expect("failed to load certificate or private key");
				let socket_addr = format!("{}:{}", downstream.listen, downstream.port);
				let udp_socket = UdpSocket::bind(&socket_addr)
					.await
					.with_context(|| format!("failed to bind tcp socket {}", socket_addr))
					.unwrap_or_else(|err| panic!("{err:?}"));
				server
					.register_quic_listener(
						udp_socket,
						Duration::from_millis(downstream.timeout_ms),
						cert_and_key,
						downstream.dns_hostname
					)
					.expect("failed to register tls downstream")
			}
		}
	}
	let blocklist_len_move = blocklist_len.clone();
	tokio::spawn(async move {
		let blocklist = blocklist;
		let lists = config.blocklist.lists;
		loop {
			blocklist
				.update(&lists, false, blocklist_len_move.clone())
				.await;
			sleep(Duration::from_secs(7200)).await; //2h
		}
	});
	info!("🚀 start dns server");
	let res = try_join!(
		async {
			server
				.block_until_done()
				.await
				.with_context(|| "failed to start dns server")
		},
		async {
			api::init(config.api, stats, blocklist_len.clone())
				.await
				.with_context(|| "failed to start api/web server")
		}
	);
	res.unwrap();
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
	upstream: ForwardConfig,
	downstream: Vec<DownstreamConfig>,
	blocklist: BlockConfig,
	api: Option<api::Config>
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
	Udp(UdpConfig),
	Tls(TlsConfig),
	Https(HttpsAndQuicConfig),
	Quic(HttpsAndQuicConfig)
}

fn default_timeout() -> u64 {
	3000
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UdpConfig {
	port: u16,
	listen: String
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsConfig {
	port: u16,
	listen: String,
	certificate: PathBuf,
	key: PathBuf,
	#[serde(default = "default_timeout")]
	timeout_ms: u64
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpsAndQuicConfig {
	port: u16,
	listen: String,
	certificate: PathBuf,
	key: PathBuf,
	#[serde(default = "default_timeout")]
	timeout_ms: u64,
	dns_hostname: String
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
