#![warn(rust_2018_idioms, unreachable_pub)]
#![forbid(elided_lifetimes_in_paths)]
#![cfg_attr(not(all(test, nightly)), forbid(unsafe_code))]
#![cfg_attr(all(test, nightly), feature(test))]

#[cfg(all(test, nightly))]
extern crate test;

#[cfg(all(test, nightly))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod api;
mod logger;
mod parser;

use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use directories::ProjectDirs;
use hickory_proto::{
	op::{header::Header, response_code::ResponseCode},
	rr::Name
};
use hickory_server::{
	authority::{Catalog, MessageResponseBuilder},
	server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
	store::forwarder::{ForwardAuthority, ForwardConfig},
	ServerFuture as Server
};
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use reqwest::Client;
use rustls::{
	crypto::CryptoProvider,
	server::ResolvesServerCert,
	sign::{CertifiedKey, SingleCertAndKey}
};
use serde::Deserialize;
use std::{
	env::var,
	fs::{self, File},
	io::BufReader,
	iter,
	path::{Path, PathBuf},
	sync::{
		atomic::{AtomicU64, Ordering},
		Arc
	},
	time::Duration,
	vec
};
use time::OffsetDateTime;
use tokio::{
	fs::{read_to_string, write},
	net::{TcpListener, UdpSocket},
	time::sleep,
	try_join
};
use url::Url;

use clap::{Parser, Subcommand};

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

use crate::logger::init_logger;

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
	async fn new(config: &Config, stats: Stats) -> Self {
		let zone_name = Name::root();
		let authority = ForwardAuthority::builder_tokio(config.upstream.clone())
			.build()
			.expect("Failed to create forwarder");

		let mut catalog = Catalog::new();
		catalog.upsert(zone_name.into(), vec![Arc::new(authority)]);

		let blocklist = BlockList::new();
		blocklist
			.update(&config.blocklist.lists, &config.blocklist.allow_list, true)
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
		let Ok(lower_query) = request.request_info().map(|v| v.query) else {
			warn!("Multiple questions in one dns query is currently unsupported");
			return response_handler
				.send_response(
					MessageResponseBuilder::from_message_request(request)
						.error_msg(request.header(), ResponseCode::ServFail)
				)
				.await
				.unwrap_or_else(|_| {
					let mut header = Header::new();
					header.set_response_code(ResponseCode::ServFail);
					header.into()
				});
		};
		self.stats.total_request.fetch_add(1, Ordering::Relaxed);
		if self
			.blocklist
			.blocked(
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
		}

		debug!("{lower_query:?}");
		self.catalog.handle_request(request, response_handler).await
	}
}

fn reader_for(path: &Path) -> anyhow::Result<BufReader<File>> {
	Ok(BufReader::new(File::open(path).with_context(|| {
		format!("Failed to open {}", path.display())
	})?))
}

fn load_cert_and_key(
	cert_path: &Path,
	key_path: &Path
) -> anyhow::Result<Arc<impl ResolvesServerCert>> {
	let certificates = rustls_pemfile::certs(&mut reader_for(cert_path)?)
		.filter_map(|cert| {
			if let Err(err) = &cert {
				warn!("Failed to parse {}: {}", cert_path.display(), err)
			}
			cert.ok()
		})
		.collect::<Vec<_>>();
	if certificates.is_empty() {
		bail!("No x509 certificate found in {}", cert_path.display());
	}
	let key = rustls_pemfile::private_key(&mut reader_for(key_path)?)
		.with_context(|| format!("Failed to parse {}", key_path.display()))?
		.ok_or_else(|| {
			anyhow!(
				"No private RSA/PKCS8/ECKey key found in {}",
				key_path.display()
			)
		})?;

	let certified_key = CertifiedKey::from_der(
		certificates,
		key,
		CryptoProvider::get_default()
			.expect("CryptoProvider default should have been registered in main!")
	)?;
	Ok(Arc::new(SingleCertAndKey::from(certified_key)))
}

/// Load a text file from url and cache it.
/// If restore_from_cache is true, only the cache is used.
/// The first return value is the file content.
/// It will be None if an error has occured.
/// The second value is a combined error message.
async fn get_file(
	url: &Url,
	restore_from_cache: bool,
	cache_file: bool
) -> (Option<String>, String) {
	if url.scheme() == "file" {
		let path = url.path();
		info!("load file {path:?}");
		let raw_list = read_to_string(&path).await;
		match raw_list.with_context(|| format!("can not open file {path:?}")) {
			Ok(value) => (Some(value), String::new()),
			Err(err) => {
				error!("{err}");
				(None, format!("{err}"))
			}
		}
	} else {
		let mut all_errors = String::new();
		let mut path = url.path().to_owned().replace('/', "-");
		if !path.is_empty() {
			path.remove(0);
		}
		if let Some(query) = url.query() {
			path += "--";
			path += query;
		}
		let path = PathBuf::from(&*LIST_DIR).join(path);
		let raw_list = if !path.exists() || !restore_from_cache {
			info!("downloading {url}");
			let resp: anyhow::Result<String> = async {
				//try block
				let resp = CLIENT
					.get(url.to_owned())
					.send()
					.await?
					.error_for_status()?
					.text()
					.await?;
				if cache_file {
					if let Err(err) = write(&path, &resp)
						.await
						.with_context(|| format!("failed to save to {path:?}"))
					{
						error!("{err:?}");
					}
				}
				Ok(resp)
			}
			.await;
			match resp.with_context(|| format!("error downloading {url}")) {
				Ok(value) => Some(value),
				Err(err) => {
					error!("{err:?}");
					all_errors += &format!("{err}\n");
					None
				}
			}
		} else {
			None
		};
		match raw_list {
			Some(value) => (Some(value), all_errors),
			None => {
				if path.exists() {
					info!("restore from cache {url}");
					all_errors += "restore from cache\n";
					match read_to_string(&path)
						.await
						.with_context(|| format!("error reading file {path:?}"))
					{
						Ok(value) => (Some(value), all_errors),
						Err(err) => {
							error!("{err:?}");
							all_errors += &format!("{err}\n");
							(None, all_errors)
						}
					}
				} else {
					(None, all_errors)
				}
			},
		}
	}
}

#[tokio::main]
async fn async_main(config: Config) {
	let stats = Stats::default();
	let handler = Handler::new(&config, stats.clone()).await;
	let blocklist = handler.blocklist.clone();
	let mut server = Server::new(handler);
	for downstream in config.downstream {
		info!("add downstream {:?}", downstream);
		match downstream {
			DownstreamConfig::Udp(downstream) => {
				let socket_addr = format!("{}:{}", downstream.listen, downstream.port);
				let udp_socket = UdpSocket::bind(&socket_addr)
					.await
					.with_context(|| format!("failed to bind udp socket {socket_addr}"))
					.unwrap_or_else(|err| panic!("{err:?}"));
				server.register_socket(udp_socket);
			},
			DownstreamConfig::Tls(downstream) => {
				let cert_and_key =
					load_cert_and_key(&downstream.certificate, &downstream.key)
						.expect("failed to load certificate or private key");
				let socket_addr = format!("{}:{}", downstream.listen, downstream.port);
				let tcp_listener = TcpListener::bind(&socket_addr)
					.await
					.with_context(|| format!("failed to bind tcp socket {socket_addr}"))
					.unwrap_or_else(|err| panic!("{err:?}"));
				server
					.register_tls_listener(
						tcp_listener,
						Duration::from_millis(downstream.timeout_ms),
						cert_and_key
					)
					.expect("failed to register tls downstream");
			},
			DownstreamConfig::Https(downstream) => {
				let cert_and_key =
					load_cert_and_key(&downstream.certificate, &downstream.key)
						.expect("failed to load certificate or private key");
				let socket_addr = format!("{}:{}", downstream.listen, downstream.port);
				let tcp_listener =
					TcpListener::bind(&socket_addr).await.unwrap_or_else(|err| {
						panic!("failed to bind tcp socket {socket_addr}: {err:?}")
					});
				server
					.register_https_listener(
						tcp_listener,
						Duration::from_millis(downstream.timeout_ms),
						cert_and_key,
						downstream.dns_hostname,
						downstream.http_endpoint
					)
					.expect("failed to register https downstream");
			},
			DownstreamConfig::H3(downstream) => {
				let cert_and_key =
					load_cert_and_key(&downstream.certificate, &downstream.key)
						.expect("failed to load certificate or private key");
				let socket_addr = format!("{}:{}", downstream.listen, downstream.port);
				let udp_socket =
					UdpSocket::bind(&socket_addr).await.unwrap_or_else(|err| {
						panic!("failed to bind udp socket {socket_addr}: {err:?}")
					});
				server
					.register_h3_listener(
						udp_socket,
						Duration::from_millis(downstream.timeout_ms),
						cert_and_key,
						downstream.dns_hostname
					)
					.expect("failed to register h3 downstream")
			},
			DownstreamConfig::Quic(downstream) => {
				let cert_and_key =
					load_cert_and_key(&downstream.certificate, &downstream.key)
						.expect("failed to load certificate or private key");
				let socket_addr = format!("{}:{}", downstream.listen, downstream.port);
				let udp_socket =
					UdpSocket::bind(&socket_addr).await.unwrap_or_else(|err| {
						panic!("failed to bind udp socket {socket_addr}: {err:?}")
					});
				server
					.register_quic_listener(
						udp_socket,
						Duration::from_millis(downstream.timeout_ms),
						cert_and_key,
						downstream.dns_hostname
					)
					.expect("failed to register quic downstream");
			}
		}
	}
	let blocklist_move = blocklist.clone();
	tokio::spawn(async move {
		let blocklist = blocklist_move;
		loop {
			blocklist
				.update(&config.blocklist.lists, &config.blocklist.allow_list, false)
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
			api::init(config.api, stats, blocklist)
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
	#[serde(default)]
	blocklist: BlockConfig,
	api: Option<api::Config>
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockConfig {
	lists: Vec<Url>,
	include_subdomains: bool,
	#[serde(default)]
	allow_list: Vec<Url>
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "lowercase", tag = "protocol")]
enum DownstreamConfig {
	Udp(UdpConfig),
	Tls(TlsConfig),
	Https(HttpsConfig),
	H3(QuicConfig),
	Quic(QuicConfig)
}

fn default_timeout() -> u64 {
	3000
}

fn default_http_endpoint() -> String {
	"/dns-query".into()
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
struct QuicConfig {
	port: u16,
	listen: String,
	certificate: PathBuf,
	key: PathBuf,
	#[serde(default = "default_timeout")]
	timeout_ms: u64,
	dns_hostname: Option<String>
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpsConfig {
	port: u16,
	listen: String,
	certificate: PathBuf,
	key: PathBuf,
	#[serde(default = "default_timeout")]
	timeout_ms: u64,
	dns_hostname: Option<String>,
	#[serde(default = "default_http_endpoint")]
	http_endpoint: String
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
	#[command(subcommand)]
	command: Option<Commands>
}

#[derive(Subcommand)]
enum Commands {
	ValidateConfig,
	ValidateLists
}

fn main() {
	init_logger();
	info!("🦀 {CARGO_PKG_NAME}  v{CARGO_PKG_VERSION} 🦀");
	Lazy::force(&CONFIG_PATH);
	Lazy::force(&LIST_DIR);

	#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
	let key_provider = rustls::crypto::aws_lc_rs::default_provider();
	#[cfg(feature = "ring")]
	let key_provider = rustls::crypto::ring::default_provider();
	CryptoProvider::install_default(key_provider).unwrap_or_else(|_| {
		error!("Failed to install default crypto provider.");
		std::process::exit(1);
	});

	let cli = Cli::parse();

	let config = match load_config() {
		Ok(config) => {
			debug!("{:#?}", config);
			config
		},
		Err(err) => {
			error!("{err}");
			error!("{}", err.root_cause());
			std::process::exit(1);
		}
	};

	match cli.command {
		Some(command) => match command {
			Commands::ValidateConfig => info!("Config is valid"),
			Commands::ValidateLists => {
				if !async_validate_lists(config) {
					error!("Config validation failed!");
					std::process::exit(1);
				} else {
					info!("All lists are valid");
				}
			},
		},
		None => async_main(config)
	}
}

fn load_config() -> Result<Config, anyhow::Error> {
	info!("load config from {:?}", &*CONFIG_PATH);
	let config = fs::read(&*CONFIG_PATH)
		.with_context(|| format!("Failed to read {:?}", CONFIG_PATH.as_path()))
		.unwrap_or_else(|err| panic!("{err:?}"));
	toml::from_slice(&config).with_context(|| "Failed to deserialize config")
}

#[tokio::main]
async fn async_validate_lists(config: Config) -> bool {
	let mut validated = true;
	//Allow List
	for list in config.blocklist.allow_list {
		let (file_content, error_message) = get_file(&list, false, false).await;
		if let Some(content) = file_content {
			if let Err(err) = parser::Blocklist::parse(list.path(), &content) {
				error!("{}", err.msg());
				validated = false;
			}
		} else {
			error!("{error_message}");
			validated = false;
		}
	}

	//Block List
	for list in config.blocklist.lists {
		let (file_content, error_message) = get_file(&list, false, false).await;
		if let Some(content) = file_content {
			if let Err(err) = parser::Blocklist::parse(list.path(), &content) {
				error!("{}", err.msg());
				validated = false;
			}
		} else {
			error!("{error_message}");
			validated = false;
		}
	}

	validated
}

#[cfg(test)]
mod tests {
	use std::{
		fmt::Display,
		io::BufRead,
		mem::take,
		process::Command,
		thread::{self, sleep},
		time::Duration
	};

	use crate::async_main;

	#[track_caller]
	fn unwrap_dis<T, E: Display>(res: Result<T, E>) -> T {
		match res {
			Ok(value) => value,
			Err(err) => panic!("{err}")
		}
	}

	#[test]
	fn config_file() {
		let config = include_bytes!("../config.toml");
		let _: super::Config = toml::from_slice(config).unwrap();
	}
	#[test]
	fn example_config_file() {
		let config = include_bytes!("../example-config.toml");
		let _: super::Config = unwrap_dis(toml::from_slice(config));
	}

	#[test]
	/// test all config files at the readme.me,
	/// which have a comment `<!-- test_config -->` at the previous line
	fn readme_config() {
		#[derive(Debug, PartialEq)]
		enum PraseState {
			Nothing,
			FoundComment,
			ConfigFile
		}

		let readme = include_bytes!("../README.md");
		let mut prase_state = PraseState::Nothing;
		let mut config_files: Vec<String> = Default::default();
		let mut current_config_files: String = Default::default();
		for line in readme.lines() {
			let line = line.unwrap();
			let line = line.trim();
			if line == "<!-- test_config -->" {
				if prase_state != PraseState::Nothing {
					panic!("prase readme error:\nfound test comment while not in state PraseState::Nothing\nIs in state {prase_state:?}");
				}
				prase_state = PraseState::FoundComment;
				continue;
			}
			if line.starts_with("```") && prase_state == PraseState::FoundComment {
				prase_state = PraseState::ConfigFile;
				continue;
			}
			if line.starts_with("```") && prase_state == PraseState::ConfigFile {
				prase_state = PraseState::Nothing;
				config_files.push(take(&mut current_config_files));
				continue;
			}
			if prase_state == PraseState::ConfigFile {
				current_config_files.push_str(line);
				current_config_files.push('\n');
			}
		}
		if prase_state != PraseState::Nothing {
			panic!("prase readme error:\nUnexpected end of file. Praser is still in state {prase_state:?}");
		}
		if config_files.is_empty() {
			panic!("no config files found at README.md");
		}
		println!("found {} configs in readme", config_files.len());
		for (i, config) in config_files.iter().enumerate() {
			println!("\n\nprase {}. config", i + 1);
			println!("prase:\n{config}");
			let _: super::Config = unwrap_dis(toml::from_str(config));
		}
	}

	#[test]
	#[ignore]
	fn run() {
		let config = include_bytes!("../config.toml");
		let config: super::Config = toml::from_slice(config).unwrap();
		let _ = thread::spawn(|| async_main(config));
		let duration = Duration::from_secs(6);
		sleep(duration);
		assert!(Command::new("kdig")
			.args(["example.com", "@localhost:8080"])
			.status()
			.unwrap()
			.success());
	}
}
