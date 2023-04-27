use async_trait::async_trait;
use log::{debug, info};
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use std::{fs, io::Write, iter, sync::Arc, time::Duration};
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

mod trie;

mod blocklist;
use blocklist::BlockList;

static CLIENT: Lazy<Client> = Lazy::new(|| Client::new());

struct Handler {
	catalog: Catalog,
	blocklist: Arc<BlockList>
}

impl Handler {
	async fn new(config: &ForwardConfig, adlist: &Vec<Url>) -> Self {
		let zone_name = Name::root();
		let authority = ForwardAuthority::try_from_config(
			zone_name.clone(),
			ZoneType::Forward,
			config
		)
		.expect("Failed to create forwarder");

		let mut catalog = Catalog::new();
		catalog.upsert(zone_name.into(), Box::new(Arc::new(authority)));

		let blocklist = BlockList::new();
		blocklist.update(adlist, true).await;

		Self {
			catalog,
			blocklist: Arc::new(blocklist)
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
			.contains(&lower_query.to_string(), true)
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
				.unwrap(); //when does this fail?
		} else {
			debug!("{lower_query:?}");
		}

		self.catalog.handle_request(request, response_handler).await
	}
}

#[tokio::main]
async fn async_main(config: Config) {
	let udp_socket = UdpSocket::bind("[::]:8080")
		.await
		.expect("failed to bind udp socket");
	let handler = Handler::new(&config.upstream, &config.blocklist.lists).await;
	let blocklist = handler.blocklist.clone();
	tokio::spawn(async {
		let blocklist = blocklist;
		let lists = config.blocklist.lists;
		loop {
			blocklist.update(&lists, false).await;
			sleep(Duration::from_secs(7200)).await; //2h
		}
	});
	let mut server = Server::new(handler);
	server.register_socket(udp_socket);
	info!("🚀 start dns server");
	server
		.block_until_done()
		.await
		.expect("failed to run dns server");
}

#[derive(Deserialize)]
struct Config {
	upstream: ForwardConfig,
	blocklist: BlockConfig
}

#[derive(Deserialize)]
struct BlockConfig {
	lists: Vec<Url>,
	inculde_subdomains: bool
}

fn main() {
	let config = fs::read("config.toml").expect("Failed to read config");
	let config: Config = toml::from_slice(&config).expect("Failed to deserialize config");
	my_env_logger_style::just_log();
	async_main(config);
}
