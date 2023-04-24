use async_trait::async_trait;
use serde::Deserialize;
use std::{fs, sync::Arc};
use tokio::net::UdpSocket;
use trust_dns_proto::rr::Name;
use trust_dns_server::{
	authority::{Catalog, ZoneType},
	server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
	store::forwarder::{ForwardAuthority, ForwardConfig},
	ServerFuture as Server
};

mod trie;

struct Handler {
	catalog: Catalog
}

impl Handler {
	fn new(config: &ForwardConfig) -> Self {
		let zone_name = Name::root();
		let authority = ForwardAuthority::try_from_config(
			zone_name.clone(),
			ZoneType::Forward,
			config
		)
		.expect("Failed to create forwarder");

		let mut catalog = Catalog::new();
		catalog.upsert(zone_name.into(), Box::new(Arc::new(authority)));
		Self { catalog }
	}
}

#[async_trait]
impl RequestHandler for Handler {
	async fn handle_request<R: ResponseHandler>(
		&self,
		request: &Request,
		response_handle: R
	) -> ResponseInfo {
		let lower_query = request.request_info().query;
		println!("{lower_query:?}");

		self.catalog.handle_request(request, response_handle).await
	}
}

#[tokio::main]
async fn async_main(config: Config) {
	let udp_socket = UdpSocket::bind("[::]:8080")
		.await
		.expect("failed to bind udp socket");
	let handler = Handler::new(&config.upstream);
	let mut server = Server::new(handler);
	server.register_socket(udp_socket);
	server
		.block_until_done()
		.await
		.expect("failed to run dns server");
}

#[derive(Deserialize)]
struct Config {
	upstream: ForwardConfig
}

fn main() {
	let config = fs::read("config.toml").expect("Failed to read config");
	let config: Config = toml::from_slice(&config).expect("Failed to deserialize config");

	async_main(config);
}
