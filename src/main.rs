use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use trust_dns_server::{
	client::client::AsyncDnssecClient,
	proto::quic::QuicClientStream,
	server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
	ServerFuture as Server
};

struct Handler {
	client: AsyncDnssecClient
}

#[async_trait]
impl RequestHandler for Handler {
	async fn handle_request<R: ResponseHandler>(
		&self,
		request: &Request,
		response_handler: R
	) -> ResponseInfo {
		let query = request.request_info().query;
		println!("{query:?}");
		unimplemented!()
	}
}

#[tokio::main]
async fn async_main() {
	let (client, bg) = AsyncDnssecClient::builder(QuicClientStream::builder().build(
		SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
		"1dot1dot1dot1.cloudflare-dns.com".into()
	))
	.build()
	.await
	.expect("connection to upstream dns server failed");
	// make sure to run the background task
	tokio::spawn(bg);

	let upd_socket = UdpSocket::bind("0.0.0.0:8080")
		.await
		.expect("failed to bind udp socket");
	let handler = Handler { client };
	let mut server = Server::new(handler);
	server.register_socket(upd_socket);
	server
		.block_until_done()
		.await
		.expect("failed to run dns server");
}

fn main() {
	println!("Hello, world!");
	async_main();
}
