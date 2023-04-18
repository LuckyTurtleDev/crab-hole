use async_trait::async_trait;
use rustls::{OwnedTrustAnchor, RootCertStore};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use trust_dns_server::{
	client::client::AsyncDnssecClient,
	proto::{
		https::{HttpsClientStream, HttpsClientStreamBuilder},
		quic::QuicClientStream
	},
	resolver::config::TlsClientConfig,
	server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
	ServerFuture as Server
};
use webpki::TrustAnchor;
use webpki_roots::TLS_SERVER_ROOTS;

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
	// convert the webpki root certificates to rustls format
	let root_store = RootCertStore {
		roots: TLS_SERVER_ROOTS
			.0
			.iter()
			.map(
				|TrustAnchor {
				     subject,
				     spki,
				     name_constraints
				 }| {
					OwnedTrustAnchor::from_subject_spki_name_constraints(
						*subject,
						*spki,
						*name_constraints
					)
				}
			)
			.collect()
	};

	// create a tls config for the upstream client
	let tls_config = rustls::ClientConfig::builder()
		.with_safe_defaults()
		.with_root_certificates(root_store)
		.with_no_client_auth();

	// create the upstream client
	let mut client_stream_builder = QuicClientStream::builder();
	client_stream_builder.crypto_config(tls_config);
	let client_stream = client_stream_builder.build(
		SocketAddr::new(IpAddr::V4(Ipv4Addr::new(94, 140, 14, 140)), 853),
		"unfiltered.adguard-dns.com".into()
	);
	let (client, bg) = AsyncDnssecClient::builder(client_stream)
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
	async_main();
}
