use async_trait::async_trait;
use client::{proto::iocompat::AsyncIoTokioAsStd, tcp::TcpClientStream};
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket};
use trust_dns_server::{
	client,
	client::client::AsyncClient,
	server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
	ServerFuture as Server
};

struct Handler {
	client: AsyncClient
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
	let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(
		([8, 8, 8, 8], 53).into()
	);
	let client = AsyncClient::new(stream, sender, None);
	// await the connection to be established
	let (client, bg) = client
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
