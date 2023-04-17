use client::{proto::iocompat::AsyncIoTokioAsStd, tcp::TcpClientStream};
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket};
use trust_dns_server::{
	client, client::client::AsyncClient, server::RequestHandler, ServerFuture as Server
};

struct Handler {
	client: AsyncClient
}

impl RequestHandler for Handler {
	fn handle_request<'life0, 'life1, 'async_trait, R>(
		&'life0 self,
		request: &'life1 trust_dns_server::server::Request,
		response_handle: R
	) -> core::pin::Pin<
		Box<
			dyn core::future::Future<Output = trust_dns_server::server::ResponseInfo>
				+ core::marker::Send
				+ 'async_trait
		>
	>
	where
		R: 'async_trait + trust_dns_server::server::ResponseHandler,
		'life0: 'async_trait,
		'life1: 'async_trait,
		Self: 'async_trait
	{
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
