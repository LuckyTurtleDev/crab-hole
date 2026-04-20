use std::{
	net::{IpAddr, SocketAddr},
	sync::Arc
};

use hickory_resolver::config::{
	ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverOpts
};
use hickory_server::store::forwarder::ForwardConfig;
use serde::Deserialize;

/// Configuration for forwarder zones
#[derive(Clone, Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct OurForwardConfig {
	/// upstream name_server configurations
	pub name_servers: Vec<UpstreamServer>,
	/// Resolver options
	pub options: Option<ResolverOpts>
}

impl From<OurForwardConfig> for ForwardConfig {
	fn from(value: OurForwardConfig) -> Self {
		ForwardConfig {
			name_servers: value.name_servers.into_iter().map(|f| f.into()).collect(),
			options: value.options
		}
	}
}

#[derive(Deserialize, Debug, Clone)]
pub enum UpstreamServer {
	Udp(UpstreamCommon),
	Tcp(UpstreamCommon),
	Tls(UpstreamTlsQuick),
	Quick(UpstreamTlsQuick),
	Https(UpstreamHttps),
	H3(UpstreamH3)
}

/// settings which have every protocoll.
/// I would to like serde `flatten` here, but it is not compatible with serde `deny_unknown_fields`.
/// It is also used for TCP and UDP since they have no addiotional configuration.

#[derive(Deserialize, Debug, Clone)]
pub struct UpstreamCommon {
	pub trust_negative_responses: bool,
	pub ip: IpAddr,
	pub port: Option<u16>,
	pub bind_addr: Option<SocketAddr>
}

#[derive(Deserialize, Debug, Clone)]
pub struct UpstreamTlsQuick {
	pub trust_negative_responses: bool,
	pub ip: IpAddr,
	pub port: Option<u16>,
	pub bind_addr: Option<SocketAddr>,
	//custom
	pub server_name: Arc<str>
}

#[derive(Deserialize, Debug, Clone)]
pub struct UpstreamHttps {
	pub trust_negative_responses: bool,
	pub ip: IpAddr,
	pub port: Option<u16>,
	pub bind_addr: Option<SocketAddr>,
	//custom
	pub server_name: Arc<str>,
	pub path: Arc<str>
}

#[derive(Deserialize, Debug, Clone)]
pub struct UpstreamH3 {
	pub trust_negative_responses: bool,
	pub ip: IpAddr,
	pub port: Option<u16>,
	pub bind_addr: Option<SocketAddr>,
	//custom
	pub server_name: Arc<str>,
	pub path: Arc<str>,
	pub disable_grease: bool
}

impl From<&UpstreamServer> for UpstreamCommon {
	fn from(value: &UpstreamServer) -> Self {
		// should i write a macro for this?
		match value {
			UpstreamServer::Udp(value) | UpstreamServer::Tcp(value) => value.clone(),
			UpstreamServer::Tls(value) | UpstreamServer::Quick(value) => UpstreamCommon {
				trust_negative_responses: value.trust_negative_responses,
				ip: value.ip,
				port: value.port,
				bind_addr: value.bind_addr
			},
			UpstreamServer::Https(value) => UpstreamCommon {
				trust_negative_responses: value.trust_negative_responses,
				ip: value.ip,
				port: value.port,
				bind_addr: value.bind_addr
			},
			UpstreamServer::H3(value) => UpstreamCommon {
				trust_negative_responses: value.trust_negative_responses,
				ip: value.ip,
				port: value.port,
				bind_addr: value.bind_addr
			}
		}
	}
}

impl From<UpstreamServer> for ProtocolConfig {
	fn from(value: UpstreamServer) -> Self {
		match value {
			UpstreamServer::Udp(_) => ProtocolConfig::Udp,
			UpstreamServer::Tcp(_) => ProtocolConfig::Tcp,
			UpstreamServer::Tls(value) => ProtocolConfig::Tls {
				server_name: value.server_name
			},
			UpstreamServer::Quick(value) => ProtocolConfig::Quic {
				server_name: value.server_name
			},
			UpstreamServer::Https(value) => ProtocolConfig::Https {
				server_name: value.server_name,
				path: value.path
			},
			UpstreamServer::H3(value) => ProtocolConfig::H3 {
				server_name: value.server_name,
				path: value.path,
				disable_grease: value.disable_grease
			}
		}
	}
}

// convert our own config to the one used by hickory dns
impl From<UpstreamServer> for NameServerConfig {
	fn from(val: UpstreamServer) -> Self {
		let common = UpstreamCommon::from(&val);
		let mut connection = ConnectionConfig::new(val.into());
		connection.bind_addr = common.bind_addr;
		if let Some(port) = common.port {
			// if not set this is the protocoll default port
			connection.port = port;
		}
		NameServerConfig::new(common.ip, common.trust_negative_responses, vec![])
	}
}
