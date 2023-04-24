use chumsky::prelude::*;
use std::net::Ipv4Addr;

pub(crate) struct Domain(pub(crate) Vec<u8>);

impl Domain {
	fn parser() -> impl Parser<u8, Self> {
		let ident = filter(|c: &u8| *c >= 0x21 && *c <= 0x7F).repeated();
		ident.then(one_of([b'.']).then(ident).repeated()).then_ignore(one_of([b'.']).or(empty()))
	}
}

pub(crate) struct Blocklist {
	pub domains: Vec<Vec<u8>>
}

pub(crate) struct ParseError;

pub(crate) type ParseResult<T> = Result<T, ParseError>;

impl Blocklist {
	pub(crate) fn parse(bytes: Vec<u8>) -> ParseResult<Self> {
		unimplemented!()
	}
}

enum Line {
	Domain(Vec<u8>),
	IpDomain(Ipv4Addr, Vec<u8>)
}

impl Line {
	fn parser() -> impl Parser<u8, Self> {
		let ident = filter(|c: &u8| *c >= 0x21 && *c <= 0x7F).repeated();
		let domain = ident.then(one_of([b'.']).then(ident))

		unimplemented!()
	}
}
