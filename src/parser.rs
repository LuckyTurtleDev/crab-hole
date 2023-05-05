use chumsky::prelude::*;
use std::net::IpAddr;

type ParserError = Simple<char>;

/// A domain. Never contains a trailing punct.
pub(crate) struct Domain(pub(crate) String);

impl Domain {
	fn parser() -> impl Parser<char, Self, Error = ParserError> {
		let ident = filter(|c: &char| {
			*c != '#' && *c != ':' && (*c == '-' || c.is_alphanumeric())
		})
		.repeated()
		.at_least(1);
		ident
			.then(just(".").then(ident).repeated())
			.then_ignore(just(".").ignored().or(empty()))
			.map(|(first, tail)| {
				let mut domain: String = first.into_iter().collect();
				for (punct, part) in tail {
					domain += punct;
					domain.extend(part.into_iter());
				}
				Self(domain)
			})
	}
}

pub(crate) struct Blocklist {
	pub(crate) entries: Vec<Line>
}

pub(crate) struct ParseError;

pub(crate) type ParseResult<T> = Result<T, ParseError>;

impl Blocklist {
	pub(crate) fn parse(input: &str) -> ParseResult<Self> {
		Self::parser().parse(input).map_err(|_| ParseError)
	}

	fn parser() -> impl Parser<char, Self, Error = ParserError> {
		Line::parser()
			.then_ignore(one_of(['\r', '\n']).repeated().at_least(1))
			.repeated()
			.then(Line::parser())
			.then_ignore(one_of(['\r', '\n']).repeated())
			.then_ignore(end())
			.map(|(mut entries, last)| {
				entries.push(last);
				Self {
					entries: entries.into_iter().flatten().collect()
				}
			})
	}
}

pub(crate) enum Line {
	Domain(Domain),
	IpDomain(IpAddr, Domain)
}

impl Line {
	fn parser() -> impl Parser<char, Option<Self>, Error = ParserError> {
		choice((
			// empty line
			one_of([' ', '\t']).repeated().map(|_| None),
			// full line comment
			just("#")
				.then(none_of(['\r', '\n']).repeated())
				.map(|_| None),
			// [<ip>] <domain>
			choice((
				empty().map(|_| None),
				filter(|c: &char| c.is_ascii_hexdigit() || *c == '.' || *c == ':')
					.repeated()
					.at_least(2)
					.map(|ip| Some(ip.into_iter().collect::<String>().parse().unwrap()))
					.then_ignore(one_of([' ', '\t']).repeated().at_least(1))
			))
			.then(Domain::parser())
			.map(|(addr, domain)| {
				Some(match addr {
					None => Self::Domain(domain),
					Some(addr) => Self::IpDomain(addr, domain)
				})
			})
		))
	}
}
