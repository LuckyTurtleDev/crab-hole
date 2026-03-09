use ariadne::{Color, Label, Report, ReportKind, Source};
use chumsky::prelude::*;
use std::net::IpAddr;

type Extra<'a> = extra::Err<Rich<'a, char>>;

fn ident<'a>() -> impl Parser<'a, &'a str, &'a str, Extra<'a>> {
	any()
		.filter(|c: &char| *c != '#' && *c != ':' && *c != '.' && !c.is_whitespace())
		.repeated()
		.at_least(1)
		.to_slice()
}

/// A domain. Never contains a trailing punct.
pub(crate) struct Domain(pub(crate) String);

impl Domain {
	fn parser<'a>() -> impl Parser<'a, &'a str, Self, Extra<'a>> {
		ident()
			.then(just(".").then(ident()).repeated().to_slice())
			.then_ignore(just(".").ignored().or(empty()))
			.map(|(first, tail)| Self(format!("{first}{tail}")))
	}
}

pub(crate) struct Blocklist {
	pub(crate) entries: Vec<Line>
}

pub(crate) struct ParseError<'a> {
	input: &'a str,
	path_str: &'a str,
	err: Vec<Rich<'a, char>>
}

fn report_err(buf: &str, path_str: &str, err: Vec<Rich<'_, char>>) -> String {
	let mut output = Vec::<u8>::new();
	for e in err {
		Report::build(ReportKind::Error, (path_str, e.span().into_range()))
			.with_config(ariadne::Config::new().with_index_type(ariadne::IndexType::Byte))
			.with_message(e.to_string())
			.with_label(
				Label::new((path_str, e.span().into_range()))
					.with_message(e.reason().to_string())
					.with_color(Color::Red)
			)
			.with_labels(e.contexts().map(|(label, span)| {
				Label::new((path_str, span.into_range()))
					.with_message(format!("while parsing this {label}"))
					.with_color(Color::Yellow)
			}))
			.finish()
			.write((path_str, Source::from(buf)), &mut output)
			.unwrap();
		output.push(b'\n');
	}
	String::from_utf8_lossy(&output).into_owned()
}

impl ParseError<'_> {
	pub(crate) fn msg(self) -> String {
		report_err(self.input, self.path_str, self.err)
	}
}

pub(crate) type ParseResult<'a, T> = Result<T, ParseError<'a>>;

impl Blocklist {
	pub(crate) fn parse<'a>(path: &'a str, input: &'a str) -> ParseResult<'a, Self> {
		let parser = Self::parser();
		let result = parser.parse(input);
		if result.has_errors() {
			return Err(ParseError {
				input,
				path_str: path,
				err: result.into_errors()
			});
		}
		Ok(result.into_output().unwrap())
	}

	fn parser<'a>() -> impl Parser<'a, &'a str, Self, Extra<'a>> {
		Line::parser()
			.then_ignore(one_of(['\r', '\n']).repeated().at_least(1))
			.repeated()
			.collect::<Vec<_>>()
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

struct Comment;

impl Comment {
	fn parser<'a>() -> impl Parser<'a, &'a str, Self, Extra<'a>> {
		any()
			.filter(|c: &char| c.is_whitespace())
			.repeated()
			.ignore_then(just("#"))
			.ignore_then(none_of(['\r', '\n']).repeated())
			.map(|_| Self)
	}
}

#[allow(dead_code)] // these are results from parsing, the types are relevant
pub(crate) enum Line {
	Domain(Domain),
	IpDomain(IpAddr, Domain),
	IpIfaceDomain(IpAddr, String, Domain)
}

impl Line {
	pub(crate) fn domain(&self) -> &Domain {
		match self {
			Self::Domain(domain)
			| Self::IpDomain(_, domain)
			| Self::IpIfaceDomain(_, _, domain) => domain
		}
	}

	fn parser<'a>() -> impl Parser<'a, &'a str, Option<Self>, Extra<'a>> {
		choice((
			// [<ip>][%<iface>] <domain>
			choice((
				any()
					.filter(|c: &char| c.is_ascii_hexdigit() || *c == '.' || *c == ':')
					.repeated()
					.at_least(2)
					.to_slice()
					.try_map(|ip: &str, span| {
						Ok(Some(ip.parse().map_err(|err| Rich::custom(span, err))?))
					})
					.then(choice((
						just("%")
							.ignore_then(
								any()
									.filter(|c: &char| c.is_ascii_alphanumeric())
									.repeated()
									.to_slice()
							)
							.map(|iface: &str| Some(iface.into())),
						empty().map(|_| None)
					)))
					.then_ignore(one_of([' ', '\t']).repeated().at_least(1)),
				empty().map(|_| (None, None))
			))
			.then(Domain::parser())
			.map(|(addr, domain)| {
				Some(match addr {
					(None, None) => Self::Domain(domain),
					(Some(addr), None) => Self::IpDomain(addr, domain),
					(Some(addr), Some(iface)) => Self::IpIfaceDomain(addr, iface, domain),
					_ => unreachable!()
				})
			})
			.then_ignore(choice((Comment::parser().ignored(), empty()))),
			// full line comment
			Comment::parser().map(|_| None),
			// empty line
			one_of([' ', '\t']).repeated().map(|_| None)
		))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use indoc::indoc;

	fn parse(input: &str) -> Blocklist {
		match Blocklist::parse("<test-input>", input) {
			Ok(blocklist) => blocklist,
			Err(err) => {
				panic!("Failed to parse input\n{}", err.msg());
			}
		}
	}

	fn test(input: &str, output: Vec<String>) {
		let blocklist = parse(input);
		let blocked: Vec<String> = blocklist
			.entries
			.into_iter()
			.map(|f| f.domain().0.clone())
			.collect();
		assert_eq!(blocked, output);
	}

	#[test]
	fn simple_domain() {
		test("example.com\n", vec!["example.com".into()]);
	}
	#[test]
	fn simple_domain_no_new_line() {
		test("example.com", vec!["example.com".into()]);
	}
	#[test]
	fn simple_sub_domain() {
		test("foo.baaa.dev\n", vec!["foo.baaa.dev".into()]);
	}
	#[test]
	fn muli_line_domain() {
		let input = indoc! {"
		example.com
		foo.baaa.dev
		"};
		test(input, vec!["example.com".into(), "foo.baaa.dev".into()]);
	}
	#[test]
	fn umlauts_domain() {
		test("exämple.de\n", vec!["exämple.de".into()]);
	}
	#[test]
	fn emoji_domain() {
		test("🐢.🦀.rs\n", vec!["🐢.🦀.rs".into()]);
	}
	#[test]
	fn kanji_domain() {
		test("大.陸.jp\n", vec!["大.陸.jp".into()]);
	}
	#[test]
	fn ipv4_domain() {
		test("0.0.0.0 example.com\n", vec!["example.com".into()]);
	}
	#[test]
	fn multiline_ipv4_domain() {
		let input = indoc! {"
		0.0.0.0 foo.baaa.dev
		93.184.216.34 example.com
		"};
		test(input, vec!["foo.baaa.dev".into(), "example.com".into()]);
	}
	#[test]
	fn ipv6_localhost_domain() {
		test("::1 example.com\n", vec!["example.com".into()]);
	}
	#[test]
	fn ipv6_domain() {
		//https://fungenerators.com/random/ipv6
		test(
			"e07f:11fd:8305:4f91:2892:852f:20ea:3bf9 example.com\n",
			vec!["example.com".into()]
		);
	}
	#[test]
	fn multiline_ipv6_domain() {
		let input = indoc! {"
		5af1:5a34:a062:a3f:84fd:76f1:cf8:f67 foo.baaa.dev
		babb:658e:8fa1:a257:521b:4638:d348:8b7d example.com
		"};
		test(input, vec!["foo.baaa.dev".into(), "example.com".into()]);
	}
	#[test]
	fn multiline_mish_domain() {
		let input = indoc! {"
		5af1:5a34:a062:a3f:84fd:76f1:cf8:f67 foo.baaa.dev
		example.com
		15.236.66.114 crates.io
		"};
		test(input, vec![
			"foo.baaa.dev".into(),
			"example.com".into(),
			"crates.io".into(),
		]);
	}

	#[test]
	fn comment() {
		test("#example.com\n", vec![]);
	}
	#[test]
	fn comment_muli_line() {
		let input = indoc! {"
		example.com
		#foo.baa
		#
		foo.baaa.dev
		"};
		test(input, vec!["example.com".into(), "foo.baaa.dev".into()]);
	}
	#[test]
	fn empty() {
		test("", vec![]);
	}
	#[test]
	fn empty_lines() {
		let input = indoc! {"

		example.com

		"};
		test(input, vec!["example.com".into()]);
	}

	#[test]
	fn strange_chars_in_comment1() {
		test("#</maybe-spy>", vec![]);
	}

	#[test]
	fn strange_chars_in_comment2() {
		test("#@ <<<<<<<< hostsplus => hosts", vec![]);
	}

	#[test]
	fn loopback_ipv6_domain() {
		test("fe80::1%lo0 localhost", vec!["localhost".into()]);
	}
}
