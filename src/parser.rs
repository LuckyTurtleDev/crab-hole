use ariadne::{Label, Report, ReportKind, Source};
use chumsky::{error::SimpleReason, prelude::*};
use std::net::IpAddr;

type ParserError = Simple<char>;

/// A domain. Never contains a trailing punct.
pub(crate) struct Domain(pub(crate) String);

impl Domain {
	fn parser() -> impl Parser<char, Self, Error = ParserError> {
		let ident =
			filter(|c: &char| *c != '#' && *c != ':' && *c != '.' && !c.is_whitespace())
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
			.debug("Domain parser")
	}
}

pub(crate) struct Blocklist {
	pub(crate) entries: Vec<Line>
}

pub(crate) struct ParseError<'a> {
	input: &'a str,
	path_str: &'a str,
	err: Vec<ParserError>
}

fn report_err(buf: &str, path_str: &str, err: Vec<ParserError>) {
	for e in err {
		let mut report = Report::build(ReportKind::Error, path_str, e.span().start);
		match (e.reason(), e.found()) {
			(SimpleReason::Unexpected, Some(found)) => {
				report.set_message("Unexpected token");
				report.add_label(
					Label::new((path_str, e.span()))
						.with_message(format!("Unexpected token {found}"))
				);
				if e.expected().len() > 0 {
					report.set_note(format!(
						"Expected {}",
						e.expected()
							.map(|ex| match ex {
								Some(ex) => ex.to_string(),
								None => "end of file".to_owned()
							})
							.collect::<Vec<_>>()
							.join(", ")
					));
				}
			},

			(SimpleReason::Unexpected, None) => {
				report.set_message("Unexpected end of file");
			},

			(SimpleReason::Unclosed { span, delimiter }, found) => {
				report.set_message("Unclosed delimiter");
				report.add_label(
					Label::new((path_str, span.clone()))
						.with_message(format!("Unclosed delimiter {delimiter}"))
				);
				if let Some(found) = found {
					report.add_label(
						Label::new((path_str, e.span()))
							.with_message(format!("Must be closed before this {found}"))
					);
				}
			},

			(SimpleReason::Custom(msg), _) => {
				report.set_message(msg);
				report.add_label(Label::new((path_str, e.span())).with_message(msg));
			}
		};
		report
			.finish()
			.print((path_str, Source::from(buf)))
			.unwrap();
	}
}

impl ParseError<'_> {
	pub(crate) fn print(self) {
		report_err(self.input, self.path_str, self.err);
	}
}

pub(crate) type ParseResult<'a, T> = Result<T, ParseError<'a>>;

impl Blocklist {
	pub(crate) fn parse<'a>(path: &'a str, input: &'a str) -> ParseResult<'a, Self> {
		let parser = Self::parser();
		#[cfg(test)]
		let result = parser.parse_recovery_verbose(input);
		#[cfg(not(test))]
		let result = parser.parse_recovery(input);
		match result {
			(Some(value), errs) if errs.is_empty() => Ok(value),
			(_, errs) => Err(ParseError {
				input,
				path_str: path,
				err: errs
			})
		}
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
			.debug("Blocklist parser")
	}
}

pub(crate) enum Line {
	Domain(Domain),
	IpDomain(IpAddr, Domain)
}

impl Line {
	fn parser() -> impl Parser<char, Option<Self>, Error = ParserError> {
		choice((
			// [<ip>] <domain>
			choice((
				filter(|c: &char| c.is_ascii_hexdigit() || *c == '.' || *c == ':')
					.repeated()
					.at_least(2)
					.map(|ip| Some(ip.into_iter().collect::<String>().parse().unwrap()))
					.then_ignore(one_of([' ', '\t']).repeated().at_least(1)),
				empty().map(|_| None)
			))
			.then(Domain::parser())
			.map(|(addr, domain)| {
				Some(match addr {
					None => Self::Domain(domain),
					Some(addr) => Self::IpDomain(addr, domain)
				})
			})
			.debug("Line parser: IpDomain"),
			// full line comment
			just("#")
				.then(none_of(['\r', '\n']).repeated())
				.map(|_| None)
				.debug("Line parser: Comment"),
			// empty line
			one_of([' ', '\t'])
				.repeated()
				.map(|_| None)
				.debug("Line parser: Empty")
		))
		.debug("Line parser")
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
				err.print();
				panic!("Failed to parse input");
			}
		}
	}

	fn test(input: &str, output: Vec<String>) {
		let blocklist = parse(input);
		let blocked: Vec<String> = blocklist
			.entries
			.into_iter()
			.map(|f| {
				match f {
					Line::Domain(domain) => domain,
					Line::IpDomain(_, domain) => domain
				}
				.0
			})
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
