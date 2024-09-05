use log::{Level, Record};
use my_env_logger_style::env_logger::fmt::Formatter;
use once_cell::sync::Lazy;
use regex::Regex;
use std::{io, io::Write};

static REGEX: Lazy<Regex> = Lazy::new(|| {
	// https://ihateregex.io/expr/ip/
	let regex_ipv4 = r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}";
	// https://ihateregex.io/expr/ipv6/
	let regex_ipv6 = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";
	// emoji: https://ihateregex.io/expr/emoji/
	let regex_domain = r"(([\w\-\p{Math}\p{Emoji}\p{Emoji_Component}])+\.){2,}";
	Regex::new(&format! {"{regex_ipv4}|{regex_ipv6}|{regex_domain}"}).unwrap()
});

fn format(buf: &mut Formatter, record: &Record<'_>) -> io::Result<()> {
	my_env_logger_style::format(buf, record)?;
	Ok(())
}

pub(crate) fn init_logger() {
	my_env_logger_style::get_set_max_module_len(20);
	my_env_logger_style::set_arg_formatter(Box::new(
		|buf: &mut Formatter, record: &Record<'_>| {
			if let Some(mod_path) = record.module_path() {
				if log::max_level() < Level::Debug && mod_path.starts_with("hickory") {
					let message = format!("{}", record.args());
					let message = REGEX.replace_all(&message, "RESTRAINED");
					return writeln!(buf, "{message}");
				}
			};
			writeln!(buf, "{}", record.args())
		}
	))
	.unwrap();
	let mut logger = my_env_logger_style::builder();
	logger.format(format).init();
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn regex() {
		Lazy::force(&REGEX);
		assert!(REGEX.replace("com.", "") == "com."); //matching this would cause to much false positive
		assert!(REGEX.replace(".com.", "") == ".com.");
		assert!(REGEX.replace("example.com.", "") == "");
		assert!(REGEX.replace("ex_am-ple.com.", "") == "");
		assert!(REGEX.replace(".example.com.", "") == ".");
		assert!(REGEX.replace(":example.com.", "") == ":");
		assert!(REGEX.replace("eiea.eiuuue.euu.", "") == "");
		assert!(REGEX.replace("🐬.com.", "") == "");
		assert!(REGEX.replace("👪.com.", "") == "");
		assert!(REGEX.replace("♡.com.", "") == ""); //`♡` is a Math char
		assert!(REGEX.replace("ä.com.", "") == "");
		assert!(REGEX.replace("∫.com.", "") == ""); //is this a valid domain?
		assert!(REGEX.replace(":.com.", "") == ":.com.");
	}
}
