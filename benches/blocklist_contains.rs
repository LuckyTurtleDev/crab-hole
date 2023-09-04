#![warn(rust_2018_idioms, unreachable_pub)]
#![forbid(elided_lifetimes_in_paths, unsafe_code)]

#[allow(dead_code)]
#[path = "../src/parser.rs"]
mod parser;
#[allow(dead_code)]
#[path = "../src/trie.rs"]
mod trie;

use once_cell::sync::Lazy;
use std::fs;
use trie::Trie;

static DOMAINS: Lazy<Vec<String>> = Lazy::new(|| {
	let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bench/domains.txt");
	let raw_list = fs::read_to_string(path).unwrap();
	let list = crate::parser::Blocklist::parse(path, &raw_list)
		.ok()
		.unwrap();
	drop(raw_list);
	list.entries
		.iter()
		.map(|line| line.domain().0.clone())
		.collect()
});

static TRIE: Lazy<Trie> = Lazy::new(|| {
	let mut trie = Trie::new();
	for domain in DOMAINS.iter() {
		trie.insert(domain);
	}
	trie
});

mod iai_benchmarks {
	use super::{DOMAINS, TRIE};

	#[inline(never)]
	fn trie_contains_hit() {
		for domain in DOMAINS.iter().take(1) {
			assert!(TRIE.contains(domain, false));
		}
	}

	// define main function
	iai::main!(trie_contains_hit);

	// expose main function to the parent module
	pub(super) fn run() {
		main();
	}
}

fn main() {
	// force to initialise the trie
	_ = &*TRIE;
	println!("Benchmark Initialised");

	// run the benchmarks
	iai_benchmarks::run();
}
