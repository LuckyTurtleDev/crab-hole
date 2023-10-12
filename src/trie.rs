use cedarwood::Cedar;
use std::iter;

pub(crate) struct Trie {
	cedar: Cedar,
	len: usize
}

fn rev(domain: &str) -> String {
	domain.chars().rev().chain(iter::once('.')).collect()
}

impl Trie {
	pub(crate) fn new() -> Self {
		Self {
			cedar: Cedar::new(),
			len: 0
		}
	}

	pub(crate) fn insert(&mut self, domain: &str) {
		if domain.is_empty() || self.contains(domain, false) {
			return;
		}

		let rev = rev(domain);
		self.cedar.update(&rev, 1);
		self.len += 1;
	}

	pub(crate) fn contains(&self, domain: &str, include_subdomains: bool) -> bool {
		let rev = rev(domain);
		if include_subdomains {
			for (_, prefix_len) in self.cedar.common_prefix_iter(&rev) {
				if &rev[prefix_len ..= prefix_len] == "." || prefix_len == rev.len() {
					return true;
				}
			}
			false
		} else {
			self.cedar.exact_match_search(&rev).is_some()
		}
	}

	pub(crate) fn shrink_to_fit(&mut self) {}

	pub(crate) fn len(&self) -> usize {
		self.len
	}
}

#[cfg(test)]
mod tests {
	use super::Trie;

	#[test]
	fn simple() {
		let mut tree = Trie::new();
		assert!(!tree.contains("example.com", false));
		tree.insert("example.com");
		assert!(tree.contains("example.com", false));
		assert!(!tree.contains("xample.com", false));
		assert!(!tree.contains("example.co", false));
		assert!(!tree.contains("eexample.com", false));
		tree.insert("eexample.com");
		assert!(tree.contains("eexample.com", false));
	}

	#[test]
	fn sub_domain() {
		let mut tree = Trie::new();
		assert!(!tree.contains("example.com", true));
		tree.insert("example.com");
		assert!(tree.contains("example.com", true));
		assert!(!tree.contains("xample.com", true));
		assert!(!tree.contains("example.co", true));
		assert!(!tree.contains("eexample.com", true));
		tree.insert("eexample.com");
		assert!(tree.contains("eexample.com", true));

		assert!(tree.contains("foo.example.com", true));
		assert!(!tree.contains("foo.example.com", false));
	}

	#[cfg(nightly)]
	mod bench {
		use super::*;
		use std::{collections::HashSet, fs};
		use test::Bencher;

		fn load_domains(path: &str) -> Vec<String> {
			let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path);
			let raw_list = fs::read_to_string(&path).unwrap();
			let list = crate::parser::Blocklist::parse(&path, &raw_list)
				.ok()
				.unwrap();
			drop(raw_list);
			list.entries
				.iter()
				.map(|line| line.domain().0.clone())
				.collect()
		}

		#[bench]
		fn create_trie(b: &mut Bencher) {
			let domains = load_domains("/bench/domains.txt");
			let mut trie = Trie::new();
			b.iter(|| {
				for domain in &domains {
					trie.insert(domain);
				}
			});
		}

		#[bench]
		fn trie_contains(b: &mut Bencher) {
			let domains = load_domains("/bench/domains.txt");
			let mut trie = Trie::new();
			for domain in &domains {
				trie.insert(domain);
			}
			let domains: HashSet<String> = domains.into_iter().take(1000).collect();
			b.iter(|| {
				for domain in &domains {
					if !trie.contains(domain, true) {
						panic!("this domain should be insert")
					};
				}
			});
		}

		#[bench]
		fn trie_miss(b: &mut Bencher) {
			let domains = load_domains("/bench/domains.txt");
			let mut trie = Trie::new();
			for domain in &domains {
				trie.insert(domain);
			}
			drop(domains);
			let miss_domanis = load_domains("/bench/missing-domains.txt");
			b.iter(|| {
				for domain in &miss_domanis {
					trie.contains(domain, true);
				}
			});
		}
	}
}
