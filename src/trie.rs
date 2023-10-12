use qp_trie::Trie as QTrie;
use std::fmt::{self, Debug, Formatter};

#[derive(Default)]
pub(crate) struct Trie(QTrie<Vec<u8>, ()>);

impl Debug for Trie {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		struct TrieDebug<'a>(&'a Trie);

		impl Debug for TrieDebug<'_> {
			fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
				f.debug_list()
					.entries(
						self.0
							 .0
							.iter()
							.map(|(bytes, _)| String::from_utf8_lossy(bytes))
					)
					.finish()
			}
		}

		f.debug_tuple("Trie").field(&TrieDebug(self)).finish()
	}
}

impl Trie {
	pub(crate) fn new() -> Self {
		Self(QTrie::new())
	}

	pub(crate) fn insert(&mut self, domain: &str) {
		if domain.is_empty() {
			return;
		}
		let key = domain.bytes().rev().collect();
		self.0.insert(key, ());
	}

	pub(crate) fn contains(&self, domain: &str, include_subdomains: bool) -> bool {
		if include_subdomains {
			let mut key = Vec::new();
			let mut domain = domain.bytes().rev();
			let mut sub_trie = self.0.subtrie(&Vec::new());
			while !sub_trie.is_empty() {
				for byte in &mut domain {
					if byte == b'.' {
						break;
					}
					key.push(byte);
				}
				sub_trie = sub_trie.subtrie(&*key);
				if sub_trie.get(&*key).is_some() {
					return true;
				}
				key.push(b'.');
			}
			false
		} else {
			let key: Vec<u8> = domain.bytes().rev().collect();
			self.0.get(&key).is_some()
		}
	}

	pub(crate) fn shrink_to_fit(&mut self) {}

	pub(crate) fn len(&self) -> usize {
		self.0.count()
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
		dbg!(&tree);
		assert!(!tree.contains("example.com", true));
		tree.insert("example.com");
		dbg!(&tree);
		assert!(tree.contains("example.com", true));
		assert!(!tree.contains("xample.com", true));
		assert!(!tree.contains("example.co", true));
		assert!(!tree.contains("eexample.com", true));
		tree.insert("eexample.com");
		dbg!(&tree);
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
