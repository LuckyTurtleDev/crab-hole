use std::{collections::HashMap as Map, iter::Rev};

#[derive(Default)]
struct Node {
	is_in: bool,
	childs: Map<String, Node>
}

impl Node {
	fn insert<'a>(&mut self, mut iter: impl Iterator<Item = &'a str>) {
		match iter.next() {
			None => self.is_in = true,
			Some(domain_part) => match self.childs.get_mut(domain_part) {
				Some(child) => child.insert(iter),
				None => {
					let mut child = Node::default();
					child.insert(iter);
					self.childs.insert(domain_part.to_owned(), child);
				}
			}
		}
	}

	fn contains<'a>(
		&self,
		mut iter: impl Iterator<Item = &'a str>,
		include_subdomains: bool
	) -> bool {
		match iter.next() {
			None => self.is_in,
			Some(domain_part) => {
				if include_subdomains && self.is_in {
					return true;
				}
				match self.childs.get(domain_part) {
					None => false,
					Some(child) => child.contains(iter, include_subdomains)
				}
			}
		}
	}

	fn shrink_to_fit(&mut self) {
		self.childs.shrink_to_fit();
		for (_, child) in self.childs.iter_mut() {
			child.shrink_to_fit();
		}
	}

	fn len(&self, len: &mut usize) {
		if self.is_in {
			*len += 1;
		}
		for (_, child) in &self.childs {
			child.len(len);
		}
	}
}

#[derive(Default)]
pub(crate) struct Trie {
	root: Node
}

impl Trie {
	pub(crate) fn new() -> Self {
		Trie::default()
	}

	pub(crate) fn insert(&mut self, domain: &str) {
		if domain.is_empty() {
			return;
		}
		let mut iter = domain.split('.').rev();
		self.root.insert(&mut iter);
	}

	pub(crate) fn contains(&self, domain: &str, include_subdomains: bool) -> bool {
		let mut iter = domain.split('.').rev();
		self.root.contains(&mut iter, include_subdomains)
	}

	pub(crate) fn shrink_to_fit(&mut self) {
		self.root.shrink_to_fit();
	}

	pub(crate) fn len(&self) -> usize {
		let mut len: usize = 0;
		self.root.len(&mut len);
		len
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

		#[bench]
		fn create_trie(b: &mut Bencher) {
			let mut trie = Trie::new();
			let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bench/domains.txt");
			let raw_list = fs::read_to_string(path).unwrap();
			let list = crate::parser::Blocklist::parse(path, &raw_list)
				.ok()
				.unwrap();
			drop(raw_list);
			let domains: Vec<String> = list
				.entries
				.iter()
				.map(|line| line.domain().0.clone())
				.collect();
			b.iter(|| {
				for domain in &domains {
					trie.insert(domain);
				}
			});
		}

		#[bench]
		fn trie_contains(b: &mut Bencher) {
			let mut trie = Trie::new();
			let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bench/domains.txt");
			let raw_list = fs::read_to_string(path).unwrap();
			let list = crate::parser::Blocklist::parse(path, &raw_list)
				.ok()
				.unwrap();
			drop(raw_list);
			let domains: Vec<String> = list
				.entries
				.iter()
				.map(|line| line.domain().0.clone())
				.collect();
			for domain in &domains {
				trie.insert(domain);
			}
			let domains: HashSet<String> = domains.into_iter().collect();
			b.iter(|| {
				for domain in &domains {
					if !trie.contains(domain, false) {
						panic!("this domain should be insert")
					};
				}
			});
		}
	}
}
