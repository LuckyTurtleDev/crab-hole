use std::collections::HashMap;

#[derive(Default)]
struct Node {
	is_in: bool,
	childs: HashMap<String, Node>
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
		for child in self.childs.values() {
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
		use std::{
			collections::HashSet,
			ffi::{c_char, c_void},
			fs,
			io::{self, Write as _},
			ptr::{null, null_mut}
		};
		use test::Bencher;

		/// https://stackoverflow.com/a/30983834/3755692
		extern "C" fn write_cb(_: *mut c_void, message: *const c_char) {
			write!(
				io::stderr(),
				"{}",
				String::from_utf8_lossy(unsafe {
					std::ffi::CStr::from_ptr(message as *const i8).to_bytes()
				})
			)
			.unwrap();
		}

		/// https://stackoverflow.com/a/30983834/3755692
		fn mem_print() {
			unsafe {
				jemalloc_sys::malloc_stats_print(Some(write_cb), null_mut(), null())
			}
		}

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
			mem_print();
			let miss_domanis = load_domains("/bench/missing-domains.txt");
			b.iter(|| {
				for domain in &miss_domanis {
					trie.contains(domain, true);
				}
			});
		}
	}
}
