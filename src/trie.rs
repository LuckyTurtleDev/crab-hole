use bit_vec::BitVec;
use qp_trie::Trie as QTrie;
use std::{
	fmt::{self, Debug, Formatter},
	iter
};

#[derive(Debug)]
pub(crate) struct TrieValue {
	/// domain is blocked if [`BitVec`] contains at least one true
	/// `true`s in [`BitVec`] are the indices of those lists in `BlockList.list_info`
	/// that contain the domain.
	pub(crate) block_source: BitVec,
	/// domain was manuall allowed.
	/// Allows have a higher piority than blocks
	/// I think we do not need track the sources here, since they are regular not many allow lists.
	pub(crate) allowed: bool
}

#[derive(Default)]
pub(crate) struct Trie(QTrie<Vec<u8>, TrieValue>);

impl Debug for Trie {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		struct TrieDebug<'a>(&'a Trie);

		impl Debug for TrieDebug<'_> {
			fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
				f.debug_list()
					.entries(
						self.0 .0.iter().map(|(bytes, value)| {
							(String::from_utf8_lossy(bytes), value)
						})
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

	/// Add a domain to this trie. If the domain is not already in the trie, it will
	/// be added with the list marked as its single source and returns true. If the
	/// domain is already in the trie but was not marked as coming from the list, it
	/// will be marked as coming from the list as well and returns true. If the
	/// domain is already in the trie and is marked as coming from the list, it will
	/// return false.
	pub(crate) fn insert(&mut self, domain: &str, list_info_index: usize) -> bool {
		let mut was_already_add_by_this_list = false;
		if domain.is_empty() {
			return was_already_add_by_this_list;
		}
		let key: Vec<u8> = domain.bytes().rev().collect();
		let mut index = BitVec::from_elem(list_info_index + 1, false);
		// We will add more new value than editing existing once.
		// So we assume that value does not exist first and try to insert a new value first.
		index.set(list_info_index, true);
		let old_value = self.0.insert(key.clone(), TrieValue {
			block_source: index,
			allowed: false
		});
		if let Some(mut old_value) = old_value {
			// if value already exist, we need to add the entry to the existing bitvec
			was_already_add_by_this_list = old_value
				.block_source
				.get(list_info_index)
				.is_some_and(|f| f);
			if list_info_index + 1 > old_value.block_source.len() {
				let grow = list_info_index + 1 - old_value.block_source.len();
				old_value.block_source.grow(grow, false);
				old_value.block_source.set(list_info_index, true);
			}
			self.0.insert(key, old_value);
		};
		was_already_add_by_this_list
	}

	/// return true if domain is blocked
	pub(crate) fn blocked(&self, domain: &str, include_subdomains: bool) -> bool {
		if include_subdomains {
			let mut key = Vec::new();
			let mut domain = domain.bytes().rev();
			let mut sub_trie = self.0.subtrie(&Vec::new());
			let mut allowed = true;
			while !sub_trie.is_empty() {
				for byte in &mut domain {
					if byte == b'.' {
						break;
					}
					key.push(byte);
				}
				sub_trie = sub_trie.subtrie(&*key);
				let trie_value = sub_trie.get(&*key);
				if let Some(trie_value) = trie_value {
					allowed = trie_value.allowed;
				}
				key.push(b'.');
			}
			!allowed
		} else {
			let key: Vec<u8> = domain.bytes().rev().collect();
			self.0.get(&key).is_some_and(|f| !f.allowed)
		}
	}

	/// return all block and allow entrys assiated with `domain` including subdomains
	pub(crate) fn query(&self, domain: &str) -> Vec<(&TrieValue, usize)> {
		// not the fasted way, but it does not slow down the `blocked` function
		// and has no duplicated code
		let domain: Vec<u8> = domain.bytes().rev().collect();
		let pos_iter = domain
			.iter()
			.enumerate()
			.filter_map(|(i, byte)| if byte == &b'.' { Some(i) } else { None })
			.chain(iter::once(domain.len()));
		let mut hits = Vec::new();
		for pos in pos_iter {
			if let Some(index) = self.0.get(&domain[.. pos]) {
				hits.push((index, domain.len() - pos)); //order in rev here
			}
		}
		hits
	}

	/// allow a domain, even it was blocked before.
	/// After calling this function [`Self::insert()`] should no called anymore at the same trie.
	pub(crate) fn allow(&mut self, domain: &str, remove_subdoamains: bool) {
		let mut key: Vec<u8> = domain.bytes().rev().chain(iter::once(b'.')).collect();
		if remove_subdoamains {
			for (_, entry) in self.0.iter_prefix_mut(&key) {
				entry.allowed = true;
			}
		}
		key.pop();
		if let Some(entry) = self.0.get_mut(&key) {
			entry.allowed = true;
		} else {
			let entry = TrieValue {
				allowed: true,
				block_source: BitVec::new()
			};
			self.0.insert(key.clone(), entry);
		}
	}

	pub(crate) fn shrink_to_fit(&mut self) {}

	pub(crate) fn len(&self) -> usize {
		self.0.count()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn simple() {
		let mut tree = Trie::new();
		assert!(!tree.blocked("example.com", false));
		tree.insert("example.com", 0);
		assert!(tree.blocked("example.com", false));
		assert!(!tree.blocked("xample.com", false));
		assert!(!tree.blocked("example.co", false));
		assert!(!tree.blocked("eexample.com", false));
		tree.insert("eexample.com", 0);
		assert!(tree.blocked("eexample.com", false));
	}

	#[test]
	fn sub_domain() {
		let mut tree = Trie::new();
		dbg!(&tree);
		assert!(!tree.blocked("example.com", true));
		tree.insert("example.com", 0);
		dbg!(&tree);
		assert!(tree.blocked("example.com", true));
		assert!(!tree.blocked("xample.com", true));
		assert!(!tree.blocked("example.co", true));
		assert!(!tree.blocked("eexample.com", true));
		tree.insert("eexample.com", 0);
		dbg!(&tree);
		assert!(tree.blocked("eexample.com", true));
		assert!(tree.blocked("foo.example.com", true));
		assert!(!tree.blocked("foo.example.com", false));
	}

	#[test]
	fn allow() {
		let mut tree = Trie::new();
		tree.insert("example.com", 0);
		tree.insert("sub.example.com", 0);
		dbg!(&tree);
		assert!(tree.blocked("example.com", false));
		assert!(tree.blocked("sub.example.com", false));
		tree.allow("example.com", false);
		dbg!(&tree);
		assert!(!tree.blocked("example.com", false));
		assert!(tree.blocked("sub.example.com", false));
	}

	#[test]
	fn allow_all_subdomains() {
		let mut tree = Trie::new();
		tree.insert("example.com", 0);
		tree.insert("sub.example.com", 0);
		dbg!(&tree);
		assert!(tree.blocked("example.com", false));
		assert!(tree.blocked("sub.example.com", false));
		tree.allow("example.com", true);
		dbg!(&tree);
		assert!(!tree.blocked("example.com", false));
		assert!(!tree.blocked("sub.example.com", false));
	}

	#[test]
	fn allow_sub_domain() {
		let mut tree = Trie::new();
		tree.insert("example.com", 0);
		tree.insert("sub.example.com", 0);
		dbg!(&tree);
		assert!(tree.blocked("example.com", true));
		assert!(tree.blocked("sub.example.com", true));
		tree.allow("sub.example.com", true);
		dbg!(&tree);
		assert!(tree.blocked("example.com", true));
		assert!(!tree.blocked("sub.example.com", true));
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
			let raw_list = read_to_string(&path).unwrap();
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
					trie.insert(domain, 0);
				}
			});
		}

		#[bench]
		fn trie_contains(b: &mut Bencher) {
			let domains = load_domains("/bench/domains.txt");
			let mut trie = Trie::new();
			for domain in &domains {
				trie.insert(domain, 0);
			}
			let domains: HashSet<String> = domains.into_iter().take(1000).collect();
			b.iter(|| {
				for domain in &domains {
					if trie.find(domain, true).is_none() {
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
				trie.insert(domain, 0);
			}
			drop(domains);
			mem_print();
			let miss_domanis = load_domains("/bench/missing-domains.txt");
			b.iter(|| {
				for domain in &miss_domanis {
					trie.find(domain, true);
				}
			});
		}
	}
}
