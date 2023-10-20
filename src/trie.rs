use bit_vec::BitVec;
use qp_trie::Trie as QTrie;
use std::{
	fmt::{self, Debug, Formatter},
	iter
};

#[derive(Default)]
pub(crate) struct Trie(QTrie<Vec<u8>, BitVec>);

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
		index.set(list_info_index, true);
		let old_value = self.0.insert(key.clone(), index);
		if let Some(mut old_value) = old_value {
			// if value already exist, we need to add the entry to the existing bitvec
			was_already_add_by_this_list =
				old_value.get(list_info_index).is_some_and(|f| f);
			if list_info_index + 1 > old_value.len() {
				let grow = list_info_index + 1 - old_value.len();
				old_value.grow(grow, false);
				old_value.set(list_info_index, true);
			}
			self.0.insert(key, old_value);
		};
		was_already_add_by_this_list
	}

	/// Search for a domain in this trie. Returns `None` if domain was not found in the
	/// trie. Otherwise it returns a reference to a [`BitVec`], where the position of
	/// `true`s in [`BitVec`] are the indices of those lists in `BlockList.list_info`
	/// that contain the domain.
	pub(crate) fn find(&self, domain: &str, include_subdomains: bool) -> Option<&BitVec> {
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
				let index = sub_trie.get(&*key);
				if index.is_some() {
					return index;
				}
				key.push(b'.');
			}
			None
		} else {
			let key: Vec<u8> = domain.bytes().rev().collect();
			self.0.get(&key)
		}
	}

	pub(crate) fn query(&self, domain: &str) -> Vec<(&BitVec, usize)> {
		// not the fasted way, but it does not slow down the `contains` function
		// and has no duplicated code
		let pos_iter =
			iter::once(0).chain(domain.bytes().enumerate().filter_map(|(i, byte)| {
				if byte == b'.' {
					Some(i + 1) // +1 does not panic, if `.` is the last element
				} else {
					None
				}
			}));
		let mut hits = Vec::new();
		for pos in pos_iter {
			if let Some(index) = self.find(&domain[pos ..], false) {
				hits.push((index, pos));
			}
		}
		hits
	}

	pub(crate) fn remove(
		&mut self,
		domain: &str,
		remove_subdoamains: bool
	) -> QTrie<Vec<u8>, BitVec> {
		let mut key: Vec<u8> = domain.bytes().rev().collect();
		let direct_hit = self.0.remove(&key);
		let mut removed_domains = if remove_subdoamains {
			// if the domain ist `foo.com` we want to also remove `baa.foo.com`,
			// but keep `baafoo.com`
			key.push(b'.');
			let removed_trie = self.0.remove_prefix(&key);
			key.pop();
			removed_trie
		} else {
			QTrie::default()
		};
		if let Some(direct_hit) = direct_hit {
			removed_domains.insert(key, direct_hit);
		}
		removed_domains
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
		assert!(tree.find("example.com", false).is_none());
		tree.insert("example.com", 0);
		assert!(tree.find("example.com", false).is_some());
		assert!(tree.find("xample.com", false).is_none());
		assert!(tree.find("example.co", false).is_none());
		assert!(tree.find("eexample.com", false).is_none());
		tree.insert("eexample.com", 0);
		assert!(tree.find("eexample.com", false).is_some());
	}

	#[test]
	fn sub_domain() {
		let mut tree = Trie::new();
		dbg!(&tree);
		assert!(tree.find("example.com", true).is_none());
		tree.insert("example.com", 0);
		dbg!(&tree);
		assert!(tree.find("example.com", true).is_some());
		assert!(tree.find("xample.com", true).is_none());
		assert!(tree.find("example.co", true).is_none());
		assert!(tree.find("eexample.com", true).is_none());
		tree.insert("eexample.com", 0);
		dbg!(&tree);
		assert!(tree.find("eexample.com", true).is_some());

		assert!(tree.find("foo.example.com", true).is_some());
		assert!(tree.find("foo.example.com", false).is_none());
	}

	#[test]
	fn remove() {
		let mut tree = Trie::new();
		tree.insert("example.com", 0);
		tree.insert("sub.example.com", 0);
		dbg!(&tree);
		assert!(tree.find("example.com", false).is_some());
		assert!(tree.find("foo.example.com", false).is_some());
		tree.remove("example.com", false);
		assert!(tree.find("example.com", false).is_none());
		assert!(tree.find("foo.example.com", false).is_some());
	}

	#[test]
	fn remove_sub() {
		let mut tree = Trie::new();
		tree.insert("example.com", 0);
		tree.insert("sub.example.com", 0);
		dbg!(&tree);
		assert!(tree.find("example.com", false).is_some());
		assert!(tree.find("foo.example.com", false).is_some());
		tree.remove("example.com", true);
		assert!(tree.find("example.com", false).is_none());
		assert!(tree.find("foo.example.com", false).is_none());
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
