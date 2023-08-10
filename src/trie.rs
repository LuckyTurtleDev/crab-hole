use nohash_hasher::BuildNoHashHasher;
use std::{collections::HashMap as Map, iter::Rev, sync::Mutex};

#[derive(Default)]
struct Node {
	is_in: bool,
	childs: Map<u8, Node, BuildNoHashHasher<u8>>
}

impl Node {
	fn insert(&mut self, iter: &mut Rev<std::str::Bytes<'_>>) {
		match iter.next() {
			None => self.is_in = true,
			Some(ch) => match self.childs.get_mut(&ch) {
				Some(child) => child.insert(iter),
				None => {
					let mut child = Node::default();
					child.insert(iter);
					self.childs.insert(ch, child);
				}
			}
		}
	}

	fn contains(
		&self,
		iter: &mut Rev<std::str::Bytes<'_>>,
		include_subdomains: bool
	) -> bool {
		match iter.next() {
			None => self.is_in,
			Some(ch) => {
				if include_subdomains && self.is_in && (ch == b'.') {
					return true;
				}
				match self.childs.get(&ch) {
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
		let mut iter = domain.bytes().rev();
		if iter.len() == 0 {
			return;
		}
		self.root.insert(&mut iter);
	}

	pub(crate) fn contains(&self, domain: &str, include_subdomains: bool) -> bool {
		let mut iter = domain.bytes().rev();
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
}
