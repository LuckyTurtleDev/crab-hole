use std::{collections::HashMap as Map, iter::Rev};

#[derive(Default)]
struct Node {
	is_in: bool,
	childs: Map<u8, Node>
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
			Some(ch) => match self.childs.get(&ch) {
				None => false,
				Some(child) => {
					if include_subdomains && self.is_in && (ch == '.' as u8) {
						return true;
					}
					child.contains(iter, include_subdomains)
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
}

pub struct Trie {
	root: Node
}

impl Trie {
	pub fn new() -> Self {
		Trie {
			root: Node::default()
		}
	}

	pub fn insert(&mut self, domain: &str) {
		let mut iter = domain.bytes().rev();
		if iter.len() == 0 {
			return;
		}
		self.root.insert(&mut iter);
	}

	pub fn contains(&self, domain: &str, include_subdomains: bool) -> bool {
		let mut iter = domain.bytes().rev();
		self.root.contains(&mut iter, include_subdomains)
	}

	pub fn shrink_to_fit(&mut self) {
		self.root.shrink_to_fit();
	}
}
