use crate::{get_file, parser, trie::Trie, LIST_DIR};
use anyhow::Context;
use log::{error, info, warn};
use num_format::{Locale, ToFormattedString};
use tokio::{fs::create_dir_all, sync::RwLock};
use url::Url;

#[derive(Clone, Debug, poem_openapi::Object)]
pub(crate) struct ListInfo {
	/// count of domains inside this List
	pub(crate) blocked: u64,
	pub(crate) url: String
}

#[derive(Debug, Default)]
pub(crate) struct InnerBlockList {
	trie: Trie,
	list_info: Vec<ListInfo>
}

impl InnerBlockList {
	pub(crate) fn allow(&mut self, domain: &str, allow_subdomains: bool) {
		self.trie.allow(domain, allow_subdomains);
	}
}

#[derive(Debug, Default)]
pub(crate) struct BlockList {
	rw_lock: RwLock<InnerBlockList>
}

impl BlockList {
	pub(crate) fn new() -> Self {
		BlockList::default()
	}

	///Clear and update the current Blocklist, to all entries of the list at from `adlist`.
	///if `use_cache` is set true, cached list, will not be redownloaded (faster init)
	pub(crate) async fn update(
		&self,
		adlist: &Vec<Url>,
		allow_list: &Vec<Url>,
		restore_from_cache: bool
	) {
		if restore_from_cache {
			info!("👮💾 restore blocklist, from cache");
		} else {
			info!("👮📥 updating blocklist");
		}
		if let Err(err) = create_dir_all(&*LIST_DIR)
			.await
			.with_context(|| format!("failed create dir {:?}", LIST_DIR.as_path()))
		{
			error!("{err:?}");
		}
		let mut trie = Trie::new();
		let mut list_info = Vec::new();

		// block list
		for url in adlist {
			let raw_list = get_file(url, restore_from_cache).await;
			match raw_list {
				None => error!("skipp list {url}"),
				Some(raw_list) => {
					let result = parser::Blocklist::parse(url.as_str(), &raw_list);
					match result {
						Err(err) => {
							error!("parsing Blockist {}", url.as_str());
							err.print();
						},
						Ok(list) => {
							let mut count = 0;
							for entry in list.entries {
								if !trie.insert(&entry.domain().0, list_info.len()) {
									// domain was not already add by this list
									count += 1;
								}
							}
							list_info.push(ListInfo {
								blocked: count,
								url: url.as_str().to_owned()
							});
						}
					}
				}
			}
		}

		let mut inner_block_list = InnerBlockList { trie, list_info };

		// allow list
		for url in allow_list {
			info!("load allow list");
			let raw_list = get_file(url, restore_from_cache).await;
			match raw_list {
				None => error!("skipp list {url}"),
				Some(raw_list) => {
					let result = parser::Blocklist::parse(url.as_str(), &raw_list);
					match result {
						Err(err) => {
							error!("parsing allow list {}", url.as_str());
							err.print();
						},
						Ok(list) => {
							for entry in list.entries {
								if entry.domain().0.starts_with("*.") {
									inner_block_list.allow(&entry.domain().0[2 ..], true);
								} else {
									inner_block_list.allow(&entry.domain().0, false);
								}
							}
						},
					}
				}
			}
		}
		info!("shrink blocklist");
		inner_block_list.trie.shrink_to_fit();
		info!(
			"{} domains are blocked",
			inner_block_list.trie.len().to_formatted_string(&Locale::en)
		);
		if inner_block_list.trie.len() == 0 {
			warn!("Blocklist is empty");
		}
		let mut guard = self.rw_lock.write().await;
		*guard = inner_block_list;
		drop(guard);
		info!("👮✅ finish updating blocklist");
	}

	pub(crate) async fn contains(&self, domain: &str, include_subdomains: bool) -> bool {
		self.rw_lock
			.read()
			.await
			.trie
			.get(domain, include_subdomains)
			.is_some()
	}

	pub(crate) async fn list<'a>(&self) -> Vec<ListInfo> {
		self.rw_lock.read().await.list_info.to_owned()
	}

	pub(crate) async fn len(&self) -> usize {
		self.rw_lock.read().await.trie.len()
	}

	pub(crate) async fn query(&self, domain: &str) -> Vec<(ListInfo, usize)> {
		let guard = self.rw_lock.read().await;
		let mut hits = Vec::new();
		for (trie_value, pos) in guard.trie.query(domain).iter() {
			for (i, is_in) in trie_value.block_source.iter().enumerate() {
				if is_in {
					let list_info = guard.list_info.get(i).unwrap();
					hits.push((list_info.to_owned(), pos.to_owned()))
				}
			}
		}
		hits
	}
}
