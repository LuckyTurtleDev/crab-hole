use crate::{parser, trie::Trie, CLIENT, LIST_DIR};
use anyhow::Context;
use log::{error, info, warn};
use num_format::{Locale, ToFormattedString};
use std::{
	path::PathBuf,
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc
	}
};
use tokio::{
	fs::{create_dir_all, read_to_string, write},
	sync::RwLock
};
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
		restore_from_cache: bool,
		blocklist_len: Arc<AtomicUsize>
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

		for url in adlist {
			let raw_list = if url.scheme() == "file" {
				let path = url.path();
				info!("load file {path:?}");
				let raw_list = read_to_string(&path).await;
				match raw_list.with_context(|| format!("can not open file {path:?}")) {
					Ok(value) => Some(value),
					Err(err) => {
						error!("{err:?}");
						None
					}
				}
			} else {
				let mut path = url.path().to_owned().replace('/', "-");
				if !path.is_empty() {
					path.remove(0);
				}
				if let Some(query) = url.query() {
					path += "--";
					path += query;
				}
				let path = PathBuf::from(&*LIST_DIR).join(path);
				let raw_list = if !path.exists() || !restore_from_cache {
					info!("downloading {url}");
					let resp: anyhow::Result<String> = (|| async {
						//try block
						let resp = CLIENT
							.get(url.to_owned())
							.send()
							.await?
							.error_for_status()?
							.text()
							.await?;
						if let Err(err) = write(&path, &resp)
							.await
							.with_context(|| format!("failed to save to {path:?}"))
						{
							error!("{err:?}");
						}
						Ok(resp)
					})()
					.await;
					match resp.with_context(|| format!("error downloading {url}")) {
						Ok(value) => Some(value),
						Err(err) => {
							error!("{err:?}");
							None
						}
					}
				} else {
					None
				};
				match raw_list {
					Some(value) => Some(value),
					None => {
						if path.exists() {
							info!("restore from cache {url}");
							match read_to_string(&path)
								.await
								.with_context(|| format!("error reading file {path:?}"))
							{
								Ok(value) => Some(value),
								Err(err) => {
									error!("{err:?}");
									None
								}
							}
						} else {
							None
						}
					},
				}
			};
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
		info!("shrink blocklist");
		trie.shrink_to_fit();
		let blocked_count = trie.len();
		blocklist_len.store(blocked_count, Ordering::Relaxed);
		info!(
			"{} domains are blocked",
			blocked_count.to_formatted_string(&Locale::en)
		);
		if blocked_count == 0 {
			warn!("Blocklist is empty");
		}
		let mut guard = self.rw_lock.write().await;
		guard.trie = trie;
		guard.list_info = list_info;
		drop(guard);
		info!("👮✅ finish updating blocklist");
	}

	pub(crate) async fn contains(&self, domain: &str, include_subdomains: bool) -> bool {
		self.rw_lock
			.read()
			.await
			.trie
			.find(domain, include_subdomains)
			.is_some()
	}

	pub(crate) async fn remove(
		&self,
		domain: &str,
		remove_subdomains: bool
	) -> Vec<String> {
		let mut guard = self.rw_lock.write().await;
		let removed = guard.trie.remove(domain, remove_subdomains);
		removed
			.into_iter()
			.map(|(mut domain, index)| {
				// reduce the counter of blocked domains in listinfo
				for (i, is_in) in index.iter().enumerate() {
					if is_in {
						guard.list_info[i].blocked -= 1;
					}
				}
				domain.reverse();
				String::from_utf8(domain).unwrap() //should only include valid utf8
			})
			.collect()
	}

	pub(crate) async fn list<'a>(&self) -> Vec<ListInfo> {
		self.rw_lock.read().await.list_info.to_owned()
	}

	pub(crate) async fn query(&self, domain: &str) -> Vec<(ListInfo, usize)> {
		let guard = self.rw_lock.read().await;
		let mut hits = Vec::new();
		for (index, pos) in guard.trie.query(domain).iter() {
			for (i, is_in) in index.iter().enumerate() {
				if is_in {
					let list_info = guard.list_info.get(i).unwrap();
					hits.push((list_info.to_owned(), pos.to_owned()))
				}
			}
		}
		hits
	}
}
