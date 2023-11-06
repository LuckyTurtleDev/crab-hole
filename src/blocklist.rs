use std::collections::HashMap;

use crate::{api, get_file, parser, trie::Trie, LIST_DIR};
use anyhow::Context;
use log::{error, info, warn};
use num_format::{Locale, ToFormattedString};
use tokio::{fs::create_dir_all, sync::RwLock};
use url::Url;

#[derive(Clone, Debug, poem_openapi::Object)]
pub(crate) struct ListInfo {
	/// count of domains inside this List
	pub(crate) len: u64,
	pub(crate) url: String,
	/// If `Some` the list has partly fail (for example downloading a newer version)
	/// String stores error messages.
	pub(crate) errors: Option<String>
}

#[derive(Clone, Debug, poem_openapi::Enum)]
#[oai(rename_all = "lowercase")]
pub(crate) enum ListType {
	Block,
	Allow
}

#[derive(Clone, Debug, poem_openapi::Object)]
pub(crate) struct FailedList {
	pub(crate) url: String,
	#[oai(rename = "type")]
	pub(crate) tipe: ListType,
	/// reason why loading list failed
	pub(crate) errors: String
}

#[derive(Debug, Default)]
pub(crate) struct InnerBlockList {
	trie: Trie,
	/// info about used blocklist.
	/// To keep `trie` as small as possilble,
	/// blocked list is stored in its own field.
	block_list_info: Vec<ListInfo>,
	/// store list, wich could not be loadedi
	failed_lists: Vec<FailedList>,
	/// info about allow list
	allow_list_info: Vec<ListInfo>
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
	// TODO: clean this up
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
		let mut block_list_info = Vec::new();
		let mut failed_lists = Vec::new();

		// block list
		for url in adlist {
			let (raw_list, mut list_errors) = get_file(url, restore_from_cache).await;
			match raw_list {
				None => {
					error!("skipp list {url}");
					failed_lists.push(FailedList {
						url: url.as_str().to_owned(),
						errors: list_errors,
						tipe: ListType::Block
					})
				},
				Some(raw_list) => {
					let result = parser::Blocklist::parse(url.as_str(), &raw_list);
					match result {
						Err(err) => {
							let msg = err.msg();
							error!("parsing Blockist {}\n{msg}", url.as_str());
							list_errors += &msg;
							failed_lists.push(FailedList {
								url: url.as_str().to_owned(),
								errors: list_errors,
								tipe: ListType::Block
							})
						},
						Ok(list) => {
							let mut count = 0;
							for entry in list.entries {
								if !trie.insert(&entry.domain().0, block_list_info.len())
								{
									// domain was not already add by this list
									count += 1;
								}
							}
							block_list_info.push(ListInfo {
								len: count,
								url: url.as_str().to_owned(),
								errors: (!list_errors.is_empty()).then_some(list_errors)
							});
						}
					}
				}
			}
		}

		let mut inner_block_list = InnerBlockList {
			trie,
			block_list_info,
			failed_lists,
			allow_list_info: Vec::new()
		};

		// allow list
		for url in allow_list {
			info!("load allow list");
			let (raw_list, mut list_errors) = get_file(url, restore_from_cache).await;
			match raw_list {
				None => error!("skipp list {url}"),
				Some(raw_list) => {
					let result = parser::Blocklist::parse(url.as_str(), &raw_list);
					match result {
						Err(err) => {
							let msg = err.msg();
							error!("parsing Blockist {}\n{msg}", url.as_str());
							list_errors += &msg;
							inner_block_list.failed_lists.push(FailedList {
								url: url.as_str().to_owned(),
								errors: list_errors,
								tipe: ListType::Allow
							})
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

	/// return true if domain is blocked
	pub(crate) async fn blocked(&self, domain: &str, include_subdomains: bool) -> bool {
		self.rw_lock
			.read()
			.await
			.trie
			.blocked(domain, include_subdomains)
	}

	// #################### api helper functions ####################

	/// return info about all blocklist
	pub(crate) async fn list<'a>(&self) -> Vec<api::List> {
		let guard = self.rw_lock.read().await;
		guard
			.block_list_info
			.iter()
			.map(|f| (f, ListType::Block))
			.chain(guard.allow_list_info.iter().map(|f| (f, ListType::Allow)))
			.map(|(list, tipe)| {
				if let Some(errors) = &list.errors {
					api::List::UpdateFailed(api::UpdateFailedList {
						len: list.len,
						url: list.url.to_owned(),
						errors: errors.to_owned(),
						tipe
					})
				} else {
					api::List::Ok(api::OkList {
						len: list.len,
						url: list.url.to_owned(),
						tipe
					})
				}
			})
			.chain(
				guard
					.failed_lists
					.iter()
					.map(|f| api::List::Error(f.clone()))
			)
			.collect()
	}

	pub(crate) async fn len(&self) -> usize {
		self.rw_lock.read().await.trie.len()
	}

	/// querry all block and allow entrys assiated with `domain` including subdomains.
	/// retrun the listinfo, allowed_state and start pos of the match
	pub(crate) async fn query(&self, domain: &str) -> HashMap<String, QueryInfo> {
		let guard = self.rw_lock.read().await;
		let mut hits = HashMap::new();
		for (trie_value, pos) in guard.trie.query(domain).iter() {
			let mut query_info = QueryInfo {
				lists: Vec::new(),
				allowed: trie_value.allowed
			};
			for (i, is_in) in trie_value.block_source.iter().enumerate() {
				if is_in {
					let list_info = guard.block_list_info.get(i).unwrap();
					query_info.lists.push(list_info.url.clone());
				}
			}
			hits.insert((domain[*pos ..]).to_owned(), query_info);
		}
		hits
	}
}

#[derive(Debug, poem_openapi::Object)]
pub(crate) struct QueryInfo {
	/// url of the blocklists, which blocks the domain
	lists: Vec<String>,
	/// indicate if the access to the matched domain is blocked
	/// or was allowed by a allowlist
	allowed: bool
}
