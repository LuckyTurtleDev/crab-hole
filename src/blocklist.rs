use crate::{trie::Trie, CLIENT, LIST_DIR};
use anyhow::Context;
use log::{error, info};
use std::path::PathBuf;
use tokio::{
	fs::{create_dir_all, read_to_string, write},
	sync::RwLock
};
use url::Url;

#[derive(Default)]
pub struct BlockList {
	trie: RwLock<Trie>
}

impl BlockList {
	pub fn new() -> Self {
		BlockList::default()
	}

	///Clear and update the current Blocklist, to all entries of the list at from `adlist`.
	///if `use_cache` is set true, cached list, will not be redownloaded (faster init)
	pub async fn update(&self, adlist: &Vec<Url>, restore_from_cache: bool) {
		if restore_from_cache {
			info!("restore blocklist, from cache");
		} else {
			info!("updating blocklist");
		}
		if let Err(err) = create_dir_all(&*LIST_DIR)
			.await
			.with_context(|| format!("failed create dir {:?}", LIST_DIR.as_path()))
		{
			error!("{err:?}");
		}
		let mut trie = Trie::new();

		for url in adlist {
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
			let raw_list = match raw_list {
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
			};
			if raw_list.is_none() {
				error!("skipp list {url}");
			}
			//TODO PRASE
		}
		info!("shrink blocklist");
		trie.shrink_to_fit();
		let mut guard = self.trie.write().await;
		*guard = trie;
		drop(guard);
		info!("finish updating blocklist");
	}

	pub async fn contains(&self, domain: &str, include_subdomains: bool) -> bool {
		self.trie.read().await.contains(domain, include_subdomains)
	}
}
