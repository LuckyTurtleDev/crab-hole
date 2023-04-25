use crate::{trie::Trie, CLIENT};
use std::path::PathBuf;
use tokio::{
	fs::{read_to_string, write},
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
	pub async fn update(&self, adlist: &Vec<Url>, use_cache: bool) {
		if use_cache {
			println!("updating blocklist, using cache");
		} else {
			println!("upading blocklist");
		}
		let mut trie = Trie::new();

		for url in adlist {
			let mut path = url.path().to_owned().replace('/', "-");
			if !path.is_empty() {
				path.remove(0); // remove first
			}
			if let Some(query) = url.query() {
				path += "--";
				path += query;
			}
			let path = PathBuf::from("./data").join(path); //TODO: make this config able and create path
			let raw_list = if path.exists() && use_cache {
				println!("use cache for {url}");
				read_to_string(path).await.unwrap()
			} else {
				println!("download {url}");
				let resp = CLIENT
					.get(url.to_owned())
					.send()
					.await
					.unwrap()
					.error_for_status()
					.unwrap()
					.text()
					.await
					.unwrap();
				write(path, &resp).await.unwrap();
				resp
			};
			println!("TODO prase raw_list and at to trie");
		}

		println!("shrink trie");
		trie.shrink_to_fit();
		println!("WARNING IF EMPTY");
		let mut guard = self.trie.write().await;
		*guard = trie;
		drop(guard);
		println!("shrink trie");
	}

	pub async fn contains(&self, domain: &str, include_subdomains: bool) -> bool {
		let guard = self.trie.read().await;
		guard.contains(domain, include_subdomains)
	}
}
