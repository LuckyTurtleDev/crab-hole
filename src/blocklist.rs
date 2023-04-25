use crate::{trie::Trie, CLIENT};
use anyhow::Context;
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
			let raw_list = if !path.exists() || !use_cache {
				println!("download {url}");
				let resp: anyhow::Result<String> = (|| async {
					//try block
					let resp = CLIENT
						.get(url.to_owned())
						.send()
						.await?
						.error_for_status()?
						.text()
						.await?;
					write(&path, &resp).await.unwrap();
					Ok(resp)
				})()
				.await;
				match resp.with_context(|| format!("error downloading {url}")) {
					Ok(value) => Some(value),
					Err(err) => {
						eprintln!("{err}");
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
						println!("use cache for {url}");
						match read_to_string(&path)
							.await
							.with_context(|| format!("error reading file {path:?}"))
						{
							Ok(value) => Some(value),
							Err(err) => {
								eprintln!("{err}");
								None
							}
						}
					} else {
						None
					}
				},
			};
			if raw_list.is_none() {
				eprintln!("skipp list {url}");
			}
			//TODO PRASE
		}
		trie.shrink_to_fit();
		println!("finish updating block list");
	}

	pub async fn contains(&self, domain: &str, include_subdomains: bool) -> bool {
		self.trie.read().await.contains(domain, include_subdomains)
	}
}
