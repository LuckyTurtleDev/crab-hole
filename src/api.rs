use crate::{BLOCKLIST_LEN, QUERIES_ALL, QUERIES_BLOCKED};
use gotham_restful::{
	gotham::{pipeline::PipelineHandleChain, router::builder::ScopeBuilder},
	read_all, DrawResourcesWithSchema as _, GetOpenapi as _, OpenapiInfo, Resource,
	Success, WithOpenapi as _
};
use openapi_type::OpenapiType;
use serde::{Deserialize, Serialize};
use std::{panic::RefUnwindSafe, sync::atomic::Ordering};

pub(crate) fn route<C, P>(url: &str, router: &mut ScopeBuilder<'_, C, P>)
where
	C: PipelineHandleChain<P> + Copy + Send + Sync + 'static,
	P: RefUnwindSafe + Send + Sync + 'static
{
	let info = OpenapiInfo {
		title: "crab-hole API".to_owned(),
		version: "1".to_owned(),
		urls: vec![format!("{url}/v1")]
	};
	router.with_openapi(info, |mut route| {
		route.resource::<StatsResource>("/stats");

		route.openapi_spec("openapi");
		route.openapi_doc("/");
	});
}

#[derive(Resource)]
#[resource(stats)]
struct StatsResource;

#[derive(Deserialize, OpenapiType, Serialize)]
struct Stats {
	/// The count of all entries on the blocklist.
	blocklist_len: usize,
	/// The count of all queries.
	queries_all: usize,
	/// The count of all blocked queries.
	queries_blocked: usize
}

#[read_all]
fn stats() -> Success<Stats> {
	Stats {
		blocklist_len: BLOCKLIST_LEN.load(Ordering::Relaxed),
		queries_all: QUERIES_ALL.load(Ordering::Relaxed),
		queries_blocked: QUERIES_BLOCKED.load(Ordering::Relaxed)
	}
	.into()
}
