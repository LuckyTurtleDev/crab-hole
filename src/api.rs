use crate::{BLOCKLIST_LEN, QUERIES_ALL, QUERIES_BLOCKED, RUNNING_SINCE};
use gotham_restful::{
	gotham::{pipeline::PipelineHandleChain, router::builder::ScopeBuilder},
	read_all, DrawResourcesWithSchema as _, GetOpenapi as _, OpenapiInfo, Resource,
	Success, WithOpenapi as _
};
use openapi_type::OpenapiType;
use serde::{Deserialize, Serialize};
use std::{panic::RefUnwindSafe, sync::atomic::Ordering};
use time::OffsetDateTime;

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
	/// The timestamp when the server was started.
	running_since: OffsetDateTime,
	/// The count of all entries on the blocklist.
	blocklist_len: usize,
	/// The percentage of all queries that were blocked.
	percentage_blocked: f64
}

#[read_all]
fn stats() -> Success<Stats> {
	let queries_blocked = QUERIES_BLOCKED.load(Ordering::Relaxed);
	let queries_all = QUERIES_ALL.load(Ordering::Relaxed);
	Stats {
		running_since: *RUNNING_SINCE,
		blocklist_len: BLOCKLIST_LEN.load(Ordering::Relaxed),
		percentage_blocked: (queries_all != 0)
			.then_some(queries_blocked as f64 / queries_all as f64)
			.unwrap_or_default()
	}
	.into()
}
