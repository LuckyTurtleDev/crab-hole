use crate::CrabHole;
use gotham::{
	middleware::state::StateMiddleware,
	pipeline::{single_middleware, single_pipeline, PipelineHandleChain},
	prelude::*,
	router::{build_router, builder::ScopeBuilder, Router},
	state::State
};
use gotham_restful::{
	read_all, DrawResourcesWithSchema as _, GetOpenapi as _, OpenapiInfo, Resource,
	Success, WithOpenapi as _
};
use openapi_type::OpenapiType;
use serde::{Deserialize, Serialize};
use std::{
	ops::Deref,
	panic::RefUnwindSafe,
	sync::{atomic::Ordering, Arc}
};
use time::OffsetDateTime;

#[derive(Clone, StateData)]
struct CrabHoleState(Arc<CrabHole>);

impl Deref for CrabHoleState {
	type Target = CrabHole;

	fn deref(&self) -> &Self::Target {
		self.0.deref()
	}
}

// TODO verify this
impl RefUnwindSafe for CrabHoleState {}

pub(crate) fn build_api_router(url: &str, crabhole: Arc<CrabHole>) -> Router {
	let middleware = StateMiddleware::new(CrabHoleState(crabhole));

	let pipeline = single_middleware(middleware);
	let (chain, pipelines) = single_pipeline(pipeline);

	build_router(chain, pipelines, |router| {
		router.scope("/v1", |router| {
			route_v1(url, router);
		})
	})
}

fn route_v1<C, P>(url: &str, router: &mut ScopeBuilder<'_, C, P>)
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
fn stats(state: &State) -> Success<Stats> {
	let crabhole = CrabHoleState::borrow_from(state);

	let queries_blocked = crabhole.queries_blocked.load(Ordering::Relaxed);
	let queries_all = crabhole.queries_all.load(Ordering::Relaxed);
	Stats {
		running_since: crabhole.running_since,
		blocklist_len: crabhole.blocklist_len.load(Ordering::Relaxed),
		percentage_blocked: (queries_all != 0)
			.then_some(queries_blocked as f64 / queries_all as f64)
			.unwrap_or_default()
	}
	.into()
}
