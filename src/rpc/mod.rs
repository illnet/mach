pub mod event;
pub mod inspect;

use std::{sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};

use crate::{
    proxy::EventIdent,
    router::RouteReport,
    telemetry::inspect::{
        InspectRequest, ListSessionsResponse, ListStatsResponse, ListTunnelResponse,
    },
};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Id {
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Empty {}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct NonObj<T> {
    _v: T,
}

impl<T> NonObj<T> {
    pub const fn new(v: T) -> Self {
        Self { _v: v }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "_c")]
pub(crate) enum EventEnvelope {
    Hello(Empty),
    SetRoute(crate::router::Route),
    RemoveRoute(Id),
    FlushTunnelTokens(Empty),
    SetTunnelToken(crate::config::TokenEntry),
    ListRouteRequest(Empty),
    ListRouteResponse(NonObj<Vec<crate::router::Route>>),
    ListSessionsRequest(InspectRequest),
    ListSessionsResponse(ListSessionsResponse),
    ListStatsRequest(InspectRequest),
    ListStatsResponse(ListStatsResponse),
    ListTunnelRequest(InspectRequest),
    ListTunnelResponse(ListTunnelResponse),
    FlushRoute(Empty),
    HandshakeRoute(RouteReport),
    HandshakeIdent(EventIdent),
}

pub(crate) type EventServiceInstance = Arc<event::EventService<EventEnvelope, EventEnvelope>>;

pub(crate) fn init_event(url: String) -> Arc<event::EventService<EventEnvelope, EventEnvelope>> {
    let service: event::EventService<EventEnvelope, EventEnvelope> =
        event::EventService::new(url, Duration::from_secs(1));

    Arc::new(service)
}
