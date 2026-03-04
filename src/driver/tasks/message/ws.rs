#![allow(missing_docs)]

use bytes::Bytes;
use serde_json::Value;

use super::Interconnect;
use crate::{model::Event as GatewayEvent, ws::WsStream};

pub enum WsMessage {
    Ws(Box<WsStream>),
    ReplaceInterconnect(Interconnect),
    SetKeepalive(f64),
    Speaking(bool),
    Deliver(GatewayEvent),
    DeliverBinary(Bytes),
    DeliverUnknownJson { op: u8, data: Value },
}
