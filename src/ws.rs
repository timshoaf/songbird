use crate::{error::JsonError, model::Event};

use bytes::Bytes;
use futures::{SinkExt, StreamExt, TryStreamExt};
use serde::Serialize;
use serde_json::Value;
use tokio::{
    net::TcpStream,
    time::{timeout, Duration},
};
#[cfg(feature = "tungstenite")]
use tokio_tungstenite::{
    tungstenite::{
        error::Error as TungsteniteError,
        protocol::{CloseFrame, WebSocketConfig as Config},
        Message,
    },
    MaybeTlsStream, WebSocketStream,
};
#[cfg(feature = "tws")]
use tokio_websockets::{
    CloseCode, Error as TwsError, Limits, MaybeTlsStream, Message, WebSocketStream,
};
use tracing::{debug, instrument, warn};
use url::Url;

pub struct WsStream(WebSocketStream<MaybeTlsStream<TcpStream>>);

#[derive(Clone, Debug)]
pub enum GatewayMessage {
    Json(Event),
    UnknownJson { op: u8, data: Value },
    Binary(Bytes),
}

impl WsStream {
    #[instrument]
    pub(crate) async fn connect(url: Url) -> Result<Self> {
        #[cfg(feature = "tungstenite")]
        let (stream, _) = tokio_tungstenite::connect_async_with_config::<Url>(
            url,
            Some(
                Config::default()
                    .max_message_size(None)
                    .max_frame_size(None),
            ),
            true,
        )
        .await?;
        #[cfg(feature = "tws")]
        let (stream, _) = tokio_websockets::ClientBuilder::new()
            .limits(Limits::unlimited())
            .uri(url.as_str())
            .unwrap() // Any valid URL is a valid URI.
            .connect()
            .await?;

        Ok(Self(stream))
    }

    pub(crate) async fn recv_event(&mut self) -> Result<Option<GatewayMessage>> {
        const TIMEOUT: Duration = Duration::from_millis(500);

        let ws_message = match timeout(TIMEOUT, self.0.next()).await {
            Ok(Some(Ok(v))) => Some(v),
            Ok(Some(Err(e))) => return Err(e.into()),
            Ok(None) | Err(_) => None,
        };

        convert_ws_message(ws_message)
    }

    pub(crate) async fn recv_event_no_timeout(&mut self) -> Result<Option<GatewayMessage>> {
        convert_ws_message(self.0.try_next().await?)
    }

    pub(crate) async fn send_json(&mut self, value: &Event) -> Result<()> {
        let res = crate::json::to_string(value);
        let res = res.map(Message::text);
        Ok(res.map_err(Error::from).map(|m| self.0.send(m))?.await?)
    }

    pub(crate) async fn send_json_opcode<T: Serialize>(&mut self, op: u8, data: &T) -> Result<()> {
        let body = serde_json::json!({ "op": op, "d": data });
        let txt = crate::json::to_string(&body)?;
        Ok(self.0.send(Message::text(txt)).await?)
    }

    pub(crate) async fn send_binary(&mut self, payload: Bytes) -> Result<()> {
        Ok(self.0.send(Message::binary(payload)).await?)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Json(JsonError),

    #[cfg(feature = "tungstenite")]
    Ws(TungsteniteError),
    #[cfg(feature = "tws")]
    Ws(TwsError),

    #[cfg(feature = "tungstenite")]
    WsClosed(Option<CloseFrame>),
    #[cfg(feature = "tws")]
    WsClosed(Option<CloseCode>),
}

impl From<JsonError> for Error {
    fn from(e: JsonError) -> Error {
        Error::Json(e)
    }
}

#[cfg(feature = "tungstenite")]
impl From<TungsteniteError> for Error {
    fn from(e: TungsteniteError) -> Error {
        Error::Ws(e)
    }
}

#[cfg(feature = "tws")]
impl From<TwsError> for Error {
    fn from(e: TwsError) -> Self {
        Error::Ws(e)
    }
}

#[inline]
pub(crate) fn convert_ws_message(message: Option<Message>) -> Result<Option<GatewayMessage>> {
    #[cfg(feature = "tungstenite")]
    let text = match message {
        Some(Message::Text(ref payload)) => {
            debug!(len = payload.len(), "WS text frame received");
            payload
        },
        Some(Message::Binary(bytes)) => {
            debug!(len = bytes.len(), "WS binary frame received");
            return Ok(Some(GatewayMessage::Binary(bytes)));
        },
        Some(Message::Close(Some(frame))) => {
            return Err(Error::WsClosed(Some(frame)));
        },
        // Ping/Pong message behaviour is internally handled by tungstenite.
        _ => return Ok(None),
    };
    #[cfg(feature = "tws")]
    let text = match message {
        Some(ref message) if message.is_text() => {
            if let Some(text) = message.as_text() {
                text
            } else {
                return Ok(None);
            }
        },
        Some(message) if message.is_binary() => {
            return Ok(Some(GatewayMessage::Binary(message.into_payload().into())));
        },
        Some(message) if message.is_close() => {
            return Err(Error::WsClosed(message.as_close().map(|(c, _)| c)));
        },
        // ping/pong; will also be internally handled by tokio-websockets.
        _ => return Ok(None),
    };

    let value = serde_json::from_str::<Value>(text).map_err(|e| {
        warn!("Unexpected JSON parse failure: {e}. Payload: {text}");
        e
    })?;

    if let Some(op) = value
        .get("op")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
    {
        debug!(op, "WS JSON opcode observed");
        if op == 4 {
            let data = value.get("d").cloned().unwrap_or(Value::Null);
            let dave_v = data
                .get("dave_protocol_version")
                .and_then(Value::as_u64)
                .or_else(|| data.get("protocol_version").and_then(Value::as_u64))
                .or_else(|| {
                    data.get("dave_protocol")
                        .and_then(|v| v.get("version"))
                        .and_then(Value::as_u64)
                });
            debug!(d = %data, ?dave_v, "WS select_protocol_ack payload observed");
            return Ok(Some(GatewayMessage::UnknownJson { op, data }));
        }

        // Force DAVE control-plane opcodes through unknown-json path so they reach
        // ws::process_ws_unknown_json even if voice-model parses them as generic events.
        if matches!(op, 18 | 20 | 21 | 22 | 24 | 31) {
            let data = value.get("d").cloned().unwrap_or(Value::Null);
            return Ok(Some(GatewayMessage::UnknownJson { op, data }));
        }
    }

    if let Ok(evt) = serde_json::from_str::<Event>(text) {
        return Ok(Some(GatewayMessage::Json(evt)));
    }

    let Some(op) = value
        .get("op")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok())
    else {
        warn!("Voice gateway JSON missing valid opcode: {value}");
        return Ok(None);
    };
    debug!(op, "WS JSON frame parsed with opcode field");
    let data = value.get("d").cloned().unwrap_or(Value::Null);

    Ok(Some(GatewayMessage::UnknownJson { op, data }))
}
