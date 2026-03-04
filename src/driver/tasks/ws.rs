use super::{
    message::*,
    ws_dave::{self, DaveState},
};
use crate::{
    events::CoreContext,
    model::{
        payload::{Heartbeat, Speaking},
        CloseCode as VoiceCloseCode, Event as GatewayEvent, FromPrimitive, SpeakingState,
    },
    ws::{Error as WsError, WsStream},
    ConnectionInfo,
};
use flume::Receiver;
use rand::{distr::Uniform, Rng};
use serde_json::Value;
#[cfg(feature = "receive")]
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    select,
    time::{sleep_until, Instant},
};
#[cfg(feature = "tungstenite")]
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tracing::{debug, info, instrument, trace, warn};

pub(crate) struct AuxNetwork {
    rx: Receiver<WsMessage>,
    ws_client: WsStream,
    dont_send: bool,

    ssrc: u32,
    heartbeat_interval: Duration,

    speaking: SpeakingState,
    last_heartbeat_nonce: Option<u64>,

    attempt_idx: usize,
    info: ConnectionInfo,

    #[cfg(feature = "receive")]
    ssrc_signalling: Arc<SsrcTracker>,

    dave_state: DaveState,
}

impl AuxNetwork {
    pub(crate) fn new(
        evt_rx: Receiver<WsMessage>,
        ws_client: WsStream,
        ssrc: u32,
        heartbeat_interval: f64,
        attempt_idx: usize,
        info: ConnectionInfo,
        #[cfg(feature = "receive")] ssrc_signalling: Arc<SsrcTracker>,
    ) -> Self {
        Self {
            rx: evt_rx,
            ws_client,
            dont_send: false,

            ssrc,
            heartbeat_interval: Duration::from_secs_f64(heartbeat_interval / 1000.0),

            speaking: SpeakingState::empty(),
            last_heartbeat_nonce: None,

            attempt_idx,
            info,

            #[cfg(feature = "receive")]
            ssrc_signalling,

            dave_state: DaveState::default(),
        }
    }

    #[instrument(skip(self))]
    async fn run(&mut self, interconnect: &mut Interconnect) {
        let mut next_heartbeat = Instant::now() + self.heartbeat_interval;

        loop {
            let mut ws_error = false;
            let mut should_reconnect = false;
            let mut ws_reason = None;

            let hb = sleep_until(next_heartbeat);

            select! {
                () = hb => {
                    ws_error = match self.send_heartbeat().await {
                        Err(e) => {
                            should_reconnect = ws_error_is_not_final(&e);
                            ws_reason = Some((&e).into());
                            true
                        },
                        _ => false,
                    };
                    next_heartbeat = self.next_heartbeat();
                }
                ws_msg = self.ws_client.recv_event_no_timeout(), if !self.dont_send => {
                    ws_error = match ws_msg {
                        Err(e) => {
                            should_reconnect = ws_error_is_not_final(&e);
                            ws_reason = Some((&e).into());
                            true
                        },
                        Ok(Some(crate::ws::GatewayMessage::Json(msg))) => {
                            self.process_ws(interconnect, msg);
                            if let Err(e) = self.flush_dave_outbound().await {
                                should_reconnect = ws_error_is_not_final(&e);
                                ws_reason = Some((&e).into());
                                true
                            } else {
                                false
                            }
                        },
                        Ok(Some(crate::ws::GatewayMessage::UnknownJson { op, data })) => {
                            self.process_ws_unknown_json(interconnect, op, data);
                            if let Err(e) = self.flush_dave_outbound().await {
                                should_reconnect = ws_error_is_not_final(&e);
                                ws_reason = Some((&e).into());
                                true
                            } else {
                                false
                            }
                        },
                        Ok(Some(crate::ws::GatewayMessage::Binary(msg))) => {
                            self.process_ws_binary(interconnect, msg);
                            if let Err(e) = self.flush_dave_outbound().await {
                                should_reconnect = ws_error_is_not_final(&e);
                                ws_reason = Some((&e).into());
                                true
                            } else {
                                false
                            }
                        },
                        _ => false,
                    };
                }
                inner_msg = self.rx.recv_async() => {
                    match inner_msg {
                        Ok(WsMessage::Ws(data)) => {
                            self.ws_client = *data;
                            next_heartbeat = self.next_heartbeat();
                            self.dont_send = false;
                        },
                        Ok(WsMessage::ReplaceInterconnect(i)) => {
                            *interconnect = i;
                        },
                        Ok(WsMessage::SetKeepalive(keepalive)) => {
                            self.heartbeat_interval = Duration::from_secs_f64(keepalive / 1000.0);
                            next_heartbeat = self.next_heartbeat();
                        },
                        Ok(WsMessage::Speaking(is_speaking)) => {
                            if self.speaking.contains(SpeakingState::MICROPHONE) != is_speaking && !self.dont_send {
                                self.speaking.set(SpeakingState::MICROPHONE, is_speaking);
                                info!("Changing to {:?}", self.speaking);

                                let ssu_status = self.ws_client
                                    .send_json(&GatewayEvent::from(Speaking {
                                        delay: Some(0),
                                        speaking: self.speaking,
                                        ssrc: self.ssrc,
                                        user_id: None,
                                    }))
                                    .await;

                                ws_error |= match ssu_status {
                                    Err(e) => {
                                        should_reconnect = ws_error_is_not_final(&e);
                                        ws_reason = Some((&e).into());
                                        true
                                    },
                                    _ => false,
                                }
                            }
                        },
                        Ok(WsMessage::Deliver(msg)) => {
                            self.process_ws(interconnect, msg);
                            if let Err(e) = self.flush_dave_outbound().await {
                                ws_error = true;
                                should_reconnect = ws_error_is_not_final(&e);
                                ws_reason = Some((&e).into());
                            }
                        },
                        Ok(WsMessage::DeliverBinary(msg)) => {
                            self.process_ws_binary(interconnect, msg);
                            if let Err(e) = self.flush_dave_outbound().await {
                                ws_error = true;
                                should_reconnect = ws_error_is_not_final(&e);
                                ws_reason = Some((&e).into());
                            }
                        },
                        Ok(WsMessage::DeliverUnknownJson { op, data }) => {
                            self.process_ws_unknown_json(interconnect, op, data);
                            if let Err(e) = self.flush_dave_outbound().await {
                                ws_error = true;
                                should_reconnect = ws_error_is_not_final(&e);
                                ws_reason = Some((&e).into());
                            }
                        },
                        Err(flume::RecvError::Disconnected) => {
                            break;
                        },
                    }
                }
            }

            if ws_error {
                self.dont_send = true;

                if should_reconnect {
                    drop(interconnect.core.send(CoreMessage::Reconnect));
                } else {
                    drop(interconnect.core.send(CoreMessage::SignalWsClosure(
                        self.attempt_idx,
                        self.info.clone(),
                        ws_reason,
                    )));
                    break;
                }
            }
        }
    }

    fn next_heartbeat(&self) -> Instant {
        Instant::now() + self.heartbeat_interval
    }

    async fn flush_dave_outbound(&mut self) -> Result<(), WsError> {
        #[cfg(feature = "dave-e2ee")]
        {
            if let Some(payload) = self.dave_state.take_pending_key_package() {
                let sequence = self
                    .dave_state
                    .last_binary_sequence
                    .unwrap_or(0)
                    .wrapping_add(1);
                let frame = ws_dave::encode_binary_gateway_packet(sequence, 26, payload.as_ref());
                self.ws_client.send_binary(frame).await?;
                self.dave_state.last_binary_sequence = Some(sequence);
                trace!(
                    sequence,
                    payload_len = payload.len(),
                    "Sent DAVE MLS key package"
                );
            }
        }

        while let Some(outbound) = self.dave_state.take_pending_outbound() {
            match outbound {
                ws_dave::DaveOutboundMessage::Json { op, data } => {
                    self.ws_client.send_json_opcode(op, &data).await?;
                    trace!(op, data = %data, "Sent DAVE JSON gateway message");
                },
                ws_dave::DaveOutboundMessage::Binary { opcode, payload } => {
                    let sequence = self
                        .dave_state
                        .last_binary_sequence
                        .unwrap_or(0)
                        .wrapping_add(1);
                    let frame =
                        ws_dave::encode_binary_gateway_packet(sequence, opcode, payload.as_ref());
                    self.ws_client.send_binary(frame).await?;
                    self.dave_state.last_binary_sequence = Some(sequence);
                    trace!(
                        opcode,
                        sequence,
                        payload_len = payload.len(),
                        "Sent DAVE binary gateway message"
                    );
                },
            }
        }

        Ok(())
    }

    async fn send_heartbeat(&mut self) -> Result<(), WsError> {
        // Discord have suddenly, mysteriously, started rejecting
        // ints-as-strings. Keep JS happy here, I suppose...
        const JS_MAX_INT: u64 = (1u64 << 53) - 1;
        let nonce_range =
            Uniform::new(0, JS_MAX_INT).expect("uniform range is finite and nonempty");
        let nonce = rand::rng().sample(nonce_range);
        self.last_heartbeat_nonce = Some(nonce);

        trace!("Sent heartbeat {:?}", self.speaking);

        if !self.dont_send {
            self.ws_client
                .send_json(&GatewayEvent::from(Heartbeat { nonce }))
                .await?;
        }

        Ok(())
    }

    fn process_ws_binary(&mut self, _interconnect: &Interconnect, payload: bytes::Bytes) {
        match ws_dave::parse_binary_gateway_packet(&payload) {
            Some(pkt) => {
                self.dave_state.on_binary_packet(&pkt);
                match ws_dave::DaveBinaryOpcode::from_u8(pkt.opcode) {
                    Some(opcode) => {
                        trace!(
                            ?opcode,
                            sequence = pkt.sequence,
                            payload_len = pkt.payload.len(),
                            "Received DAVE binary voice gateway payload"
                        );
                    },
                    None => {
                        trace!(
                            opcode = pkt.opcode,
                            sequence = pkt.sequence,
                            payload_len = pkt.payload.len(),
                            "Received non-DAVE binary voice gateway payload"
                        );
                    },
                }
            },
            None => {
                trace!(
                    len = payload.len(),
                    "Received malformed binary voice gateway payload"
                );
            },
        }
    }

    fn process_ws_unknown_json(&mut self, _interconnect: &Interconnect, op: u8, data: Value) {
        match op {
            21 => {
                if let Some(msg) = ws_dave::parse_prepare_transition(&data) {
                    self.dave_state.on_prepare_transition(msg);
                    trace!(
                        transition_id = msg.transition_id,
                        protocol_version = msg.protocol_version,
                        "Processed DAVE prepare transition"
                    );
                } else {
                    trace!(op, data = %data, "Malformed DAVE prepare transition payload");
                }
            },
            22 => {
                if let Some(msg) = ws_dave::parse_execute_transition(&data) {
                    self.dave_state.on_execute_transition(msg);
                    trace!(
                        transition_id = msg.transition_id,
                        "Processed DAVE execute transition"
                    );
                } else {
                    trace!(op, data = %data, "Malformed DAVE execute transition payload");
                }
            },
            24 => {
                if let Some(msg) = ws_dave::parse_prepare_epoch(&data) {
                    let user_id: u64 = self.info.user_id.into();
                    let channel_id: u64 = self
                        .info
                        .channel_id
                        .map(Into::into)
                        .unwrap_or_else(|| self.info.guild_id.into());
                    self.dave_state.on_prepare_epoch(msg, user_id, channel_id);
                    trace!(
                        transition_id = msg.transition_id,
                        protocol_version = msg.protocol_version,
                        epoch = msg.epoch,
                        "Processed DAVE prepare epoch"
                    );
                } else {
                    trace!(op, data = %data, "Malformed DAVE prepare epoch payload");
                }
            },
            31 => {
                if let Some(msg) = ws_dave::parse_invalid_commit_welcome(&data) {
                    self.dave_state.on_invalid_commit_welcome(msg);
                    trace!(
                        transition_id = msg.transition_id,
                        "Processed DAVE invalid commit/welcome"
                    );
                } else {
                    trace!(op, data = %data, "Malformed DAVE invalid commit/welcome payload");
                }
            },
            _ => {
                trace!(op, data = %data, "Received unknown voice gateway JSON opcode");
            },
        }
    }

    fn process_ws(&mut self, interconnect: &Interconnect, value: GatewayEvent) {
        match value {
            GatewayEvent::Speaking(ev) => {
                #[cfg(feature = "receive")]
                if let Some(user_id) = &ev.user_id {
                    self.ssrc_signalling.user_ssrc_map.insert(*user_id, ev.ssrc);
                }

                drop(interconnect.events.send(EventMessage::FireCoreEvent(
                    CoreContext::SpeakingStateUpdate(ev),
                )));
            },
            GatewayEvent::ClientConnect(ev) => {
                debug!("Received discontinued ClientConnect: {:?}", ev);
            },
            GatewayEvent::ClientDisconnect(ev) => {
                #[cfg(feature = "receive")]
                {
                    self.ssrc_signalling.disconnected_users.insert(ev.user_id);
                }

                drop(interconnect.events.send(EventMessage::FireCoreEvent(
                    CoreContext::ClientDisconnect(ev),
                )));
            },
            GatewayEvent::HeartbeatAck(ev) => {
                if let Some(nonce) = self.last_heartbeat_nonce.take() {
                    if ev.nonce == nonce {
                        trace!("Heartbeat ACK received.");
                    } else {
                        warn!(
                            "Heartbeat nonce mismatch! Expected {}, saw {}.",
                            nonce, ev.nonce
                        );
                    }
                }
            },
            other => {
                trace!("Received other websocket data: {:?}", other);
            },
        }
    }
}

#[instrument(skip(interconnect, aux))]
pub(crate) async fn runner(mut interconnect: Interconnect, mut aux: AuxNetwork) {
    trace!("WS thread started.");
    aux.run(&mut interconnect).await;
    trace!("WS thread finished.");
}

fn ws_error_is_not_final(err: &WsError) -> bool {
    match err {
        #[cfg(feature = "tungstenite")]
        WsError::WsClosed(Some(frame)) => match frame.code {
            CloseCode::Library(l) => {
                if let Some(code) = VoiceCloseCode::from_u16(l) {
                    code.should_resume()
                } else {
                    true
                }
            },
            _ => true,
        },
        #[cfg(feature = "tws")]
        WsError::WsClosed(Some(code)) => match (*code).into() {
            code @ 4000..=4999_u16 => {
                if let Some(code) = VoiceCloseCode::from_u16(code) {
                    code.should_resume()
                } else {
                    true
                }
            },
            _ => true,
        },
        e => {
            debug!("Error sending/receiving ws {:?}.", e);
            true
        },
    }
}
