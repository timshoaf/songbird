use bytes::Bytes;
#[cfg(feature = "dave-e2ee")]
use davey::{DaveSession, ProposalsOperationType, DAVE_PROTOCOL_VERSION};
use serde::Deserialize;
use serde_json::Value;
use std::collections::VecDeque;
#[cfg(feature = "dave-e2ee")]
use std::num::NonZeroU16;

#[derive(Clone, Debug)]
pub(crate) struct BinaryGatewayPacket {
    pub(crate) sequence: u16,
    pub(crate) opcode: u8,
    pub(crate) payload: Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DaveBinaryOpcode {
    MlsExternalSender = 25,
    MlsKeyPackage = 26,
    MlsProposals = 27,
    MlsCommitWelcome = 28,
    MlsAnnounceCommitTransition = 29,
    MlsWelcome = 30,
}

impl DaveBinaryOpcode {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            25 => Some(Self::MlsExternalSender),
            26 => Some(Self::MlsKeyPackage),
            27 => Some(Self::MlsProposals),
            28 => Some(Self::MlsCommitWelcome),
            29 => Some(Self::MlsAnnounceCommitTransition),
            30 => Some(Self::MlsWelcome),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum DaveOutboundMessage {
    Json { op: u8, data: Value },
    Binary { opcode: u8, payload: Bytes },
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DaveState {
    pub(crate) protocol_version: Option<u16>,
    pub(crate) epoch: Option<u64>,
    pub(crate) transition_id: Option<u32>,
    pub(crate) awaiting_transition_execute: bool,
    pub(crate) last_binary_sequence: Option<u16>,

    #[cfg(feature = "dave-e2ee")]
    session: Option<DaveSession>,
    #[cfg(feature = "dave-e2ee")]
    pending_key_package: Option<Bytes>,

    pending_outbound: VecDeque<DaveOutboundMessage>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct DavePrepareTransition {
    pub(crate) transition_id: u32,
    pub(crate) protocol_version: u16,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct DaveExecuteTransition {
    pub(crate) transition_id: u32,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct DavePrepareEpoch {
    pub(crate) transition_id: u32,
    pub(crate) protocol_version: u16,
    pub(crate) epoch: u64,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct DaveInvalidCommitWelcome {
    pub(crate) transition_id: u32,
}

impl DaveState {
    pub(crate) fn on_prepare_transition(&mut self, msg: DavePrepareTransition) {
        self.transition_id = Some(msg.transition_id);
        self.protocol_version = Some(msg.protocol_version);
        self.awaiting_transition_execute = true;
    }

    pub(crate) fn on_execute_transition(&mut self, msg: DaveExecuteTransition) {
        if self.transition_id == Some(msg.transition_id) {
            self.awaiting_transition_execute = false;
        }
    }

    pub(crate) fn on_prepare_epoch(
        &mut self,
        msg: DavePrepareEpoch,
        user_id: u64,
        channel_id: u64,
    ) {
        let previous_epoch = self.epoch;
        self.transition_id = Some(msg.transition_id);
        self.protocol_version = Some(msg.protocol_version);
        self.epoch = Some(msg.epoch);

        #[cfg(feature = "dave-e2ee")]
        {
            // Protocol version 0 means transport-only mode; no DAVE session needed.
            if msg.protocol_version == 0 {
                self.session = None;
                self.pending_key_package = None;
                return;
            }

            let protocol = NonZeroU16::new(msg.protocol_version)
                .or_else(|| NonZeroU16::new(DAVE_PROTOCOL_VERSION))
                .expect("DAVE protocol version constant must be non-zero");

            let mut session = DaveSession::new(protocol, user_id, channel_id, None)
                .or_else(|_| {
                    DaveSession::new(
                        NonZeroU16::new(DAVE_PROTOCOL_VERSION).expect("non-zero"),
                        user_id,
                        channel_id,
                        None,
                    )
                })
                .ok();

            if let Some(ref mut session) = session {
                if let Ok(key_package) = session.create_key_package() {
                    self.pending_key_package = Some(Bytes::from(key_package));
                }
            }

            self.session = session;
        }

        // If this protocol transition keeps the same epoch, there is no commit/welcome
        // roundtrip and we can immediately signal readiness once local state is prepared.
        if previous_epoch == Some(msg.epoch) {
            self.pending_outbound.push_back(DaveOutboundMessage::Json {
                op: 23,
                data: serde_json::json!({ "transition_id": msg.transition_id }),
            });
        }
    }

    pub(crate) fn on_invalid_commit_welcome(&mut self, msg: DaveInvalidCommitWelcome) {
        if self.transition_id == Some(msg.transition_id) {
            self.awaiting_transition_execute = false;
        }
    }

    pub(crate) fn on_binary_packet(&mut self, packet: &BinaryGatewayPacket) {
        self.last_binary_sequence = Some(packet.sequence);

        #[cfg(feature = "dave-e2ee")]
        {
            if let Some(op) = DaveBinaryOpcode::from_u8(packet.opcode) {
                if let Some(session) = self.session.as_mut() {
                    match op {
                        DaveBinaryOpcode::MlsExternalSender => {
                            let _ = session.set_external_sender(&packet.payload);
                            if let Ok(key_package) = session.create_key_package() {
                                self.pending_key_package = Some(Bytes::from(key_package));
                            }
                        },
                        DaveBinaryOpcode::MlsProposals => {
                            if packet.payload.is_empty() {
                                return;
                            }

                            let operation_type = if packet.payload[0] == 0 {
                                ProposalsOperationType::APPEND
                            } else {
                                ProposalsOperationType::REVOKE
                            };
                            let proposals = &packet.payload[1..];

                            if let Ok(result) =
                                session.process_proposals(operation_type, proposals, None)
                            {
                                if let Some(commit_welcome) = result {
                                    let mut out = Vec::with_capacity(
                                        commit_welcome.commit.len()
                                            + commit_welcome
                                                .welcome
                                                .as_ref()
                                                .map_or(0, |w| w.len()),
                                    );
                                    out.extend_from_slice(&commit_welcome.commit);
                                    if let Some(welcome) = commit_welcome.welcome {
                                        out.extend_from_slice(&welcome);
                                    }

                                    self.pending_outbound
                                        .push_back(DaveOutboundMessage::Binary {
                                            opcode: 28,
                                            payload: Bytes::from(out),
                                        });
                                }
                            }
                        },
                        DaveBinaryOpcode::MlsAnnounceCommitTransition => {
                            if packet.payload.len() < 2 {
                                return;
                            }
                            let transition_id =
                                u16::from_be_bytes([packet.payload[0], packet.payload[1]]) as u32;
                            let commit = &packet.payload[2..];
                            match session.process_commit(commit) {
                                Ok(()) => {
                                    self.pending_outbound.push_back(DaveOutboundMessage::Json {
                                        op: 23,
                                        data: serde_json::json!({ "transition_id": transition_id }),
                                    });
                                },
                                Err(_) => {
                                    self.pending_outbound.push_back(DaveOutboundMessage::Json {
                                        op: 31,
                                        data: serde_json::json!({ "transition_id": transition_id }),
                                    });
                                },
                            }
                        },
                        DaveBinaryOpcode::MlsWelcome => {
                            if packet.payload.len() < 2 {
                                return;
                            }
                            let transition_id =
                                u16::from_be_bytes([packet.payload[0], packet.payload[1]]) as u32;
                            let welcome = &packet.payload[2..];
                            match session.process_welcome(welcome) {
                                Ok(()) => {
                                    self.pending_outbound.push_back(DaveOutboundMessage::Json {
                                        op: 23,
                                        data: serde_json::json!({ "transition_id": transition_id }),
                                    });
                                },
                                Err(_) => {
                                    self.pending_outbound.push_back(DaveOutboundMessage::Json {
                                        op: 31,
                                        data: serde_json::json!({ "transition_id": transition_id }),
                                    });
                                },
                            }
                        },
                        DaveBinaryOpcode::MlsCommitWelcome | DaveBinaryOpcode::MlsKeyPackage => {
                            // Outbound-only from client for normal flow.
                        },
                    }
                }
            }
        }
    }

    #[cfg(feature = "dave-e2ee")]
    pub(crate) fn take_pending_key_package(&mut self) -> Option<Bytes> {
        self.pending_key_package.take()
    }

    pub(crate) fn take_pending_outbound(&mut self) -> Option<DaveOutboundMessage> {
        self.pending_outbound.pop_front()
    }
}

/// Voice gateway DAVE/MLS binary frame format:
/// - u16 sequence (big-endian)
/// - u8 opcode
/// - remaining bytes = payload
pub(crate) fn encode_binary_gateway_packet(sequence: u16, opcode: u8, payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(3 + payload.len());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.push(opcode);
    out.extend_from_slice(payload);
    Bytes::from(out)
}

pub(crate) fn parse_binary_gateway_packet(buf: &[u8]) -> Option<BinaryGatewayPacket> {
    if buf.len() < 3 {
        return None;
    }

    let sequence = u16::from_be_bytes([buf[0], buf[1]]);
    let opcode = buf[2];
    let payload = Bytes::copy_from_slice(&buf[3..]);

    Some(BinaryGatewayPacket {
        sequence,
        opcode,
        payload,
    })
}

pub(crate) fn parse_prepare_transition(data: &Value) -> Option<DavePrepareTransition> {
    serde_json::from_value(data.clone()).ok()
}

pub(crate) fn parse_execute_transition(data: &Value) -> Option<DaveExecuteTransition> {
    serde_json::from_value(data.clone()).ok()
}

pub(crate) fn parse_prepare_epoch(data: &Value) -> Option<DavePrepareEpoch> {
    serde_json::from_value(data.clone()).ok()
}

pub(crate) fn parse_invalid_commit_welcome(data: &Value) -> Option<DaveInvalidCommitWelcome> {
    serde_json::from_value(data.clone()).ok()
}
