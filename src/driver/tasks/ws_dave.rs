use bytes::Bytes;
#[cfg(feature = "dave-e2ee")]
use davey::{DaveSession, MediaType, ProposalsOperationType, DAVE_PROTOCOL_VERSION};
use serde::Deserialize;
use serde_json::Value;
#[cfg(feature = "dave-e2ee")]
use std::num::NonZeroU16;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug)]
pub(crate) struct BinaryGatewayPacket {
    pub(crate) sequence: Option<u16>,
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

pub(crate) type SharedDaveState = Arc<Mutex<DaveState>>;

pub(crate) fn new_shared_state() -> SharedDaveState {
    Arc::new(Mutex::new(DaveState::default()))
}

#[derive(Debug, Default)]
pub(crate) struct DaveState {
    pub(crate) protocol_version: Option<u16>,
    pub(crate) epoch: Option<u64>,
    pub(crate) transition_id: Option<u32>,
    pub(crate) awaiting_transition_execute: bool,
    pub(crate) last_binary_sequence: Option<u16>,
    pub(crate) local_user_id: Option<u64>,
    pub(crate) local_channel_id: Option<u64>,
    pub(crate) seen_prepare_transition: bool,
    pub(crate) seen_prepare_epoch: bool,
    pub(crate) seen_external_sender: bool,

    #[cfg(feature = "dave-e2ee")]
    session: Option<DaveSession>,
    #[cfg(feature = "dave-e2ee")]
    pending_key_package: Option<Bytes>,

    pending_outbound: VecDeque<DaveOutboundMessage>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct DavePrepareTransition {
    #[serde(alias = "transitionId")]
    pub(crate) transition_id: u32,
    #[serde(alias = "protocolVersion")]
    pub(crate) protocol_version: u16,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct DaveExecuteTransition {
    #[serde(alias = "transitionId")]
    pub(crate) transition_id: u32,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct DavePrepareEpoch {
    #[serde(alias = "transitionId")]
    pub(crate) transition_id: u32,
    #[serde(alias = "protocolVersion")]
    pub(crate) protocol_version: u16,
    pub(crate) epoch: u64,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct DaveInvalidCommitWelcome {
    #[serde(alias = "transitionId")]
    pub(crate) transition_id: u32,
}

impl DaveState {
    pub(crate) fn set_local_ids(&mut self, user_id: u64, channel_id: u64) {
        self.local_user_id = Some(user_id);
        self.local_channel_id = Some(channel_id);
    }

    pub(crate) fn on_prepare_transition(&mut self, msg: DavePrepareTransition) {
        self.seen_prepare_transition = true;
        if let Some(current) = self.transition_id {
            if msg.transition_id < current {
                return;
            }
        }

        self.transition_id = Some(msg.transition_id);
        self.protocol_version = Some(msg.protocol_version);
        self.awaiting_transition_execute = true;

        #[cfg(feature = "dave-e2ee")]
        if let Some(session) = self.session.as_mut() {
            session.set_passthrough_mode(true, Some(10));
        }
    }

    pub(crate) fn on_execute_transition(&mut self, msg: DaveExecuteTransition) {
        if self.transition_id == Some(msg.transition_id) {
            self.awaiting_transition_execute = false;

            #[cfg(feature = "dave-e2ee")]
            if let Some(session) = self.session.as_mut() {
                session.set_passthrough_mode(false, Some(10));
            }
        }
    }

    pub(crate) fn on_prepare_epoch(
        &mut self,
        msg: DavePrepareEpoch,
        user_id: u64,
        channel_id: u64,
    ) {
        self.seen_prepare_epoch = true;
        if let Some(current) = self.transition_id {
            if msg.transition_id < current {
                return;
            }
        }

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

            let needs_fresh_session = msg.epoch == 1 || self.session.is_none();
            if needs_fresh_session {
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
                    session.set_passthrough_mode(true, Some(10));
                    if let Ok(key_package) = session.create_key_package() {
                        self.pending_key_package = Some(Bytes::from(key_package));
                    }
                }

                self.session = session;
            } else if let Some(session) = self.session.as_mut() {
                session.set_passthrough_mode(true, Some(10));
            }
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

            #[cfg(feature = "dave-e2ee")]
            if let Some(session) = self.session.as_mut() {
                session.set_passthrough_mode(true, Some(10));
            }
        }
    }

    pub(crate) fn on_binary_packet(&mut self, packet: &BinaryGatewayPacket) {
        if let Some(sequence) = packet.sequence {
            self.last_binary_sequence = Some(sequence);
        }

        #[cfg(feature = "dave-e2ee")]
        {
            if let Some(op) = DaveBinaryOpcode::from_u8(packet.opcode) {
                if self.session.is_none() && op == DaveBinaryOpcode::MlsExternalSender {
                    if let (Some(user_id), Some(channel_id)) =
                        (self.local_user_id, self.local_channel_id)
                    {
                        let protocol =
                            NonZeroU16::new(self.protocol_version.unwrap_or(DAVE_PROTOCOL_VERSION))
                                .or_else(|| NonZeroU16::new(DAVE_PROTOCOL_VERSION))
                                .expect("non-zero dave protocol");
                        self.session = DaveSession::new(protocol, user_id, channel_id, None).ok();
                    }
                }

                if let Some(session) = self.session.as_mut() {
                    match op {
                        DaveBinaryOpcode::MlsExternalSender => {
                            self.seen_external_sender = true;
                            let _ = session.set_external_sender(&packet.payload);
                            if let Ok(key_package) = session.create_key_package() {
                                self.pending_key_package = Some(Bytes::from(key_package));
                            }
                        },
                        DaveBinaryOpcode::MlsProposals => {
                            let Some((operation_type, proposals)) =
                                decode_proposals_payload(&packet.payload)
                            else {
                                return;
                            };

                            let operation_type = if operation_type == 0 {
                                ProposalsOperationType::APPEND
                            } else {
                                ProposalsOperationType::REVOKE
                            };

                            match session.process_proposals(operation_type, proposals, None) {
                                Ok(result) => {
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

                                        self.pending_outbound.push_back(
                                            DaveOutboundMessage::Binary {
                                                opcode: 28,
                                                payload: Bytes::from(out),
                                            },
                                        );
                                    }
                                },
                                Err(_) => {
                                    if let Some(transition_id) = self.transition_id {
                                        self.pending_outbound.push_back(DaveOutboundMessage::Json {
                                            op: 31,
                                            data: serde_json::json!({ "transition_id": transition_id }),
                                        });
                                    }
                                },
                            }
                        },
                        DaveBinaryOpcode::MlsAnnounceCommitTransition => {
                            let Some((transition_id, commit)) =
                                decode_transition_payload(&packet.payload)
                            else {
                                return;
                            };
                            let transition_id = transition_id as u32;
                            if let Some(current) = self.transition_id {
                                if current != transition_id {
                                    self.pending_outbound.push_back(DaveOutboundMessage::Json {
                                        op: 31,
                                        data: serde_json::json!({ "transition_id": transition_id }),
                                    });
                                    return;
                                }
                            } else {
                                self.transition_id = Some(transition_id);
                            }

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
                            let Some((transition_id, welcome)) =
                                decode_transition_payload(&packet.payload)
                            else {
                                return;
                            };
                            let transition_id = transition_id as u32;
                            if let Some(current) = self.transition_id {
                                if current != transition_id {
                                    self.pending_outbound.push_back(DaveOutboundMessage::Json {
                                        op: 31,
                                        data: serde_json::json!({ "transition_id": transition_id }),
                                    });
                                    return;
                                }
                            } else {
                                self.transition_id = Some(transition_id);
                            }

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

    #[cfg(feature = "dave-e2ee")]
    pub(crate) fn decrypt_opus_for_user(&mut self, user_id: u64, packet: &[u8]) -> Option<Vec<u8>> {
        let session = self.session.as_mut()?;
        if !session.is_ready() {
            return None;
        }

        session.decrypt(user_id, MediaType::AUDIO, packet).ok()
    }

    #[cfg(feature = "dave-e2ee")]
    pub(crate) fn dave_ready(&self) -> bool {
        self.session.as_ref().map(|s| s.is_ready()).unwrap_or(false)
    }

    #[cfg(feature = "dave-e2ee")]
    pub(crate) fn encrypt_opus_for_self(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let session = self.session.as_mut()?;
        if !session.is_ready() {
            return None;
        }

        session
            .encrypt_opus(packet)
            .ok()
            .map(|cow| cow.into_owned())
    }

    pub(crate) fn take_pending_outbound(&mut self) -> Option<DaveOutboundMessage> {
        self.pending_outbound.pop_front()
    }

    pub(crate) fn handshake_status(&self) -> (&'static str, bool, bool, bool) {
        let phase = if self.awaiting_transition_execute {
            "awaiting_execute"
        } else if self.transition_id.is_some() {
            "transitioning"
        } else {
            "idle"
        };
        (
            phase,
            self.seen_prepare_transition,
            self.seen_prepare_epoch,
            self.seen_external_sender,
        )
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

/// Client->gateway binary framing differs by opcode in DAVE:
/// - 26 (key_package) and 28 (commit_welcome) are sent without sequence prefix.
/// - sequence-prefixed framing is retained for other opcodes for forward compatibility.
pub(crate) fn encode_client_binary_packet(sequence: u16, opcode: u8, payload: &[u8]) -> Bytes {
    if opcode == 26 || opcode == 28 {
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(opcode);
        out.extend_from_slice(payload);
        Bytes::from(out)
    } else {
        encode_binary_gateway_packet(sequence, opcode, payload)
    }
}

pub(crate) fn encode_proposals_payload(operation_type: u8, proposals: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(1 + proposals.len());
    out.push(operation_type);
    out.extend_from_slice(proposals);
    Bytes::from(out)
}

pub(crate) fn decode_proposals_payload(payload: &[u8]) -> Option<(u8, &[u8])> {
    if payload.is_empty() {
        None
    } else {
        Some((payload[0], &payload[1..]))
    }
}

pub(crate) fn encode_transition_payload(transition_id: u16, body: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&transition_id.to_be_bytes());
    out.extend_from_slice(body);
    Bytes::from(out)
}

pub(crate) fn decode_transition_payload(payload: &[u8]) -> Option<(u16, &[u8])> {
    if payload.len() < 2 {
        None
    } else {
        let transition_id = u16::from_be_bytes([payload[0], payload[1]]);
        Some((transition_id, &payload[2..]))
    }
}

pub(crate) fn parse_binary_gateway_packet(buf: &[u8]) -> Option<BinaryGatewayPacket> {
    if buf.is_empty() {
        return None;
    }

    // Observed wire variants in the field:
    // 1) opcode + payload
    // 2) u16 sequence + opcode + payload
    if matches!(buf[0], 25 | 26 | 27 | 28 | 29 | 30) {
        return Some(BinaryGatewayPacket {
            sequence: None,
            opcode: buf[0],
            payload: Bytes::copy_from_slice(&buf[1..]),
        });
    }

    if buf.len() < 3 {
        return None;
    }

    let sequence = u16::from_be_bytes([buf[0], buf[1]]);
    let opcode = buf[2];
    let payload = Bytes::copy_from_slice(&buf[3..]);

    Some(BinaryGatewayPacket {
        sequence: Some(sequence),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_packet_encoding_for_key_package_and_commit_welcome_has_no_sequence() {
        let payload = [1u8, 2, 3, 4];
        let key_pkg = encode_client_binary_packet(0x1234, 26, &payload);
        assert_eq!(key_pkg.as_ref(), &[26, 1, 2, 3, 4]);

        let commit_welcome = encode_client_binary_packet(0x5678, 28, &payload);
        assert_eq!(commit_welcome.as_ref(), &[28, 1, 2, 3, 4]);
    }

    #[test]
    fn gateway_packet_encoding_for_other_opcodes_keeps_sequence() {
        let payload = [9u8, 8, 7];
        let out = encode_client_binary_packet(0x0102, 29, &payload);
        assert_eq!(out.as_ref(), &[0x01, 0x02, 29, 9, 8, 7]);
    }

    #[test]
    fn proposals_payload_roundtrip() {
        let proposals = [0xAAu8, 0xBB, 0xCC];
        let encoded = encode_proposals_payload(0, &proposals);
        let decoded = decode_proposals_payload(&encoded).expect("decode proposals payload");
        assert_eq!(decoded.0, 0);
        assert_eq!(decoded.1, proposals);
    }

    #[test]
    fn transition_payload_roundtrip() {
        let body = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let encoded = encode_transition_payload(0x1234, &body);
        let decoded = decode_transition_payload(&encoded).expect("decode transition payload");
        assert_eq!(decoded.0, 0x1234);
        assert_eq!(decoded.1, body);
    }

    #[test]
    fn transition_decode_rejects_short_payload() {
        assert!(decode_transition_payload(&[]).is_none());
        assert!(decode_transition_payload(&[0x12]).is_none());
    }
}
