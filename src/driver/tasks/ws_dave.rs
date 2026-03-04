use bytes::Bytes;
use serde::Deserialize;
use serde_json::Value;

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

#[derive(Clone, Debug, Default)]
pub(crate) struct DaveState {
    pub(crate) protocol_version: Option<u16>,
    pub(crate) epoch: Option<u64>,
    pub(crate) transition_id: Option<u32>,
    pub(crate) awaiting_transition_execute: bool,
    pub(crate) last_binary_sequence: Option<u16>,
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

    pub(crate) fn on_prepare_epoch(&mut self, msg: DavePrepareEpoch) {
        self.transition_id = Some(msg.transition_id);
        self.protocol_version = Some(msg.protocol_version);
        self.epoch = Some(msg.epoch);
    }

    pub(crate) fn on_invalid_commit_welcome(&mut self, msg: DaveInvalidCommitWelcome) {
        if self.transition_id == Some(msg.transition_id) {
            self.awaiting_transition_execute = false;
        }
    }

    pub(crate) fn on_binary_packet(&mut self, packet: &BinaryGatewayPacket) {
        self.last_binary_sequence = Some(packet.sequence);
    }
}

/// Voice gateway DAVE/MLS binary frame format:
/// - u16 sequence (big-endian)
/// - u8 opcode
/// - remaining bytes = payload
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
