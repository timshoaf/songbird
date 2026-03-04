use bytes::Bytes;

#[derive(Clone, Debug)]
pub(crate) struct BinaryGatewayPacket {
    pub(crate) sequence: u16,
    pub(crate) opcode: u8,
    pub(crate) payload: Bytes,
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
