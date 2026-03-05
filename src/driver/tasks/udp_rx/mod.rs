mod decode_sizes;
mod playout_buffer;
mod ssrc_state;

use self::{decode_sizes::*, playout_buffer::*, ssrc_state::*};

use super::{message::*, ws_dave::SharedDaveState};
use crate::driver::CryptoMode;
use crate::{
    constants::*,
    driver::crypto::Cipher,
    events::{context_data::VoiceTick, internal_data::*, CoreContext},
    Config,
};
use bytes::BytesMut;
use discortp::{
    demux::{self, DemuxedMut},
    rtp::RtpPacket,
    MutablePacket, Packet,
};
use flume::Receiver;
use std::{
    collections::{HashMap, HashSet},
    num::Wrapping,
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, select, time::Instant};
use tracing::{debug, error, instrument, trace, warn};

type RtpSequence = Wrapping<u16>;
type RtpTimestamp = Wrapping<u32>;
type RtpSsrc = u32;

#[derive(Debug, Default)]
struct UdpRxStats {
    udp_packets: u64,
    rtp_packets: u64,
    rtcp_packets: u64,
    demux_fail_parse: u64,
    demux_too_small: u64,
    dave_decrypt_success: u64,
    dave_decrypt_fail_ready: u64,
    dave_decrypt_skip_not_ready: u64,
    decode_errors: u64,
}

struct UdpRx {
    cipher: Cipher,
    crypto_mode: CryptoMode,
    decoder_map: HashMap<RtpSsrc, SsrcState>,
    config: Config,
    rx: Receiver<UdpRxMessage>,
    ssrc_signalling: Arc<SsrcTracker>,
    dave_state: SharedDaveState,
    udp_socket: UdpSocket,
    stats: UdpRxStats,
    last_stats_report: Instant,
}

impl UdpRx {
    #[instrument(skip(self))]
    async fn run(&mut self, interconnect: &mut Interconnect) {
        let mut cleanup_time = Instant::now();
        let mut playout_time = Instant::now() + TIMESTEP_LENGTH;
        let mut byte_dest: Option<BytesMut> = None;

        loop {
            if byte_dest.is_none() {
                byte_dest = Some(BytesMut::zeroed(VOICE_PACKET_MAX));
            }

            select! {
                Ok((len, _addr)) = self.udp_socket.recv_from(byte_dest.as_mut().unwrap()) => {
                    let mut pkt = byte_dest.take().unwrap();
                    pkt.truncate(len);

                    self.process_udp_message(interconnect, pkt);
                },
                msg = self.rx.recv_async() => {
                    match msg {
                        Ok(UdpRxMessage::ReplaceInterconnect(i)) => {
                            *interconnect = i;
                        },
                        Ok(UdpRxMessage::SetConfig(c)) => {
                            let old_coder = (self.config.decode_channels, self.config.decode_sample_rate);
                            let new_coder = (c.decode_channels, c.decode_sample_rate);
                            self.config = c;

                            if old_coder != new_coder {
                                self.decoder_map.values_mut().for_each(|v| v.reconfigure_decoder(&self.config));
                            }
                        },
                        Err(flume::RecvError::Disconnected) => break,
                    }
                },
                () = tokio::time::sleep_until(playout_time) => {
                    let mut tick = VoiceTick {
                        speaking: HashMap::new(),
                        silent: HashSet::new(),
                    };

                    for (ssrc, state) in &mut self.decoder_map {
                        match state.get_voice_tick(&self.config) {
                            Ok(Some(data)) => {
                                tick.speaking.insert(*ssrc, data);
                            },
                            Ok(None) => {
                                if !state.disconnected {
                                    tick.silent.insert(*ssrc);
                                }
                            },
                            Err(e) => {
                                self.stats.decode_errors = self.stats.decode_errors.saturating_add(1);
                                debug!("Decode error for SSRC {ssrc}: {e:?}");
                                tick.silent.insert(*ssrc);
                            },
                        }
                    }

                    playout_time += TIMESTEP_LENGTH;

                    drop(interconnect.events.send(EventMessage::FireCoreEvent(CoreContext::VoiceTick(tick))));
                },
                () = tokio::time::sleep_until(cleanup_time) => {
                    // periodic cleanup.
                    let now = Instant::now();

                    // check ssrc map to see if the WS task has informed us of any disconnects.
                    loop {
                        // This is structured in an odd way to prevent deadlocks.
                        // while-let seemed to keep the dashmap iter() alive for block scope, rather than
                        // just the initialiser.
                        let id = {
                            if let Some(id) = self.ssrc_signalling.disconnected_users.iter().next().map(|v| *v.key()) {
                                id
                            } else {
                                break;
                            }
                        };

                        _ = self.ssrc_signalling.disconnected_users.remove(&id);
                        if let Some((_, ssrc)) = self.ssrc_signalling.user_ssrc_map.remove(&id) {
                            if let Some(state) = self.decoder_map.get_mut(&ssrc) {
                                // don't cleanup immediately: leave for later cycle
                                // this is key with reorder/jitter buffers where we may
                                // still need to decode post disconnect for ~0.2s.
                                state.prune_time = now + Duration::from_secs(1);
                                state.disconnected = true;
                            }
                        }
                    }

                    // now remove all dead ssrcs.
                    self.decoder_map.retain(|_, v| v.prune_time > now);

                    if now.duration_since(self.last_stats_report) >= Duration::from_secs(60) {
                        tracing::info!(
                            udp_packets = self.stats.udp_packets,
                            rtp_packets = self.stats.rtp_packets,
                            rtcp_packets = self.stats.rtcp_packets,
                            demux_fail_parse = self.stats.demux_fail_parse,
                            demux_too_small = self.stats.demux_too_small,
                            dave_decrypt_success = self.stats.dave_decrypt_success,
                            dave_decrypt_fail_ready = self.stats.dave_decrypt_fail_ready,
                            dave_decrypt_skip_not_ready = self.stats.dave_decrypt_skip_not_ready,
                            decode_errors = self.stats.decode_errors,
                            tracked_ssrcs = self.decoder_map.len(),
                            "UDP voice pipeline stats (last 60s)"
                        );
                        self.stats = UdpRxStats::default();
                        self.last_stats_report = now;
                    }

                    cleanup_time = now + Duration::from_secs(5);
                },
            }
        }
    }

    fn process_udp_message(&mut self, interconnect: &Interconnect, mut packet: BytesMut) {
        self.stats.udp_packets = self.stats.udp_packets.saturating_add(1);

        // NOTE: errors here (and in general for UDP) are not fatal to the connection.
        // Panics should be avoided due to adversarial nature of rx'd packets,
        // but correct handling should not prompt a reconnect.
        //
        // For simplicity, if the event task fails then we nominate the mixing thread
        // to rebuild their context etc. (hence, the `let _ =` statements.), as it will
        // try to make contact every 20ms.
        let crypto_mode = self.crypto_mode;

        match demux::demux_mut(packet.as_mut()) {
            DemuxedMut::Rtp(mut rtp) => {
                self.stats.rtp_packets = self.stats.rtp_packets.saturating_add(1);
                if !rtp_valid(&rtp.to_immutable()) {
                    error!("Illegal RTP message received.");
                    return;
                }

                let packet_data = if self.config.decode_mode.should_decrypt() {
                    let out = self
                        .cipher
                        .decrypt_rtp_in_place(&mut rtp)
                        .map(|(s, t)| (s, t, true));

                    if let Err(ref e) = out {
                        warn!("RTP decryption failed: {:?}", e);
                    }

                    out.ok()
                } else {
                    None
                };

                let mut rtp_body_start = crypto_mode.payload_prefix_len();
                let mut rtp_body_tail = crypto_mode.payload_suffix_len();
                let mut decrypted = false;
                if let Some((s, t, d)) = packet_data {
                    rtp_body_start = s;
                    rtp_body_tail = t;
                    decrypted = d;
                }

                let sender_user_id = self.ssrc_signalling.user_ssrc_map.iter().find_map(|kv| {
                    if *kv.value() == rtp.get_ssrc() {
                        Some(kv.key().0)
                    } else {
                        None
                    }
                });

                #[cfg(feature = "dave-e2ee")]
                if let Some(user_id) = sender_user_id {
                    let (payload_len, encrypted_buf) = {
                        let payload = rtp.payload();
                        if payload.len() >= rtp_body_start + rtp_body_tail {
                            (
                                payload.len(),
                                payload[rtp_body_start..payload.len() - rtp_body_tail].to_vec(),
                            )
                        } else {
                            (0usize, Vec::new())
                        }
                    };

                    if payload_len > 0 {
                        let (dave_ready, decrypted_payload) = {
                            let mut dave = self.dave_state.lock().expect("dave mutex poisoned");
                            let ready = dave.dave_ready();
                            let out = dave.decrypt_opus_for_user(user_id, &encrypted_buf);
                            (ready, out)
                        };

                        match decrypted_payload {
                            Some(plain) => {
                                if rtp_body_start + plain.len() <= payload_len {
                                    let payload_mut = rtp.payload_mut();
                                    payload_mut[rtp_body_start..rtp_body_start + plain.len()]
                                        .copy_from_slice(&plain);
                                    rtp_body_tail = payload_len - (rtp_body_start + plain.len());
                                    decrypted = true;
                                    self.stats.dave_decrypt_success =
                                        self.stats.dave_decrypt_success.saturating_add(1);
                                    tracing::debug!(
                                        user_id,
                                        ssrc = rtp.get_ssrc(),
                                        in_len = encrypted_buf.len(),
                                        out_len = plain.len(),
                                        "DAVE inbound decrypt success"
                                    );
                                }
                            },
                            None => {
                                if dave_ready {
                                    self.stats.dave_decrypt_fail_ready =
                                        self.stats.dave_decrypt_fail_ready.saturating_add(1);
                                    tracing::debug!(
                                        user_id,
                                        ssrc = rtp.get_ssrc(),
                                        payload_len = encrypted_buf.len(),
                                        "DAVE ready but inbound decrypt failed for packet"
                                    );
                                } else {
                                    self.stats.dave_decrypt_skip_not_ready =
                                        self.stats.dave_decrypt_skip_not_ready.saturating_add(1);
                                    tracing::debug!(
                                        user_id,
                                        ssrc = rtp.get_ssrc(),
                                        dave_ready,
                                        payload_len = encrypted_buf.len(),
                                        "DAVE inbound decrypt not applied"
                                    );
                                }
                            },
                        }
                    }
                }

                let rtp = rtp.to_immutable();

                let entry = self
                    .decoder_map
                    .entry(rtp.get_ssrc())
                    .or_insert_with(|| SsrcState::new(&rtp, crypto_mode, &self.config));

                // Only do this on RTP, rather than RTCP -- this pins decoder state liveness
                // to *speech* rather than just presence.
                entry.refresh_timer(self.config.decode_state_timeout);

                let store_pkt = StoredPacket {
                    packet: packet.freeze(),
                    decrypted,
                    user_id: sender_user_id,
                };
                let packet = store_pkt.packet.clone();
                entry.store_packet(store_pkt, &self.config);

                drop(interconnect.events.send(EventMessage::FireCoreEvent(
                    CoreContext::RtpPacket(InternalRtpPacket {
                        packet,
                        payload_offset: rtp_body_start,
                        payload_end_pad: rtp_body_tail,
                    }),
                )));
            },
            DemuxedMut::Rtcp(mut rtcp) => {
                self.stats.rtcp_packets = self.stats.rtcp_packets.saturating_add(1);
                let packet_data = if self.config.decode_mode.should_decrypt() {
                    let out = self.cipher.decrypt_rtcp_in_place(&mut rtcp);

                    if let Err(ref e) = out {
                        warn!("RTCP decryption failed: {:?}", e);
                    }

                    out.ok()
                } else {
                    None
                };

                let (start, tail) = packet_data.unwrap_or_else(|| {
                    (
                        crypto_mode.payload_prefix_len(),
                        crypto_mode.payload_suffix_len(),
                    )
                });

                drop(interconnect.events.send(EventMessage::FireCoreEvent(
                    CoreContext::RtcpPacket(InternalRtcpPacket {
                        packet: packet.freeze(),
                        payload_offset: start,
                        payload_end_pad: tail,
                    }),
                )));
            },
            DemuxedMut::FailedParse(t) => {
                self.stats.demux_fail_parse = self.stats.demux_fail_parse.saturating_add(1);
                warn!("Failed to parse message of type {:?}.", t);
            },
            DemuxedMut::TooSmall => {
                self.stats.demux_too_small = self.stats.demux_too_small.saturating_add(1);
                warn!("Illegal UDP packet from voice server.");
            },
        }
    }
}

#[instrument(skip(interconnect, rx, cipher))]
pub(crate) async fn runner(
    mut interconnect: Interconnect,
    rx: Receiver<UdpRxMessage>,
    cipher: Cipher,
    crypto_mode: CryptoMode,
    config: Config,
    udp_socket: UdpSocket,
    ssrc_signalling: Arc<SsrcTracker>,
    dave_state: SharedDaveState,
) {
    trace!("UDP receive handle started.");

    let mut state = UdpRx {
        cipher,
        crypto_mode,
        decoder_map: HashMap::new(),
        config,
        rx,
        ssrc_signalling,
        dave_state,
        udp_socket,
        stats: UdpRxStats::default(),
        last_stats_report: Instant::now(),
    };

    state.run(&mut interconnect).await;

    trace!("UDP receive handle stopped.");
}

#[inline]
fn rtp_valid(packet: &RtpPacket<'_>) -> bool {
    packet.get_version() == RTP_VERSION && packet.get_payload_type() == RTP_PROFILE_TYPE
}
