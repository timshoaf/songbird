# DAVE/E2EE support plan for Songbird

This document tracks the implementation plan required to make Songbird compatible with Discord DAVE-required voice sessions.

## Problem

Discord now enforces DAVE/E2EE in eligible voice sessions. Legacy voice websocket handling is insufficient:

- JSON opcode surface must include DAVE transition opcodes (21, 22, 23, 24, 31)
- Voice gateway binary opcode surface must include MLS frames (25, 26, 27, 28, 29, 30)
- Session transitions must be coordinated with media encrypt/decrypt ratchets

## Required work

1. **Gateway model updates (serenity-voice-model)**
   - Add DAVE opcodes and payloads.
   - Add `Identify.max_dave_protocol_version`.
   - Add `SessionDescription.dave_protocol_version`.

2. **Websocket transport updates**
   - Accept binary voice gateway frames instead of failing connection.
   - Add send path for binary frames (MLS key package/commit-welcome).
   - Route binary opcode envelope to connection state machine.

3. **DAVE state machine**
   - Maintain per-connection DAVE session state (`davey::DaveSession`).
   - Implement handling for opcodes 24/25/27/29/30 and transition control 21/22/23.
   - Implement invalid commit/welcome recovery via opcode 31.

4. **Media pipeline integration**
   - Outbound: encode opus -> davey encrypt -> transport encryption.
   - Inbound: transport decrypt -> davey decrypt (using user-id / SSRC mapping).
   - Preserve transition safety window for in-flight media.

5. **Observability and correctness**
   - Track transition_id, epoch, protocol_version and readiness states.
   - Add integration tests for JSON + binary gateway sequencing.

## PR strategy

- PR 1: model + websocket binary infrastructure (no behavior change).
- PR 2: DAVE control-plane state machine.
- PR 3: media encrypt/decrypt integration and receive path.
- PR 4: docs, migration notes, and compatibility guarantees.
