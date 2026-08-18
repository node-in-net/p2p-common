//! Application-layer chunk framing & reassembly for P2P DataChannel messages.
//!
//! WebRTC DataChannels run on top of SCTP, whose per-message receive buffer is
//! capped on many stacks (commonly 16-64 KB). To stay safely below that limit we
//! split every BSON `P2pMessage` into length-prefixed chunks before writing them
//! to the channel, and reassemble them on receipt.
//!
//! Wire format of a single chunk (exactly one DataChannel message):
//! ```text
//! [ len: u16 big-endian ][ payload: `len` bytes ]
//! ```
//! A logical message is complete when a chunk arrives whose `len` is **less
//! than** the negotiated max chunk payload (a short final chunk), OR — when the
//! payload length is an exact multiple of the max chunk size — when a terminator
//! chunk with `len == 0` arrives.
//!
//! IMPORTANT: reassembly assumes the chunks of a given logical message arrive
//! **contiguously and in order** on the channel. If two producers frame and write
//! messages to the same channel concurrently, their chunks interleave and corrupt
//! each other (see `tests::interleaved_writers_corrupt_stream`). Callers must
//! serialize writes to a single DataChannel.

/// Default max chunk payload used when the peer has not negotiated one yet.
pub const DEFAULT_MAX_CHUNK_PAYLOAD: usize = 10240;

/// Split `data` into wire-ready framed chunks of at most `max_chunk_payload`
/// bytes of payload each.
///
/// Mirrors the framing performed on the send path, including the trailing
/// zero-length terminator chunk emitted when `data.len()` is an exact multiple of
/// `max_chunk_payload` (so the receiver can tell the message ended even though the
/// final real chunk was full-size).
pub fn frame_chunks(data: &[u8], max_chunk_payload: usize) -> Vec<Vec<u8>> {
    let max = max_chunk_payload.max(1);
    let mut out = Vec::new();
    let full_len = data.len();
    let mut offset = 0;
    while offset < full_len {
        let chunk_size = std::cmp::min(max, full_len - offset);
        let chunk = &data[offset..offset + chunk_size];
        let mut frame = Vec::with_capacity(2 + chunk.len());
        frame.extend_from_slice(&(chunk_size as u16).to_be_bytes());
        frame.extend_from_slice(chunk);
        out.push(frame);
        offset += chunk_size;
    }
    // When the payload divides evenly into full chunks the receiver never sees a
    // short "final" chunk, so emit an explicit terminator.
    if full_len.is_multiple_of(max) {
        out.push(vec![0u8, 0u8]);
    }
    out
}

/// Returns `true` if `frame` is the zero-length terminator chunk produced by
/// [`frame_chunks`]. A real chunk always carries at least one payload byte, so it
/// is never only two bytes long.
pub fn is_terminator(frame: &[u8]) -> bool {
    frame.len() == 2 && frame[0] == 0 && frame[1] == 0
}

/// Outcome of feeding one received chunk into a [`ChunkAssembler`].
#[derive(Debug, PartialEq, Eq)]
pub enum ChunkOutcome {
    /// Chunk buffered; the logical message is not yet complete.
    Incomplete,
    /// A full logical message has been reassembled.
    Complete(Vec<u8>),
    /// Chunk ignored (empty frame, or a terminator with nothing buffered).
    Ignored,
    /// Frame was shorter than the 2-byte length header. Carries the frame length.
    TooSmall(usize),
    /// The declared length exceeds the bytes actually present in the frame; the
    /// in-progress buffer has been reset. `available` is the payload bytes present.
    LengthMismatch { declared: usize, available: usize },
}

/// Stateful reassembler for one DataChannel's inbound framed chunks.
///
/// Feed each received DataChannel message to [`push`](Self::push) in arrival
/// order. See the module docs for the wire format and the interleaving caveat.
#[derive(Default)]
pub struct ChunkAssembler {
    buf: Vec<u8>,
}

impl ChunkAssembler {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Bytes currently buffered for the in-progress message.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Feed one received chunk in arrival order.
    ///
    /// `max_chunk_payload` is the currently negotiated max payload size; a chunk
    /// carrying fewer than that many bytes marks the final chunk of a message. A
    /// value of `0` is treated as [`DEFAULT_MAX_CHUNK_PAYLOAD`], matching the
    /// send path's fallback.
    pub fn push(&mut self, data: &[u8], max_chunk_payload: usize) -> ChunkOutcome {
        if data.is_empty() {
            return ChunkOutcome::Ignored;
        }
        if data.len() < 2 {
            return ChunkOutcome::TooSmall(data.len());
        }

        let chunk_len = u16::from_be_bytes([data[0], data[1]]) as usize;

        if chunk_len == 0 {
            // Terminator for a message whose size was an exact multiple of max.
            if self.buf.is_empty() {
                return ChunkOutcome::Ignored;
            }
            return ChunkOutcome::Complete(std::mem::take(&mut self.buf));
        }

        if 2 + chunk_len > data.len() {
            self.buf.clear();
            return ChunkOutcome::LengthMismatch {
                declared: chunk_len,
                available: data.len() - 2,
            };
        }

        self.buf.extend_from_slice(&data[2..2 + chunk_len]);

        let max_c = if max_chunk_payload == 0 {
            DEFAULT_MAX_CHUNK_PAYLOAD
        } else {
            max_chunk_payload
        };
        if chunk_len < max_c {
            return ChunkOutcome::Complete(std::mem::take(&mut self.buf));
        }
        ChunkOutcome::Incomplete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed a whole framed message (as produced by `frame_chunks`) through an
    /// assembler and return the single reassembled payload.
    fn round_trip(data: &[u8], max: usize) -> Vec<u8> {
        let mut asm = ChunkAssembler::new();
        let mut completed: Vec<Vec<u8>> = Vec::new();
        for frame in frame_chunks(data, max) {
            match asm.push(&frame, max) {
                ChunkOutcome::Complete(msg) => completed.push(msg),
                ChunkOutcome::Incomplete | ChunkOutcome::Ignored => {}
                other => panic!("unexpected outcome during round trip: {:?}", other),
            }
        }
        assert_eq!(
            completed.len(),
            1,
            "expected exactly one reassembled message, got {}",
            completed.len()
        );
        completed.pop().unwrap()
    }

    #[test]
    fn round_trip_small_single_chunk() {
        let msg = b"hello world";
        assert_eq!(round_trip(msg, DEFAULT_MAX_CHUNK_PAYLOAD), msg);
    }

    #[test]
    fn round_trip_multi_chunk() {
        let msg: Vec<u8> = (0..25_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(round_trip(&msg, DEFAULT_MAX_CHUNK_PAYLOAD), msg);
    }

    #[test]
    fn round_trip_exact_multiple_needs_terminator() {
        // Exactly two full chunks: the receiver only learns the message ended via
        // the zero-length terminator, since no short final chunk is ever sent.
        let max = 100;
        let msg: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let frames = frame_chunks(&msg, max);
        assert_eq!(frames.len(), 3, "2 full chunks + terminator");
        assert!(is_terminator(frames.last().unwrap()));
        assert_eq!(round_trip(&msg, max), msg);
    }

    #[test]
    fn empty_message_yields_no_payload() {
        let mut asm = ChunkAssembler::new();
        let frames = frame_chunks(&[], DEFAULT_MAX_CHUNK_PAYLOAD);
        // Empty input frames to just a terminator, which the assembler ignores.
        assert_eq!(frames, vec![vec![0u8, 0u8]]);
        assert_eq!(
            asm.push(&frames[0], DEFAULT_MAX_CHUNK_PAYLOAD),
            ChunkOutcome::Ignored
        );
    }

    #[test]
    fn too_small_frame_is_reported() {
        let mut asm = ChunkAssembler::new();
        assert_eq!(asm.push(&[0x7f], 10240), ChunkOutcome::TooSmall(1));
    }

    #[test]
    fn length_mismatch_resets_buffer() {
        let mut asm = ChunkAssembler::new();
        // Declares 500 payload bytes but only 3 are present.
        let mut bad = 500u16.to_be_bytes().to_vec();
        bad.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            asm.push(&bad, 10240),
            ChunkOutcome::LengthMismatch {
                declared: 500,
                available: 3
            }
        );
        assert_eq!(asm.buffered_len(), 0, "buffer must be dropped on mismatch");
    }

    /// Regression / characterization test for the concurrent-writer hazard.
    ///
    /// The assembler is a single-stream reassembler: it has no message IDs, so if
    /// the chunks of two different messages interleave on the wire (which happens
    /// when two tasks call the send path on the same DataChannel without a shared
    /// lock), a short chunk of message B is mistaken for the final chunk of
    /// message A. The result is a corrupted payload — never the two clean
    /// originals. This documents *why* writes to a channel must be serialized.
    #[test]
    fn interleaved_writers_corrupt_stream() {
        let max = 10240;
        // Message A: large, multi-chunk. Message B: small, single-chunk (like a Ping).
        let msg_a: Vec<u8> = vec![0xAA; max * 2 + 10];
        let msg_b: Vec<u8> = vec![0xBB; 32];

        let frames_a = frame_chunks(&msg_a, max);
        let frames_b = frame_chunks(&msg_b, max);
        assert!(frames_a.len() >= 3, "A should be several chunks");
        assert_eq!(frames_b.len(), 1, "B is one short chunk");

        // Interleave: A's first full chunk, then all of B, then the rest of A —
        // exactly the ordering produced when a Ping fires mid-transmission.
        let mut wire: Vec<Vec<u8>> = Vec::new();
        wire.push(frames_a[0].clone());
        wire.extend(frames_b.iter().cloned());
        wire.extend(frames_a[1..].iter().cloned());

        let mut asm = ChunkAssembler::new();
        let mut completed: Vec<Vec<u8>> = Vec::new();
        for frame in &wire {
            if let ChunkOutcome::Complete(msg) = asm.push(frame, max) {
                completed.push(msg);
            }
        }

        // The clean, correct originals must NOT both survive interleaving.
        assert!(
            !completed.contains(&msg_a) || !completed.contains(&msg_b),
            "interleaving unexpectedly preserved both messages; \
             the corruption hazard this test guards may have changed"
        );
        // Specifically, message B's short chunk prematurely completes A's buffer,
        // so the first reassembled message is A's prefix glued to B — not msg_a.
        assert_ne!(
            completed.first(),
            Some(&msg_a),
            "first completed message should be corrupted, not a clean msg_a"
        );
    }
}
