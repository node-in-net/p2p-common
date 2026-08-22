//! Application-layer chunk framing & reassembly for P2P DataChannel messages.

pub const DEFAULT_MAX_CHUNK_PAYLOAD: usize = 10240;

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
    // When the payload divides evenly into full chunks the receiver never sees a short.
    if full_len.is_multiple_of(max) {
        out.push(vec![0u8, 0u8]);
    }
    out
}

pub fn is_terminator(frame: &[u8]) -> bool {
    frame.len() == 2 && frame[0] == 0 && frame[1] == 0
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChunkOutcome {
    Incomplete,
    Complete(Vec<u8>),
    Ignored,
    TooSmall(usize),
    LengthMismatch { declared: usize, available: usize },
}

#[derive(Default)]
pub struct ChunkAssembler {
    buf: Vec<u8>,
}

impl ChunkAssembler {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    pub fn push(&mut self, data: &[u8], max_chunk_payload: usize) -> ChunkOutcome {
        if data.is_empty() {
            return ChunkOutcome::Ignored;
        }
        if data.len() < 2 {
            return ChunkOutcome::TooSmall(data.len());
        }

        let chunk_len = u16::from_be_bytes([data[0], data[1]]) as usize;

        if chunk_len == 0 {
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

    #[test]
    fn interleaved_writers_corrupt_stream() {
        let max = 10240;
        let msg_a: Vec<u8> = vec![0xAA; max * 2 + 10];
        let msg_b: Vec<u8> = vec![0xBB; 32];

        let frames_a = frame_chunks(&msg_a, max);
        let frames_b = frame_chunks(&msg_b, max);
        assert!(frames_a.len() >= 3, "A should be several chunks");
        assert_eq!(frames_b.len(), 1, "B is one short chunk");

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

        assert!(
            !completed.contains(&msg_a) || !completed.contains(&msg_b),
            "interleaving unexpectedly preserved both messages; \
             the corruption hazard this test guards may have changed"
        );
        assert_ne!(
            completed.first(),
            Some(&msg_a),
            "first completed message should be corrupted, not a clean msg_a"
        );
    }
}
