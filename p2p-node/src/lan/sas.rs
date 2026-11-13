use rand::rngs::OsRng;
use rand::RngCore as _;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;

pub const NONCE_LEN: usize = 32;

pub struct Initiator {
    h: [u8; 32],
    commit: [u8; 32],
    nonce: [u8; NONCE_LEN],
}

impl Initiator {
    pub fn new(h: [u8; 32], commit: [u8; 32]) -> Self {
        Self {
            h,
            commit,
            nonce: nonce(),
        }
    }

    pub fn nonce(&self) -> [u8; NONCE_LEN] {
        self.nonce
    }

    pub fn code(self, reveal: &[u8; NONCE_LEN]) -> Option<String> {
        opens(&self.commit, &self.h, reveal).then(|| code(&self.h, &self.nonce, reveal))
    }
}

pub struct Responder {
    h: [u8; 32],
    nonce: [u8; NONCE_LEN],
}

impl Responder {
    pub fn new(h: [u8; 32]) -> Self {
        Self { h, nonce: nonce() }
    }

    pub fn commit(&self) -> [u8; 32] {
        commitment(&self.h, &self.nonce)
    }

    pub fn reveal(self, initiator: &[u8; NONCE_LEN]) -> ([u8; NONCE_LEN], String) {
        (self.nonce, code(&self.h, initiator, &self.nonce))
    }
}

fn nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn commitment(h: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"nin-lan/1 commit")
        .chain_update(h)
        .chain_update(nonce)
        .finalize()
        .into()
}

fn opens(commit: &[u8; 32], h: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> bool {
    commitment(h, nonce).ct_eq(commit).into()
}

fn code(h: &[u8; 32], initiator: &[u8; NONCE_LEN], responder: &[u8; NONCE_LEN]) -> String {
    let hash = Sha256::new()
        .chain_update(b"nin-lan/1 sas")
        .chain_update(h)
        .chain_update(initiator)
        .chain_update(responder)
        .finalize();
    shown(u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 1_000_000)
}

fn shown(code: u32) -> String {
    format!("{:03} {:03}", code / 1000, code % 1000)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn handshake() -> ([u8; 32], [u8; 32]) {
        let params: snow::params::NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let initiator_key = snow::Builder::new(params.clone())
            .generate_keypair()
            .unwrap();
        let responder_key = snow::Builder::new(params.clone())
            .generate_keypair()
            .unwrap();
        let mut initiator = snow::Builder::new(params.clone())
            .prologue(b"nodeinnet-lan/1")
            .local_private_key(&initiator_key.private)
            .build_initiator()
            .unwrap();
        let mut responder = snow::Builder::new(params)
            .prologue(b"nodeinnet-lan/1")
            .local_private_key(&responder_key.private)
            .build_responder()
            .unwrap();
        let (mut message, mut payload) = ([0; 256], [0; 256]);
        let len = initiator.write_message(&[], &mut message).unwrap();
        responder
            .read_message(&message[..len], &mut payload)
            .unwrap();
        let len = responder.write_message(&[], &mut message).unwrap();
        initiator
            .read_message(&message[..len], &mut payload)
            .unwrap();
        let len = initiator.write_message(&[], &mut message).unwrap();
        responder
            .read_message(&message[..len], &mut payload)
            .unwrap();
        assert!(initiator.is_handshake_finished() && responder.is_handshake_finished());
        (
            initiator.get_handshake_hash().try_into().unwrap(),
            responder.get_handshake_hash().try_into().unwrap(),
        )
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn one_transcript_gives_equal_codes() {
        let (initiator_h, responder_h) = handshake();
        assert_eq!(initiator_h, responder_h);
        let b = Responder::new(responder_h);
        let a = Initiator::new(initiator_h, b.commit());
        let (reveal, code) = b.reveal(&a.nonce());
        assert_eq!(a.code(&reveal), Some(code));
    }

    #[test]
    fn relayed_sessions_get_independent_codes() {
        let (a_h, relay_a_h) = handshake();
        let (relay_b_h, b_h) = handshake();
        assert_eq!(a_h, relay_a_h);
        assert_eq!(relay_b_h, b_h);
        assert_ne!(a_h, b_h);

        let b = Responder::new(b_h);
        let a = Initiator::new(a_h, b.commit());
        let (reveal, _) = b.reveal(&a.nonce());
        assert_eq!(a.code(&reveal), None);

        let (initiator, responder) = ([1; NONCE_LEN], [2; NONCE_LEN]);
        let mut codes = HashSet::new();
        for session in 0u32..1000 {
            let mut h = [0; 32];
            h[..4].copy_from_slice(&session.to_be_bytes());
            let first = code(&h, &initiator, &responder);
            h[4] = 1;
            assert_ne!(code(&h, &initiator, &responder), first, "{session}");
            codes.insert(first);
        }
        assert!(codes.len() > 990, "{}", codes.len());
    }

    #[test]
    fn the_initiator_refuses_a_reveal_that_does_not_open_the_commit() {
        let h = [7; 32];
        let nonce = [1; NONCE_LEN];
        let commit = Responder { h, nonce }.commit();
        assert!(opens(&commit, &h, &nonce));
        let mut wrong = nonce;
        wrong[NONCE_LEN - 1] ^= 1;
        assert!(!opens(&commit, &h, &wrong));
        assert!(!opens(&commit, &[8; 32], &nonce));
        let mut altered = commit;
        altered[0] ^= 0x80;
        assert!(!opens(&altered, &h, &nonce));
        assert_eq!(Initiator::new(h, commit).code(&wrong), None);
        assert!(Initiator::new(h, commit).code(&nonce).is_some());
    }

    #[test]
    fn codes_keep_leading_zeros() {
        assert_eq!(shown(12_345), "012 345");
        assert_eq!(shown(7), "000 007");
        assert_eq!(shown(0), "000 000");
        assert_eq!(shown(999_999), "999 999");
        for _ in 0..1000 {
            let text = code(&nonce(), &nonce(), &nonce());
            let (high, low) = text.split_once(' ').unwrap();
            assert!(high.len() == 3 && low.len() == 3, "{text}");
            assert!(
                (high.bytes().chain(low.bytes())).all(|b| b.is_ascii_digit()),
                "{text}"
            );
        }
    }

    #[test]
    fn known_answers() {
        assert_eq!(
            hex(&commitment(&[0x11; 32], &[0x22; NONCE_LEN])),
            "acbbbac77b0853ccdf770ff6824ce36214965c7fdf8388ac7004561b70539ce7"
        );
        assert_eq!(
            code(&[0x11; 32], &[0x22; NONCE_LEN], &[0x33; NONCE_LEN]),
            "129 172"
        );
        assert_ne!(nonce(), nonce());
    }
}
