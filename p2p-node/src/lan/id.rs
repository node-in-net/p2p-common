use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

pub const ID_LEN: usize = 32;
pub const NAME_MAX: usize = 63;
pub const INSTANCE_NAME_MAX: usize = 40;

pub fn id_of(key: &str) -> Option<String> {
    key_bytes(key).map(|bytes| id_of_bytes(&bytes))
}

pub fn id_of_bytes(public: &[u8]) -> String {
    let hash = Sha256::digest(public);
    hash[..ID_LEN / 2]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn instance_name(name: &str, id: &str) -> String {
    format!(
        "{} [{}]",
        cut_bytes(&sanitize_name(name), INSTANCE_NAME_MAX),
        id8(id)
    )
}

pub fn id8(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

pub fn fingerprint(id: &str) -> String {
    let short = id.get(..16).unwrap_or(id);
    let groups: Vec<&str> = (0..short.len())
        .step_by(4)
        .filter_map(|at| short.get(at..(at + 4).min(short.len())))
        .collect();
    groups.join(" ")
}

pub fn is_id(s: &str) -> bool {
    s.len() == ID_LEN && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn key_bytes(key: &str) -> Option<[u8; 32]> {
    from_b64(key)?.try_into().ok()
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

pub fn from_b64(s: &str) -> Option<Vec<u8>> {
    STANDARD_NO_PAD.decode(s).ok()
}

pub fn sanitize_name(s: &str) -> String {
    cut_bytes(&clean(s), NAME_MAX)
}

fn clean(s: &str) -> String {
    let cleaned: String = (s.chars())
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|&c| !c.is_control() && !is_bidi_control(c))
        .collect();
    cleaned.trim().to_string()
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn cut_bytes(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn id_is_stable_and_self_certifying() {
        let key = b64(&[7; 32]);
        let id = id_of(&key).unwrap();
        assert!(is_id(&id));
        assert_eq!(id_of(&key).as_deref(), Some(id.as_str()));
        assert_eq!(id_of_bytes(&[7; 32]), id);
        assert_ne!(id_of(&b64(&[8; 32])).unwrap(), id);
        assert_eq!(id_of_bytes(&[0; 32]), "66687aadf862bd776c8fc18b8e9f8e20");

        assert_eq!(id_of("*"), None);
        assert_eq!(id_of(&b64(&[1; 31])), None);
    }

    #[test]
    fn keys_are_node_in_net_base64() {
        let key = [0xfb; 32];
        assert!(b64(&key).contains('+') && b64(&key).contains('/'));
        assert_eq!(key_bytes(&b64(&key)), Some(key));
        assert_eq!(key_bytes(&STANDARD.encode(key)), None);
        assert_eq!(key_bytes(&URL_SAFE_NO_PAD.encode(key)), None);
    }

    #[test]
    fn names() {
        assert_eq!(
            sanitize_name("  Living\u{202d} room\tTV\u{0}  "),
            "Living room TV"
        );
        let long = "ж".repeat(40);
        let cut = sanitize_name(&long);
        assert_eq!(cut.len(), 62);
        assert!(cut.chars().all(|c| c == 'ж'));
        assert_eq!(
            instance_name("Living room TV", ID),
            "Living room TV [01234567]"
        );
        assert_eq!(
            instance_name(&"n".repeat(60), ID),
            format!("{} [01234567]", "n".repeat(40))
        );
        assert!(is_id(ID));
        assert!(!is_id(&ID.to_uppercase()) && !is_id(&ID[1..]));
        assert_eq!(id8("abc"), "abc");
        assert_eq!(fingerprint(ID), "0123 4567 89ab cdef");
        assert_eq!(fingerprint("abcdef"), "abcd ef");
        assert_eq!(key_bytes(&b64(&[1u8; 32])), Some([1u8; 32]));
        assert_eq!(key_bytes(&b64(&[1u8; 33])), None);
    }
}
