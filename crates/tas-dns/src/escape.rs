//! Log-safe rendering of tenant- or network-controlled text.
//!
//! Every value that originates outside this process (query names, tenant ids, apexes, record
//! text, peer-supplied strings) is passed through [`esc`] before it reaches a log line or a
//! metric label, so a newline, ANSI escape or quote in it cannot forge a log record.

/// Longest rendering kept; the rest is replaced by `...`.
pub const MAX_LOGGED: usize = 96;

/// Render `s` with everything outside printable ASCII (and `"`/`\`) as `\xNN`, bounded.
#[must_use]
pub fn esc(s: &str) -> String {
    esc_bytes(s.as_bytes())
}

/// As [`esc`], for raw bytes.
#[must_use]
pub fn esc_bytes(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().min(MAX_LOGGED) + 4);
    for &c in b {
        if out.len() >= MAX_LOGGED {
            out.push_str("...");
            break;
        }
        match c {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(c));
            }
            0x20..=0x7e => out.push(char::from(c)),
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push_str("\\x");
                out.push(char::from(HEX[usize::from(c >> 4)]));
                out.push(char::from(HEX[usize::from(c & 15)]));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_quotes_and_non_ascii_are_escaped() {
        assert_eq!(
            esc("a\nb\r\x1b[31m\"\\é"),
            "a\\x0ab\\x0d\\x1b[31m\\\"\\\\\\xc3\\xa9"
        );
    }

    #[test]
    fn output_is_bounded() {
        let long = "a".repeat(10_000);
        assert!(esc(&long).len() <= MAX_LOGGED + 3);
    }
}
