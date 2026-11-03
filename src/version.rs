use std::fmt;

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Find the first `major.minor[.patch]` in free text such as
    /// `Poetry (version 2.4.1)` or `pip 26.2.2 from /opt/...`.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let starts_number = bytes[i].is_ascii_digit()
                && (i == 0 || !(bytes[i - 1].is_ascii_digit() || bytes[i - 1] == b'.'));
            if !starts_number {
                i += 1;
                continue;
            }
            // `i` sits on an ASCII digit, so it is a char boundary.
            let token: String = text[i..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let parts: Vec<&str> = token.split('.').filter(|p| !p.is_empty()).collect();
            if parts.len() >= 2
                && let (Ok(major), Ok(minor)) = (parts[0].parse(), parts[1].parse())
            {
                let patch = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
                return Some(Self::new(major, minor, patch));
            }
            i += token.len().max(1);
        }
        None
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::Version;

    #[test]
    fn parses_tool_banners() {
        let cases = [
            ("11.19.0", Version::new(11, 19, 0)),
            (
                "uv 0.12.3 (507230998 2026-08-07 aarch64-apple-darwin)",
                Version::new(0, 12, 3),
            ),
            (
                "pip 26.2.2 from /opt/homebrew/lib/python3.15/site-packages/pip (python 3.15)",
                Version::new(26, 2, 2),
            ),
            ("Poetry (version 2.4.1)", Version::new(2, 4, 1)),
            ("v22.4", Version::new(22, 4, 0)),
        ];
        for (text, want) in cases {
            assert_eq!(Version::parse(text), Some(want), "{text}");
        }
        assert_eq!(Version::parse("no digits here"), None);
        assert_eq!(Version::parse("build 42"), None);
    }
}
