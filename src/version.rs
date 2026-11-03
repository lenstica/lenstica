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
        Self::parse_with_text(text).map(|(v, _)| v)
    }

    /// [`Self::parse`], with the version as the tool wrote it: `25.0` stays
    /// `25.0`, and a pre-release keeps its tag (`1.2.1-canary.3`).
    pub fn parse_with_text(text: &str) -> Option<(Self, &str)> {
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
                let full = text[i..]
                    .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')))
                    .map_or(&text[i..], |end| &text[i..i + end])
                    .trim_end_matches(['.', '-', '+']);
                return Some((Self::new(major, minor, patch), full));
            }
            i += token.len().max(1);
        }
        None
    }
}

/// A package version, ordered well enough to compare against fixed versions:
/// any number of release parts (`1.2.3.4`, with `1.0` equal to `1.0.0`), a
/// pre-release (`-beta.1`, `rc1`, `.dev0`) before its release and a
/// post-release (`.post1`, `-1`) after it. Build metadata (`+local`) is ignored.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageVersion {
    release: Vec<u64>,
    /// -2 dev, -1 pre-release, 0 release, 1 post-release.
    phase: i8,
    /// The suffix, split into numbers and words, to order pre-releases.
    tag: Vec<TagPart>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TagPart {
    Number(u64),
    Word(String),
}

impl PackageVersion {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let text = text.strip_prefix(['v', 'V']).unwrap_or(text);
        let text = text.split('+').next().unwrap_or(text);
        let end = text
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(text.len());
        let (numbers, suffix) = text.split_at(end);
        // A trailing dot belongs to the suffix (`1.0.post1`).
        let numbers = numbers.trim_end_matches('.');
        let mut release = numbers
            .split('.')
            .map(|p| p.parse().ok())
            .collect::<Option<Vec<u64>>>()?;
        while release.len() > 1 && release.last() == Some(&0) {
            release.pop();
        }
        let suffix = suffix
            .trim_start_matches(['.', '-', '_'])
            .to_ascii_lowercase();
        let mut tag = Vec::new();
        let mut rest = suffix.as_str();
        while !rest.is_empty() {
            let digits = rest.starts_with(|c: char| c.is_ascii_digit());
            let end = rest
                .find(|c: char| c.is_ascii_digit() != digits || matches!(c, '.' | '-' | '_'))
                .unwrap_or(rest.len());
            let (part, next) = rest.split_at(end.max(1));
            if digits {
                tag.push(TagPart::Number(part.parse().unwrap_or(u64::MAX)));
            } else if !matches!(part, "." | "-" | "_") {
                tag.push(TagPart::Word(part.to_string()));
            }
            rest = next;
        }
        let phase = match tag.first() {
            None => 0,
            Some(TagPart::Word(w)) if w == "post" || w == "rev" || w == "r" => 1,
            // PyPI's `1.0-1` is a post-release.
            Some(TagPart::Number(_)) => 1,
            Some(TagPart::Word(w)) if w == "dev" => -2,
            Some(_) => -1,
        };
        Some(Self {
            release,
            phase,
            tag,
        })
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
    fn orders_package_versions() {
        use super::PackageVersion as V;
        let v = |s| V::parse(s).unwrap();
        assert!(v("2.0.0-beta.1") < v("2.0.0"));
        assert!(v("2.0.0-alpha") < v("2.0.0-beta.1"));
        assert!(v("2.0.0-beta.2") < v("2.0.0-beta.10"));
        assert!(v("1.2.3.4") < v("1.2.3.5"));
        assert_eq!(v("1.0"), v("1.0.0"));
        assert!(v("1.0.dev0") < v("1.0a1"));
        assert!(v("1.0rc1") < v("1.0") && v("1.0") < v("1.0.post1"));
        assert!(v("4.17.15") < v("4.17.21") && v("1.9") < v("1.10"));
        assert_eq!(V::parse("latest"), None);
    }

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
        assert_eq!(
            Version::parse_with_text("pip 25.0 from /x").map(|(_, t)| t),
            Some("25.0")
        );
        assert_eq!(
            Version::parse_with_text("1.2.1-canary.3\n").map(|(_, t)| t),
            Some("1.2.1-canary.3")
        );
        assert_eq!(Version::parse("no digits here"), None);
        assert_eq!(Version::parse("build 42"), None);
    }
}
