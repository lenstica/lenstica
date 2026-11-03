//! Every package manager spells "minimum age" differently: npm counts days,
//! pnpm and Yarn minutes, Bun seconds, uv and pip take durations or absolute
//! dates. This module turns any of those spellings into seconds so they can be
//! compared against the central `min_days`.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};

pub const MINUTE: i64 = 60;
pub const HOUR: i64 = 60 * MINUTE;
pub const DAY: i64 = 24 * HOUR;
pub const WEEK: i64 = 7 * DAY;

pub fn unquote(raw: &str) -> &str {
    let t = raw.trim();
    for q in ['"', '\''] {
        if t.len() >= 2 && t.starts_with(q) && t.ends_with(q) {
            return t[1..t.len() - 1].trim();
        }
    }
    t
}

/// The minimum age, in seconds, that `raw` enforces. A bare number is read in
/// `bare_unit` seconds. An absolute cutoff date enforces `now - cutoff`.
pub fn parse_age(raw: &str, bare_unit: i64, now: DateTime<Utc>) -> Option<i64> {
    let s = unquote(raw);
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<i64>() {
        return (n >= 0).then(|| n.saturating_mul(bare_unit));
    }
    if let Ok(f) = s.parse::<f64>() {
        return (f.is_finite() && f >= 0.0).then(|| (f * bare_unit as f64).round() as i64);
    }
    parse_iso8601(s)
        .or_else(|| parse_friendly(s))
        .or_else(|| parse_timestamp(s).map(|cutoff| (now - cutoff).num_seconds().max(0)))
}

/// `P7D`, `PT72H`, `P1W`, `P1DT12H`.
fn parse_iso8601(s: &str) -> Option<i64> {
    let body = s.strip_prefix(['P', 'p'])?;
    let mut total = 0f64;
    let mut in_time = false;
    let mut number = String::new();
    let mut any = false;
    for c in body.chars() {
        match c {
            'T' | 't' if number.is_empty() && !in_time => in_time = true,
            '0'..='9' | '.' => number.push(c),
            ',' => number.push('.'),
            _ => {
                let n: f64 = number.parse().ok()?;
                number.clear();
                let unit = match (c.to_ascii_uppercase(), in_time) {
                    ('Y', false) => 365 * DAY,
                    ('M', false) => 30 * DAY,
                    ('W', false) => WEEK,
                    ('D', false) => DAY,
                    ('H', true) => HOUR,
                    ('M', true) => MINUTE,
                    ('S', true) => 1,
                    _ => return None,
                };
                total += n * unit as f64;
                any = true;
            }
        }
    }
    (number.is_empty() && any).then(|| total.round() as i64)
}

fn unit_seconds(unit: &str) -> Option<f64> {
    Some(match unit.to_ascii_lowercase().as_str() {
        "ms" | "msec" | "msecs" | "millisecond" | "milliseconds" => 0.001,
        "s" | "sec" | "secs" | "second" | "seconds" => 1.0,
        "m" | "min" | "mins" | "minute" | "minutes" => MINUTE as f64,
        "h" | "hr" | "hrs" | "hour" | "hours" => HOUR as f64,
        "d" | "day" | "days" => DAY as f64,
        "w" | "wk" | "wks" | "week" | "weeks" => WEEK as f64,
        "mo" | "month" | "months" => (30 * DAY) as f64,
        "y" | "yr" | "yrs" | "year" | "years" => (365 * DAY) as f64,
        _ => return None,
    })
}

/// `7d`, `7 days`, `1 week`, `36h`, `1 day 12 hours`.
fn parse_friendly(s: &str) -> Option<i64> {
    let mut total = 0f64;
    let mut any = false;
    let mut chars = s.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace() || *c == ',').is_some() {}
        if chars.peek().is_none() {
            break;
        }
        let mut number = String::new();
        while let Some(c) = chars.next_if(|c| c.is_ascii_digit() || *c == '.') {
            number.push(c);
        }
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let mut unit = String::new();
        while let Some(c) = chars.next_if(|c| c.is_ascii_alphabetic()) {
            unit.push(c);
        }
        let n: f64 = number.parse().ok()?;
        total += n * unit_seconds(&unit)?;
        any = true;
    }
    any.then(|| total.round() as i64)
}

fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(naive.and_utc());
        }
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|naive| naive.and_utc())
}

pub fn humanize(secs: i64) -> String {
    let plural = |n: i64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    match secs {
        s if s <= 0 => "none".to_string(),
        s if s % DAY == 0 => plural(s / DAY, "day"),
        s if s >= DAY => format!("{:.1} days", s as f64 / DAY as f64),
        s if s % HOUR == 0 => plural(s / HOUR, "hour"),
        s if s >= HOUR => format!("{:.1} hours", s as f64 / HOUR as f64),
        s if s % MINUTE == 0 => plural(s / MINUTE, "minute"),
        s => plural(s, "second"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-02T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn bare_numbers_use_the_managers_unit() {
        assert_eq!(parse_age("7", DAY, now()), Some(7 * DAY));
        assert_eq!(parse_age("10080", MINUTE, now()), Some(7 * DAY));
        assert_eq!(parse_age("604800", 1, now()), Some(7 * DAY));
        assert_eq!(parse_age("\"1440\"", MINUTE, now()), Some(DAY));
        assert_eq!(parse_age("-1", DAY, now()), None);
    }

    #[test]
    fn durations_in_every_spelling() {
        for raw in [
            "P7D",
            "p7d",
            "P1W",
            "PT168H",
            "7d",
            "7 days",
            "1 week",
            "\"7 days\"",
            "6 days 24 hours",
        ] {
            assert_eq!(parse_age(raw, MINUTE, now()), Some(7 * DAY), "{raw}");
        }
        assert_eq!(parse_age("P1DT12H", MINUTE, now()), Some(DAY + 12 * HOUR));
        assert_eq!(parse_age("PT", MINUTE, now()), None);
        assert_eq!(parse_age("seven days", MINUTE, now()), None);
    }

    #[test]
    fn absolute_cutoffs_measure_age_from_now() {
        assert_eq!(
            parse_age("2026-10-26", DAY, now()),
            Some(7 * DAY + 12 * HOUR)
        );
        assert_eq!(parse_age("2026-10-26T12:00:00Z", DAY, now()), Some(7 * DAY));
        assert_eq!(parse_age("2027-01-01", DAY, now()), Some(0));
    }

    #[test]
    fn humanizes() {
        assert_eq!(humanize(7 * DAY), "7 days");
        assert_eq!(humanize(DAY), "1 day");
        assert_eq!(humanize(DAY + 12 * HOUR), "1.5 days");
        assert_eq!(humanize(3 * HOUR), "3 hours");
        assert_eq!(humanize(0), "none");
    }
}
