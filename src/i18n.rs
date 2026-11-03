//! The app's languages, shared with the window. The menu bar menu,
//! notifications and the messages the app sends the window come from the
//! same `i18n/<code>.json` files as the window's own text: English is the
//! source and the fallback for anything a translation leaves out. Adding a
//! language is adding a file (docs/translating.md).

use std::collections::HashMap;
use std::sync::{OnceLock, PoisonError, RwLock};

use serde_json::Value;

include!(concat!(env!("OUT_DIR"), "/languages.rs"));

fn catalogs() -> &'static HashMap<&'static str, Value> {
    static ALL: OnceLock<HashMap<&'static str, Value>> = OnceLock::new();
    ALL.get_or_init(|| {
        CATALOGS
            .iter()
            .filter_map(|(code, text)| match serde_json::from_str(text) {
                Ok(value) => Some((*code, value)),
                Err(e) => {
                    eprintln!("lenstica: cannot read the {code} language file: {e}");
                    None
                }
            })
            .collect()
    })
}

/// "system" or a language code: Settings → General → Language (`window.language`).
static CHOICE: RwLock<String> = RwLock::new(String::new());

/// Speak the language chosen in the settings.
pub fn choose(choice: &str) {
    *CHOICE.write().unwrap_or_else(PoisonError::into_inner) = choice.to_string();
}

/// The system's preferred languages, most preferred first (`["uk-UA", "en-US"]`).
pub fn system_languages() -> &'static [String] {
    static LANGUAGES: OnceLock<Vec<String>> = OnceLock::new();
    LANGUAGES.get_or_init(|| {
        #[cfg(target_os = "macos")]
        {
            // `(\n    "uk-UA",\n    "en-US"\n)`
            let listed = std::process::Command::new("/usr/bin/defaults")
                .args(["read", "-g", "AppleLanguages"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            let found: Vec<String> = listed
                .split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_string)
                .collect();
            if !found.is_empty() {
                return found;
            }
        }
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|var| std::env::var(var).ok())
            .find(|v| !v.is_empty() && v != "C" && v != "POSIX")
            .map(|v| vec![v.split('.').next().unwrap_or_default().replace('_', "-")])
            .unwrap_or_default()
    })
}

/// The best language for a list of preferred ones: an exact match, then the base language, else English.
fn pick(preferred: &[String]) -> &'static str {
    let all = catalogs();
    for tag in preferred {
        let lower = tag.to_ascii_lowercase();
        let base = lower.split('-').next().unwrap_or_default();
        if let Some(code) = all
            .keys()
            .find(|c| c.to_ascii_lowercase() == lower)
            .or_else(|| all.keys().find(|c| c.to_ascii_lowercase() == base))
        {
            return code;
        }
    }
    "en"
}

/// The language the app speaks now.
pub fn locale() -> &'static str {
    let choice = CHOICE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if choice.is_empty() || choice == "system" {
        pick(system_languages())
    } else {
        pick(&[choice])
    }
}

fn lookup<'a>(messages: &'a Value, key: &str) -> Option<&'a Value> {
    let found = key.split('.').try_fold(messages, |at, part| at.get(part))?;
    (found.is_string() || found.get("other").is_some_and(Value::is_string)).then_some(found)
}

/// Which plural form a count takes in a language (integers; CLDR rules).
/// English's (`one`, `other`) serves any language not listed here.
pub fn plural(locale: &str, n: u64) -> &'static str {
    let (n10, n100) = (n % 10, n % 100);
    match locale.split('-').next().unwrap_or_default() {
        "ja" | "zh" | "ko" | "vi" | "th" | "id" | "ms" | "tr" => "other",
        "fr" | "pt" => {
            if n <= 1 {
                "one"
            } else {
                "other"
            }
        }
        "uk" | "ru" | "be" | "sr" | "hr" | "bs" => {
            if n10 == 1 && n100 != 11 {
                "one"
            } else if (2..=4).contains(&n10) && !(12..=14).contains(&n100) {
                "few"
            } else {
                "many"
            }
        }
        "pl" => {
            if n == 1 {
                "one"
            } else if (2..=4).contains(&n10) && !(12..=14).contains(&n100) {
                "few"
            } else {
                "many"
            }
        }
        "cs" | "sk" => match n {
            1 => "one",
            2..=4 => "few",
            _ => "other",
        },
        "ar" => match (n, n100) {
            (0, _) => "zero",
            (1, _) => "one",
            (2, _) => "two",
            (_, 3..=10) => "few",
            (_, 11..=99) => "many",
            _ => "other",
        },
        _ => {
            if n == 1 {
                "one"
            } else {
                "other"
            }
        }
    }
}

fn fill(message: &Value, locale: &str, values: &[(&str, String)]) -> String {
    let text = match message {
        Value::String(text) => text.as_str(),
        forms => {
            let count = values
                .iter()
                .find(|(name, _)| *name == "count")
                .and_then(|(_, v)| v.parse::<u64>().ok())
                .unwrap_or(0);
            forms
                .get(plural(locale, count))
                .or_else(|| forms.get("other"))
                .and_then(Value::as_str)
                .unwrap_or_default()
        }
    };
    let mut out = text.to_string();
    for (name, value) in values {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

/// A message in the app's language with its `{placeholders}` filled in; use [`t!`].
pub fn message(key: &str, values: &[(&str, String)]) -> String {
    message_or(key, key, values)
}

/// A message whose key is only known at run time (a category's id), or `fallback`.
pub fn message_or(key: &str, fallback: &str, values: &[(&str, String)]) -> String {
    let locale = locale();
    let all = catalogs();
    let found = all
        .get(locale)
        .and_then(|m| lookup(m, key))
        .map(|m| (m, locale))
        .or_else(|| {
            all.get("en")
                .and_then(|m| lookup(m, key))
                .map(|m| (m, "en"))
        });
    match found {
        Some((m, locale)) => fill(m, locale, values),
        None => fallback.to_string(),
    }
}

/// `t!("menu.need", count = 3, days = 7)`: a message in the app's language.
macro_rules! t {
    ($key:expr $(, $name:ident = $value:expr)* $(,)?) => {
        $crate::i18n::message($key, &[$((stringify!($name), $value.to_string())),*])
    };
}
pub(crate) use t;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_fills_placeholders_and_plurals() {
        choose("en");
        assert_eq!(
            t!("menu.need", count = 1, days = 7),
            "1 needs attention · 7-day cooldown"
        );
        assert_eq!(
            t!("menu.need", count = 3, days = 7),
            "3 need attention · 7-day cooldown"
        );
        assert_eq!(message_or("categories.nope.title", "Nope", &[]), "Nope");
    }

    #[test]
    fn slavic_plurals_take_three_forms() {
        assert_eq!(
            [1, 2, 5, 11, 21, 22, 25].map(|n| plural("uk", n)),
            ["one", "few", "many", "many", "one", "few", "many"]
        );
        assert_eq!(plural("en", 0), "other");
    }

    /// Every language file has English's shape: the same keys or fewer, a
    /// plural where English has one, and only English's {placeholders}.
    #[test]
    fn every_translation_matches_english() {
        fn placeholders(text: &str) -> Vec<&str> {
            text.split('{')
                .skip(1)
                .filter_map(|s| s.split_once('}').map(|(name, _)| name))
                .collect()
        }
        fn check(code: &str, path: &str, english: &Value, theirs: &Value) {
            match (english, theirs) {
                (Value::String(en), Value::String(tr)) => {
                    for name in placeholders(tr) {
                        assert!(
                            placeholders(en).contains(&name),
                            "{code}: {path} has {{{name}}}, which English does not"
                        );
                    }
                }
                (Value::Object(en), Value::Object(tr)) => {
                    let plural = en.contains_key("other");
                    for (key, value) in tr {
                        let here = format!("{path}.{key}");
                        match en.get(key).or_else(|| plural.then(|| &en["other"])) {
                            Some(english) => check(code, &here, english, value),
                            None => panic!("{code}: {here} is not an English message"),
                        }
                    }
                }
                _ => panic!("{code}: {path} has a different shape from English"),
            }
        }
        let all = catalogs();
        assert_eq!(all.len(), CATALOGS.len(), "every language file reads");
        let english = &all["en"];
        for (code, messages) in all {
            check(code, code, english, messages);
        }
    }
}
