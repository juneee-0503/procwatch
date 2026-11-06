//! Taking secrets out of text before it is stored or leaves the machine.
//! Command lines, environment variables and logs routinely hold passwords.

use std::sync::atomic::{AtomicBool, Ordering};

/// Option and field names whose value is a secret.
const SECRET_WORDS: &[&str] = &["password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "api-key", "access_key", "access-key", "private_key", "auth", "credential"];
const MASK: &str = "***";

static REDACT: AtomicBool = AtomicBool::new(true);
static COMMAND_LINES: AtomicBool = AtomicBool::new(true);

/// Apply the privacy settings.
pub fn configure(redact: bool, command_lines: bool) {
    REDACT.store(redact, Ordering::Relaxed);
    COMMAND_LINES.store(command_lines, Ordering::Relaxed);
}

/// A command line as it may be kept, if at all.
pub fn command_line(text: &str) -> String {
    if COMMAND_LINES.load(Ordering::Relaxed) { redact(text) } else { "(command line not kept)".to_string() }
}

fn names_secret(word: &str) -> bool {
    let w = word.trim_start_matches('-').to_ascii_lowercase();
    SECRET_WORDS.iter().any(|s| w.contains(s))
}

/// Long random-looking values with known prefixes.
fn is_token(word: &str) -> bool {
    let w = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    const PREFIXES: &[&str] = &["AKIA", "ghp_", "gho_", "github_pat_", "xox", "sk-", "glpat-", "eyJ"];
    w.len() >= 16 && PREFIXES.iter().any(|p| w.starts_with(p))
}

/// Replace secrets in a command line or log line. Words are masked whole, so
/// a value is never partly shown. Errs towards hiding.
pub fn redact(text: &str) -> String {
    if !REDACT.load(Ordering::Relaxed) {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut hide_next = false;
    for (i, piece) in text.split_inclusive(char::is_whitespace).enumerate() {
        let word = piece.trim_end();
        let space = &piece[word.len()..];
        let scheme = word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic");
        if i > 0 && hide_next && !word.is_empty() && !scheme {
            hide_next = false;
            out.push_str(MASK);
            out.push_str(space);
            continue;
        }
        let masked = mask_word(word, &mut hide_next);
        out.push_str(&masked);
        out.push_str(space);
    }
    out
}

fn mask_word(word: &str, hide_next: &mut bool) -> String {
    // URLs with credentials: scheme://user:secret@host
    if let (Some(scheme), Some(at)) = (word.find("://"), word.rfind('@')) {
        if at > scheme && word[scheme + 3..at].contains(':') {
            return format!("{}{MASK}{}", &word[..scheme + 3], &word[at..]);
        }
    }
    if let Some((name, value)) = word.split_once(['=', ':']) {
        if names_secret(name) && !value.is_empty() {
            let separator = &word[name.len()..=name.len()];
            return format!("{name}{separator}{MASK}");
        }
        if names_secret(name) {
            *hide_next = true;
            return word.to_string();
        }
    }
    if is_token(word) {
        return MASK.to_string();
    }
    if word.starts_with('-') && names_secret(word) {
        *hide_next = true;
    }
    // Headers: the scheme comes first, then the secret.
    if word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic") {
        *hide_next = true;
    }
    word.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hides_what_should_be_hidden() {
        for (given, want) in [
            ("mysql -u root --password=hunter2 db", "mysql -u root --password=*** db"),
            ("mysql --password hunter2 db", "mysql --password *** db"),
            ("curl -H Authorization: Bearer abc123 http://x", "curl -H Authorization: Bearer *** http://x"),
            ("export API_KEY=abcdef", "export API_KEY=***"),
            ("git clone https://me:hunter2@example.com/r", "git clone https://***@example.com/r"),
            ("token: abc", "token: ***"),
            ("key AKIAIOSFODNN7EXAMPLE here", "key *** here"),
            ("x ghp_0123456789abcdef0123", "x ***"),
        ] {
            assert_eq!(redact(given), want, "{given}");
        }
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        for same in ["ls -la /etc/hosts", "Failed password for root from 1.2.3.4 port 22 ssh2", "", "  two  spaces ", "/usr/bin/python3 -m http.server"] {
            assert_eq!(redact(same), same);
        }
    }
}
