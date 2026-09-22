use std::{
    io::{self, Write},
    time::Duration,
};
use url::Url;

pub struct TraceEvent {
    pub sequence: u64,
    pub elapsed: Duration,
    pub phase: &'static str,
    pub hop: usize,
    pub message: String,
}
pub trait EventSink {
    fn event(&mut self, event: &TraceEvent) -> io::Result<()>;
}
pub struct TextSink<W: Write> {
    writer: W,
    ascii: bool,
}
impl<W: Write> TextSink<W> {
    pub fn new(writer: W, ascii: bool) -> Self {
        Self { writer, ascii }
    }
}
impl<W: Write> EventSink for TextSink<W> {
    fn event(&mut self, e: &TraceEvent) -> io::Result<()> {
        let message = if self.ascii {
            e.message
                .chars()
                .flat_map(|c| {
                    if c.is_ascii() {
                        c.to_string()
                    } else {
                        c.escape_unicode().to_string()
                    }
                    .chars()
                    .collect::<Vec<_>>()
                })
                .collect()
        } else {
            e.message.clone()
        };
        writeln!(
            self.writer,
            "{:04} +{:8.3}s {:<10} [hop={}] {}",
            e.sequence,
            e.elapsed.as_secs_f64(),
            e.phase,
            e.hop,
            message
        )?;
        self.writer.flush()
    }
}

#[derive(Default)]
pub struct Redactor {
    secrets: Vec<String>,
}
impl Redactor {
    pub fn secret(&mut self, value: &str) {
        if !value.is_empty() && !self.secrets.iter().any(|s| s == value) {
            self.secrets.push(value.to_owned());
            self.secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        }
    }
    pub fn url(&mut self, url: &Url) {
        self.secret(url.username());
        self.secret(&decode(url.username()));
        if let Some(p) = url.password() {
            self.secret(p);
            self.secret(&decode(p));
        }
        for (_, value) in url.query_pairs() {
            self.secret(&value);
        }
        if let Some(q) = url.query() {
            for pair in q.split('&') {
                if let Some((_, v)) = pair.split_once('=') {
                    self.secret(v);
                }
            }
        }
    }
    pub fn clean(&self, message: &str) -> String {
        let mut s = mask_queries(&mask_userinfo(message));
        for secret in &self.secrets {
            s = s.replace(secret, "[redacted]");
        }
        s.chars().flat_map(|c| {
            if c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_unicode().to_string()
            } else { c.to_string() }.chars().collect::<Vec<_>>()
        }).collect()
    }
}
pub fn display_url(url: &Url) -> String {
    let mut u = url.clone();
    let _ = u.set_username("");
    let _ = u.set_password(None);
    if u.query().is_some() {
        let keys: Vec<_> = u.query_pairs().map(|(k, _)| k.into_owned()).collect();
        u.set_query(None);
        {
            let mut q = u.query_pairs_mut();
            for k in keys {
                q.append_pair(&k, "[redacted]");
            }
        }
    }
    u.set_fragment(None);
    u.to_string()
}
fn mask_userinfo(s: &str) -> String {
    // Do not rely on successful URL parsing: even malformed redirect/verbose URLs
    // must not disclose credentials. Inspect the authority before control escaping.
    let mut result = s.to_owned();
    let mut cursor = 0;
    while let Some(scheme) = result[cursor..].find("://") {
        let start = cursor + scheme + 3;
        let end = result[start..]
            .find(['/', '?', '#', '\r', '\n'])
            .map_or(result.len(), |n| start + n);
        if let Some(at) = result[start..end].rfind('@') {
            result.replace_range(start..start + at, "[redacted]");
            cursor = start + "[redacted]@".len();
        } else {
            cursor = start;
        }
    }
    result
}
fn mask_queries(s: &str) -> String {
    // Handles URLs as well as origin-form request paths, without forwarding values.
    s.split_inclusive(char::is_whitespace)
        .map(|word| {
            if let Some((prefix, query)) = word.split_once('?') {
                let trailing: String = query
                    .chars()
                    .rev()
                    .take_while(|c| c.is_whitespace())
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                format!(
                    "{prefix}?{}{trailing}",
                    query
                        .trim_end()
                        .split('&')
                        .map(|p| format!("{}=[redacted]", p.split('=').next().unwrap_or_default()))
                        .collect::<Vec<_>>()
                        .join("&")
                )
            } else {
                word.to_owned()
            }
        })
        .collect()
}
pub fn sensitive(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "authentication-info"
            | "proxy-authentication-info"
    ) || name.contains("token")
        || name.contains("api-key")
        || name.contains("apikey")
        || name.contains("secret")
}
pub fn header(line: &str) -> String {
    if let Some((name, value)) = line.split_once(':') {
        if sensitive(name) {
            return format!("{name}: [redacted]");
        }
        if ["location", "content-location", "referer"]
            .iter()
            .any(|key| name.eq_ignore_ascii_case(key))
        {
            let value = value.trim();
            let safe = if let Ok(url) = Url::parse(value) {
                display_url(&url)
            } else if let Some((path, query)) = value.split_once('?') {
                format!(
                    "{path}?{}",
                    query
                        .split('&')
                        .map(|p| format!("{}=[redacted]", p.split('=').next().unwrap_or_default()))
                        .collect::<Vec<_>>()
                        .join("&")
                )
            } else {
                value.to_owned()
            };
            return format!("{name}: {}", mask_userinfo(&safe));
        }
    }
    line.to_owned()
}
pub fn preview(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if !bytes.contains(&0) {
            return format!("text {:?}", text); // quoted, escaped control characters
        }
    }
    format!(
        "binary hex {}",
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    )
}
pub fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(a), Some(z)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            ) {
                out.push((a * 16 + z) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secrets_and_terminal_controls() {
        let u = Url::parse("http://user:pass@host/?token=secret").unwrap();
        let mut r = Redactor::default();
        r.url(&u);
        for text in [
            display_url(&u),
            r.clean("GET /?token=secret HTTP/1.1"),
            header("Authorization: secret"),
        ] {
            assert!(!text.contains("secret"));
            assert!(!text.contains("pass"));
        }
        assert_eq!(header("Set-Cookie: a=b"), "Set-Cookie: [redacted]");
        assert!(!r
            .clean("\u{1b}[31m\u{202e}evil")
            .contains(['\u{1b}', '\u{202e}']));
        assert_eq!(decode("p%40ss"), "p@ss");
        assert_eq!(decode("%😀"), "%😀");
        assert!(!r
            .clean("Location: http://u:new-secret@host/")
            .contains("new-secret"));
        assert!(!r
            .clean("Location: http://u:bad secret@host/")
            .contains("bad secret"));
        assert!(!r
            .clean("Link: http://first https://u:new-secret@second/")
            .contains("new-secret"));
        assert!(!header("Location: /path?token=foo bar").contains("bar"));
        assert!(preview(b"a\n\0").starts_with("binary"));
    }
}
