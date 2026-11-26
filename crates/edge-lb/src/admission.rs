//! Request admission at the edge: the platform-wide filter that refuses the request shapes known to
//! turn attacker-controlled input into code execution in an interpreter behind it, **before any
//! tenant sees them**.
//!
//! This is the "virtual patch" layer. It is not a web application firewall and does not try to be
//! one: it carries a short list of rules with a documented reason each, every one decidable from the
//! request alone, none of which a legitimate browser or API client produces.
//!
//! | Rule | Refuses | Why it exists |
//! |---|---|---|
//! | `cgi_argument_injection` | a query string with no literal `=` whose `+`-separated words start with `-` or a Unicode hyphen (soft hyphen `%AD`, U+2010..U+2015, U+2212, U+FE63, U+FF0D), and `-d <ini directive>` words | RFC 3875 section 4.4: a CGI server passes such a query string to the program as **command-line arguments**. PHP-CGI then runs `-d auto_prepend_file=php://input` (CVE-2012-1823) or, via Windows best-fit mapping of U+00AD to `-`, the same thing (CVE-2024-4577, exploited in the wild, in CISA KEV). Rejected before it reaches any interpreter, whatever the tenant runs. |
//! | `nul_byte`, `target_control_byte`, `target_too_long` | NUL (raw or `%00`), control bytes, raw non-ASCII or backslash in the request target, targets over 8 KiB | NUL truncation (`shell.php%00.jpg`), request-line smuggling, parser differentials. |
//! | `encoded_traversal`, `overlong_utf8` | a `..` path segment after up to three rounds of percent-decoding, with `/` or `\` separators, `..;` segments, and overlong UTF-8 forms of `.`, `/`, `\` (`%c0%ae`, `%c0%af`, `%e0%80%ae`) | path traversal to files outside the document root. |
//! | `denied_multipart_field` | a multipart part whose field name is on the deny list (default `PHP_SESSION_UPLOAD_PROGRESS`) | `PHP2Shell` (CVE-2026-109619): session upload progress is the advisory's confirmed trigger path for the stale-state use-after-free, "enabled by default" and handled before any application code runs. The platform recipe turns it off; this rule protects tenants that have not been rebuilt yet. The list is extendable at runtime without a rebuild (`PUT /control/admission`). |
//! | `malformed_multipart`, `multipart_too_many_parts`, `upload_filename`, `param_nesting`, `too_many_params` | multipart bodies with no or an invalid boundary, no closing delimiter, a preamble, or any ambiguous delimiter line (delimiters are only recognised at line starts, as PHP does; `prefix--BOUNDARY--suffix` inside a field is data and hides no later part), more parts than `max_multipart_parts`, filenames with NUL or path separators, parameter names nested deeper than `max_param_nesting`, more than `max_params` parameters | The request-shape limits the PHP advisory asks proxies to enforce for CVE-2026-109618 (memory exhaustion during input parsing is the trigger). |
//! | `malformed_session_cookie`, `cookie_too_large` | `PHPSESSID` that is not 1..=256 of `[A-Za-z0-9,-]`; any `Cookie` header over 8 KiB | oversize and malformed session ids are the advisory's named indicator for the stale session-id pointer. |
//! | `header_flood`, `header_injection` | more than 100 headers, more than 32 KiB of headers, CR/LF/NUL in a header value, a non-token header name | header-based smuggling and parser exhaustion. |
//! | `multipart_blocked` | any multipart request for a hostname on `block_multipart_hosts` | the advisory's workaround for applications that do not use uploads. Per-host, set by the operator during an incident. |
//!
//! ## What it is not
//!
//! - Not a patch. The PHP advisory's own words: no configuration or filter "fully closes" the
//!   vulnerability; Cloudflare's: request data alone cannot always separate exploit from legitimate
//!   traffic. Other trigger paths exist (fatal errors and timeouts the attacker can induce, invalid INI
//!   diagnostics). This reduces the exposed surface while the rebuilt image rolls out; it is not the
//!   fix and `patch-sla` keeps the deadline running while a virtual patch is in force.
//! - Not body-complete. Bodies are buffered by the HTTP layer up to its cap (8 MiB); multipart bodies
//!   larger than `max_multipart_scan_bytes` are refused rather than scanned partially.
//! - Not a replacement for the interpreter profile: `cgi.fix_pathinfo=0`, FPM only, `limit_extensions`
//!   are what stop a PHP file smuggled into an upload directory from running.
//!
//! ## Configuration
//!
//! [`AdmissionConfig::default`] is the always-on baseline. A runtime overlay ([`AdmissionOverlay`],
//! JSON, from `EDGE_LB_ADMISSION_FILE` at boot and `PUT /control/admission` afterwards) can only
//! **tighten**: limits take the minimum, deny lists the union, switches the stricter value. No overlay
//! can disable a rule, so a leaked control secret can make the edge stricter, never weaker.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// The longest request target accepted.
pub const MAX_TARGET_BYTES: usize = 8 * 1024;
/// Most headers in a request.
pub const MAX_HEADER_COUNT: usize = 100;
/// Most header bytes (names plus values).
pub const MAX_HEADER_BYTES: usize = 32 * 1024;
/// Longest `Cookie` header.
pub const MAX_COOKIE_BYTES: usize = 8 * 1024;
/// Longest PHP session id (`session.sid_length` maximum).
pub const MAX_SESSION_ID_LEN: usize = 256;
/// Most multipart parts.
pub const MAX_MULTIPART_PARTS: usize = 512;
/// Deepest `a[b][c]` nesting in a parameter name.
pub const MAX_PARAM_NESTING: usize = 32;
/// Most query or form parameters (PHP's `max_input_vars` default).
pub const MAX_PARAMS: usize = 1000;
/// Largest multipart body scanned; larger is refused.
pub const MAX_MULTIPART_SCAN_BYTES: usize = 16 * 1024 * 1024;
/// Part header block limit.
const MAX_PART_HEADER_BYTES: usize = 8 * 1024;
/// RFC 2046 boundary length limit.
const MAX_BOUNDARY_LEN: usize = 70;

/// The always-on rules' parameters plus the runtime-extendable deny lists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdmissionConfig {
    /// Longest request target.
    pub max_target_bytes: usize,
    /// Most headers.
    pub max_header_count: usize,
    /// Most header bytes.
    pub max_header_bytes: usize,
    /// Longest `Cookie` header.
    pub max_cookie_bytes: usize,
    /// Most multipart parts.
    pub max_multipart_parts: usize,
    /// Deepest parameter-name nesting.
    pub max_param_nesting: usize,
    /// Most parameters in a query or urlencoded body.
    pub max_params: usize,
    /// Largest multipart body scanned.
    pub max_multipart_scan_bytes: usize,
    /// Cookie names that carry PHP session ids.
    pub session_cookie_names: BTreeSet<String>,
    /// Multipart field names refused (compared case-insensitively).
    pub deny_multipart_fields: BTreeSet<String>,
    /// Hostnames (lowercase, no port) for which every multipart request is refused.
    pub block_multipart_hosts: BTreeSet<String>,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_target_bytes: MAX_TARGET_BYTES,
            max_header_count: MAX_HEADER_COUNT,
            max_header_bytes: MAX_HEADER_BYTES,
            max_cookie_bytes: MAX_COOKIE_BYTES,
            max_multipart_parts: MAX_MULTIPART_PARTS,
            max_param_nesting: MAX_PARAM_NESTING,
            max_params: MAX_PARAMS,
            max_multipart_scan_bytes: MAX_MULTIPART_SCAN_BYTES,
            session_cookie_names: BTreeSet::from(["PHPSESSID".to_string()]),
            deny_multipart_fields: BTreeSet::from(["PHP_SESSION_UPLOAD_PROGRESS".to_string()]),
            block_multipart_hosts: BTreeSet::new(),
        }
    }
}

/// A runtime change to the configuration. Every field is optional; the merge only tightens.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdmissionOverlay {
    /// Lower the target limit.
    pub max_target_bytes: Option<usize>,
    /// Lower the header count limit.
    pub max_header_count: Option<usize>,
    /// Lower the header byte limit.
    pub max_header_bytes: Option<usize>,
    /// Lower the cookie limit.
    pub max_cookie_bytes: Option<usize>,
    /// Lower the multipart part limit.
    pub max_multipart_parts: Option<usize>,
    /// Lower the nesting limit.
    pub max_param_nesting: Option<usize>,
    /// Lower the parameter-count limit.
    pub max_params: Option<usize>,
    /// Lower the multipart scan limit.
    pub max_multipart_scan_bytes: Option<usize>,
    /// Add session cookie names to validate.
    pub session_cookie_names: BTreeSet<String>,
    /// Add multipart field names to refuse.
    pub deny_multipart_fields: BTreeSet<String>,
    /// Add hostnames whose multipart requests are all refused.
    pub block_multipart_hosts: BTreeSet<String>,
}

/// Why an overlay was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayError(pub String);

impl std::fmt::Display for OverlayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "admission overlay refused: {}", self.0)
    }
}

impl std::error::Error for OverlayError {}

/// Most entries per list (bounds the cost of the per-request scans).
const MAX_LIST: usize = 256;

fn plain_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.[]".contains(&b))
}

fn plain_host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s == s.to_ascii_lowercase()
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl AdmissionConfig {
    /// The configuration as an overlay that, applied to the baseline, reproduces it. This is the
    /// persisted form (`EDGE_LB_ADMISSION_FILE`).
    #[must_use]
    pub fn as_overlay(&self) -> AdmissionOverlay {
        AdmissionOverlay {
            max_target_bytes: Some(self.max_target_bytes),
            max_header_count: Some(self.max_header_count),
            max_header_bytes: Some(self.max_header_bytes),
            max_cookie_bytes: Some(self.max_cookie_bytes),
            max_multipart_parts: Some(self.max_multipart_parts),
            max_param_nesting: Some(self.max_param_nesting),
            max_params: Some(self.max_params),
            max_multipart_scan_bytes: Some(self.max_multipart_scan_bytes),
            session_cookie_names: self.session_cookie_names.clone(),
            deny_multipart_fields: self.deny_multipart_fields.clone(),
            block_multipart_hosts: self.block_multipart_hosts.clone(),
        }
    }

    /// Apply an overlay. The result is never less strict than `self`.
    pub fn tightened(&self, o: &AdmissionOverlay) -> Result<Self, OverlayError> {
        let min = |a: usize, b: Option<usize>| -> Result<usize, OverlayError> {
            match b {
                None => Ok(a),
                Some(0) => Err(OverlayError(
                    "a limit of 0 would refuse every request".into(),
                )),
                Some(v) => Ok(a.min(v)),
            }
        };
        let mut next = self.clone();
        next.max_target_bytes = min(self.max_target_bytes, o.max_target_bytes)?;
        next.max_header_count = min(self.max_header_count, o.max_header_count)?;
        next.max_header_bytes = min(self.max_header_bytes, o.max_header_bytes)?;
        next.max_cookie_bytes = min(self.max_cookie_bytes, o.max_cookie_bytes)?;
        next.max_multipart_parts = min(self.max_multipart_parts, o.max_multipart_parts)?;
        next.max_param_nesting = min(self.max_param_nesting, o.max_param_nesting)?;
        next.max_params = min(self.max_params, o.max_params)?;
        next.max_multipart_scan_bytes =
            min(self.max_multipart_scan_bytes, o.max_multipart_scan_bytes)?;
        if o.session_cookie_names
            .iter()
            .chain(&o.deny_multipart_fields)
            .any(|n| !plain_token(n))
        {
            return Err(OverlayError(
                "cookie and field names must be 1..=128 of [A-Za-z0-9_.\\[\\]-]".into(),
            ));
        }
        if o.block_multipart_hosts.iter().any(|h| !plain_host(h)) {
            return Err(OverlayError(
                "block_multipart_hosts entries must be lowercase hostnames".into(),
            ));
        }
        next.session_cookie_names
            .extend(o.session_cookie_names.iter().cloned());
        next.deny_multipart_fields
            .extend(o.deny_multipart_fields.iter().cloned());
        next.block_multipart_hosts
            .extend(o.block_multipart_hosts.iter().cloned());
        if next.session_cookie_names.len() > MAX_LIST
            || next.deny_multipart_fields.len() > MAX_LIST
            || next.block_multipart_hosts.len() > MAX_LIST
        {
            return Err(OverlayError(format!(
                "lists are limited to {MAX_LIST} entries"
            )));
        }
        Ok(next)
    }
}

/// The rule that refused a request. `as_str` is the metric label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rule {
    /// Target longer than the limit.
    TargetTooLong,
    /// Control byte, raw non-ASCII or backslash in the target.
    TargetControlByte,
    /// NUL byte (raw or encoded).
    NulByte,
    /// `..` segment after decoding.
    EncodedTraversal,
    /// Overlong UTF-8 encoding of a dot or separator.
    OverlongUtf8,
    /// Query string that a CGI would pass as command-line options.
    CgiArgumentInjection,
    /// Too many or too large headers.
    HeaderFlood,
    /// CR/LF/NUL in a header value or a non-token name.
    HeaderInjection,
    /// `Cookie` header over the limit.
    CookieTooLarge,
    /// Session cookie that is not a valid PHP session id.
    MalformedSessionCookie,
    /// Multipart with a missing or invalid boundary or part headers.
    MalformedMultipart,
    /// More multipart parts than allowed.
    MultipartTooManyParts,
    /// A refused multipart field name.
    DeniedMultipartField,
    /// All multipart refused for this host.
    MultipartBlocked,
    /// Upload filename with NUL or a path separator.
    UploadFilename,
    /// Parameter name nested too deep.
    ParamNesting,
    /// Too many parameters.
    TooManyParams,
}

impl Rule {
    /// Every rule, for metrics and tests.
    pub const ALL: [Self; 17] = [
        Self::TargetTooLong,
        Self::TargetControlByte,
        Self::NulByte,
        Self::EncodedTraversal,
        Self::OverlongUtf8,
        Self::CgiArgumentInjection,
        Self::HeaderFlood,
        Self::HeaderInjection,
        Self::CookieTooLarge,
        Self::MalformedSessionCookie,
        Self::MalformedMultipart,
        Self::MultipartTooManyParts,
        Self::DeniedMultipartField,
        Self::MultipartBlocked,
        Self::UploadFilename,
        Self::ParamNesting,
        Self::TooManyParams,
    ];

    /// Stable `snake_case` name (metric label).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TargetTooLong => "target_too_long",
            Self::TargetControlByte => "target_control_byte",
            Self::NulByte => "nul_byte",
            Self::EncodedTraversal => "encoded_traversal",
            Self::OverlongUtf8 => "overlong_utf8",
            Self::CgiArgumentInjection => "cgi_argument_injection",
            Self::HeaderFlood => "header_flood",
            Self::HeaderInjection => "header_injection",
            Self::CookieTooLarge => "cookie_too_large",
            Self::MalformedSessionCookie => "malformed_session_cookie",
            Self::MalformedMultipart => "malformed_multipart",
            Self::MultipartTooManyParts => "multipart_too_many_parts",
            Self::DeniedMultipartField => "denied_multipart_field",
            Self::MultipartBlocked => "multipart_blocked",
            Self::UploadFilename => "upload_filename",
            Self::ParamNesting => "param_nesting",
            Self::TooManyParams => "too_many_params",
        }
    }

    /// The HTTP status the edge answers with. The body never echoes request content.
    #[must_use]
    pub fn status(self) -> u16 {
        match self {
            Self::TargetTooLong => 414,
            Self::HeaderFlood | Self::CookieTooLarge => 431,
            Self::MultipartTooManyParts | Self::TooManyParams => 413,
            Self::CgiArgumentInjection | Self::DeniedMultipartField | Self::MultipartBlocked => 403,
            _ => 400,
        }
    }
}

/// The edge's decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Pass the request on.
    Allow,
    /// Refuse it.
    Reject(Rule),
}

/// The parts of a request the rules look at, independent of the HTTP library.
#[derive(Clone, Copy, Debug)]
pub struct RequestView<'a> {
    /// Request target exactly as received: path and query, not decoded.
    pub target: &'a str,
    /// Headers as received.
    pub headers: &'a [(&'a str, &'a [u8])],
    /// The buffered body.
    pub body: &'a [u8],
}

// ── helpers ─────────────────────────────────────────────────────────────────────────────────

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode one round. `+` is left alone (its meaning depends on where it appears).
fn pct_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' && i + 2 < s.len() {
            if let (Some(h), Some(l)) = (hex(s[i + 1]), hex(s[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

fn has_overlong_utf8(b: &[u8]) -> bool {
    b.iter().enumerate().any(|(i, &c)| match c {
        0xC0 | 0xC1 => true,
        0xE0 => b.get(i + 1).is_some_and(|n| (0x80..0xA0).contains(n)),
        0xF0 => b.get(i + 1).is_some_and(|n| (0x80..0x90).contains(n)),
        _ => false,
    })
}

fn has_dotdot_segment(decoded_path: &[u8]) -> bool {
    decoded_path
        .split(|&b| b == b'/' || b == b'\\')
        .any(|seg| seg.split(|&b| b == b';').next() == Some(b".."))
}

/// Characters that Windows best-fit mapping or lenient parsers turn into an ASCII hyphen-minus, as UTF-8.
fn starts_with_hyphen_like(w: &[u8]) -> bool {
    if w.first() == Some(&b'-') || w.first() == Some(&0xAD) {
        return true;
    }
    let Ok(s) = std::str::from_utf8(w) else {
        return false;
    };
    s.chars().next().is_some_and(|c| {
        matches!(
            c,
            '\u{00AD}' | '\u{2010}'..='\u{2015}' | '\u{2212}' | '\u{FE63}' | '\u{FF0D}'
        )
    })
}

/// INI directives a `-d` option must never set.
const DANGEROUS_INI: [&str; 8] = [
    "auto_prepend_file",
    "auto_append_file",
    "allow_url_include",
    "allow_url_fopen",
    "disable_functions",
    "open_basedir",
    "cgi.force_redirect",
    "safe_mode",
];

/// Does a query string get treated as command-line arguments by a CGI (RFC 3875 section 4.4)?
/// It does when it has no literal `=`. Also refuses the `-d <ini directive>` form regardless of `=`,
/// for servers that are lenient about the rule.
fn cgi_argument_injection(query: &str) -> bool {
    let raw_has_eq = query.as_bytes().contains(&b'=');
    // Words are separated by a literal '+' (RFC 3875); decode each, and also split decoded spaces,
    // because some servers decode before they split.
    let mut words: Vec<Vec<u8>> = Vec::new();
    for w in query.as_bytes().split(|&b| b == b'+') {
        let d = pct_decode(w);
        words.extend(
            d.split(|&b| b == b' ')
                .filter(|x| !x.is_empty())
                .map(<[u8]>::to_vec),
        );
    }
    if !raw_has_eq && words.iter().any(|w| starts_with_hyphen_like(w)) {
        return true;
    }
    words.iter().enumerate().any(|(i, w)| {
        let lw = w.to_ascii_lowercase();
        if !lw.starts_with(b"-d") {
            return false;
        }
        let rest: &[u8] = if lw.len() > 2 {
            &lw[2..]
        } else {
            words.get(i + 1).map_or(&[][..], |n| n.as_slice())
        };
        let rest = rest.to_ascii_lowercase();
        DANGEROUS_INI.iter().any(|d| rest.starts_with(d.as_bytes()))
    })
}

/// Every value of header `name` (case-insensitive), in order.
fn header_values<'a>(v: &RequestView<'a>, name: &str) -> Vec<&'a [u8]> {
    v.headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, val)| *val)
        .collect()
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// `name=value; name2="value"` parameters of a header value, lowercased names.
fn header_params(v: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for seg in v.split(|&b| b == b';').skip(1) {
        let seg = seg.trim_ascii();
        let Some(eq) = seg.iter().position(|&b| b == b'=') else {
            continue;
        };
        let name = String::from_utf8_lossy(&seg[..eq])
            .trim()
            .to_ascii_lowercase();
        let mut val = seg[eq + 1..].trim_ascii();
        if val.len() >= 2 && val[0] == b'"' && val[val.len() - 1] == b'"' {
            val = &val[1..val.len() - 1];
        }
        out.push((name, val.to_vec()));
    }
    out
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > hay.len() || hay.len() - from < needle.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn nesting_depth(name: &[u8]) -> usize {
    name.iter().fold(0, |n, &b| n + usize::from(b == b'['))
}

fn check_params(query_or_form: &str, cfg: &AdmissionConfig) -> Option<Rule> {
    let mut count = 0usize;
    for pair in query_or_form.split('&').filter(|p| !p.is_empty()) {
        count += 1;
        if count > cfg.max_params {
            return Some(Rule::TooManyParams);
        }
        let name = pair.split_once('=').map_or(pair, |(n, _)| n);
        let decoded = pct_decode(name.replace('+', " ").as_bytes());
        if nesting_depth(&decoded) > cfg.max_param_nesting {
            return Some(Rule::ParamNesting);
        }
    }
    None
}

fn check_multipart(
    view: &RequestView<'_>,
    cfg: &AdmissionConfig,
    ct: &[u8],
    host: &str,
) -> Option<Rule> {
    if cfg.block_multipart_hosts.contains(host) {
        return Some(Rule::MultipartBlocked);
    }
    let boundary = header_params(ct)
        .into_iter()
        .find(|(n, _)| n == "boundary")
        .map(|(_, v)| v);
    let Some(boundary) = boundary else {
        return Some(Rule::MalformedMultipart);
    };
    if boundary.is_empty()
        || boundary.len() > MAX_BOUNDARY_LEN
        || !boundary
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b))
    {
        return Some(Rule::MalformedMultipart);
    }
    if view.body.len() > cfg.max_multipart_scan_bytes {
        return Some(Rule::MalformedMultipart);
    }
    let mut delim = b"--".to_vec();
    delim.extend_from_slice(&boundary);
    // A delimiter is only ever recognised at the start of a line (the start of the body, or right
    // after an LF), exactly where PHP's `multipart_buffer` looks for `\n--boundary`. The same bytes
    // in the middle of a line (`prefix--BOUNDARY--suffix`) are field content: they neither close the
    // body nor open a part, so they can hide nothing from the scan and add nothing to the count.
    let mut line_delim = b"\n".to_vec();
    line_delim.extend_from_slice(&delim);
    let body = view.body;
    let mut parts = 0usize;
    let mut closed = false;
    // The body must start with the first delimiter (a preamble is allowed by RFC 2046 but no client
    // sends one; refusing it keeps the parser we are checking against the parser PHP uses).
    if !body.starts_with(&delim) {
        return Some(Rule::MalformedMultipart);
    }
    let mut next = Some(0usize);
    while let Some(d) = next {
        let after = d + delim.len();
        if body.get(after..after + 2) == Some(b"--") {
            // The closing delimiter: only `--boundary--` (optional transport padding) alone on its
            // line. Anything else on that line is ambiguous, so refuse it.
            let Some(eol) = delimiter_line_end(body, after + 2) else {
                return Some(Rule::MalformedMultipart);
            };
            // A parser that keeps going after the close would see anything that follows as more
            // parts, one that stops would not; refuse a body that has a further delimiter line.
            if find(body, &line_delim, eol.saturating_sub(1)).is_some() {
                return Some(Rule::MalformedMultipart);
            }
            closed = true;
            break;
        }
        parts += 1;
        if parts > cfg.max_multipart_parts {
            return Some(Rule::MultipartTooManyParts);
        }
        let Some(hdr_start) = delimiter_line_end(body, after) else {
            return Some(Rule::MalformedMultipart);
        };
        // Part headers end at the first blank line; a delimiter inside them is ambiguous.
        let limit = body.len().min(hdr_start + MAX_PART_HEADER_BYTES);
        let mut p = hdr_start;
        let content_start = loop {
            let Some(len) = body[p..limit].iter().position(|&b| b == b'\n') else {
                return Some(Rule::MalformedMultipart);
            };
            let raw = &body[p..p + len];
            let line = raw.strip_suffix(b"\r").unwrap_or(raw);
            if line.is_empty() {
                break p + len + 1;
            }
            if line.starts_with(&delim) {
                return Some(Rule::MalformedMultipart);
            }
            p += len + 1;
            let line = line.trim_ascii_end();
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                continue;
            };
            if !line[..colon].eq_ignore_ascii_case(b"content-disposition") {
                continue;
            }
            for (pname, pval) in header_params(&line[colon + 1..]) {
                match pname.as_str() {
                    "name" => {
                        let lname = String::from_utf8_lossy(&pval).to_ascii_lowercase();
                        if cfg
                            .deny_multipart_fields
                            .iter()
                            .any(|f| f.eq_ignore_ascii_case(&lname))
                        {
                            return Some(Rule::DeniedMultipartField);
                        }
                        if nesting_depth(&pval) > cfg.max_param_nesting {
                            return Some(Rule::ParamNesting);
                        }
                    }
                    "filename"
                        if pval.iter().any(|&b| b == 0 || b == b'/' || b == b'\\')
                            || pval.len() > 255 =>
                    {
                        return Some(Rule::UploadFilename)
                    }
                    _ => {}
                }
            }
        };
        // The terminating LF of the blank line may itself be the LF that precedes an empty part's
        // delimiter, so the next search starts one byte early.
        next = find(body, &line_delim, content_start.saturating_sub(1)).map(|p| p + 1);
    }
    if parts == 0 || !closed {
        return Some(Rule::MalformedMultipart);
    }
    None
}

/// Where the line holding a delimiter ends: skips optional transport padding (spaces, tabs) after
/// the delimiter, then needs CRLF, LF or the end of the body. Returns the offset of the first byte of
/// the next line, or `None` when anything else follows (an ambiguous delimiter line). A delimiter
/// that ends the body (no line break) is only valid as the closing one; the caller decides.
fn delimiter_line_end(body: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while matches!(body.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    match body.get(i) {
        Some(b'\n') => Some(i + 1),
        Some(b'\r') if body.get(i + 1) == Some(&b'\n') => Some(i + 2),
        None => Some(i),
        _ => None,
    }
}

/// Decide admission for one request. Pure; no allocation proportional to anything but the request.
#[must_use]
pub fn check(cfg: &AdmissionConfig, view: &RequestView<'_>) -> Verdict {
    match run(cfg, view) {
        None => Verdict::Allow,
        Some(r) => Verdict::Reject(r),
    }
}

fn run(cfg: &AdmissionConfig, view: &RequestView<'_>) -> Option<Rule> {
    let target = view.target;

    // 1. The request target.
    if target.len() > cfg.max_target_bytes {
        return Some(Rule::TargetTooLong);
    }
    let (path, query) = target.split_once('?').map_or((target, ""), |(p, q)| (p, q));
    // Fragments never reach a server; one in the target is a smuggling attempt.
    if target.contains('#') {
        return Some(Rule::TargetControlByte);
    }
    if target.bytes().any(|b| b == 0) {
        return Some(Rule::NulByte);
    }
    if target
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f || b >= 0x80 || b == b' ')
        || path.contains('\\')
    {
        return Some(Rule::TargetControlByte);
    }
    if pct_decode(query.as_bytes()).contains(&0) {
        return Some(Rule::NulByte);
    }
    // Path: up to three rounds of decoding, every round checked.
    let mut round = path.as_bytes().to_vec();
    for _ in 0..3 {
        round = pct_decode(&round);
        if round.contains(&0) {
            return Some(Rule::NulByte);
        }
        if has_overlong_utf8(&round) {
            return Some(Rule::OverlongUtf8);
        }
        if has_dotdot_segment(&round) {
            return Some(Rule::EncodedTraversal);
        }
    }
    if cgi_argument_injection(query) {
        return Some(Rule::CgiArgumentInjection);
    }
    if let Some(r) = check_params(query, cfg) {
        return Some(r);
    }

    // 2. Headers.
    if view.headers.len() > cfg.max_header_count
        || view
            .headers
            .iter()
            .map(|(n, v)| n.len() + v.len())
            .sum::<usize>()
            > cfg.max_header_bytes
    {
        return Some(Rule::HeaderFlood);
    }
    for (name, value) in view.headers {
        if !is_token(name) || value.iter().any(|&b| matches!(b, 0 | b'\r' | b'\n')) {
            return Some(Rule::HeaderInjection);
        }
    }
    for cookie in header_values(view, "cookie") {
        if cookie.len() > cfg.max_cookie_bytes {
            return Some(Rule::CookieTooLarge);
        }
        for pair in cookie.split(|&b| b == b';') {
            let pair = pair.trim_ascii();
            let Some(eq) = pair.iter().position(|&b| b == b'=') else {
                continue;
            };
            let (name, value) = (String::from_utf8_lossy(&pair[..eq]), &pair[eq + 1..]);
            if cfg.session_cookie_names.contains(name.as_ref())
                && (value.is_empty()
                    || value.len() > MAX_SESSION_ID_LEN
                    || !value
                        .iter()
                        .all(|&b| b.is_ascii_alphanumeric() || b == b',' || b == b'-'))
            {
                return Some(Rule::MalformedSessionCookie);
            }
        }
    }

    // 3. Body shape.
    let host = header_values(view, "host")
        .first()
        .copied()
        .map(|h| String::from_utf8_lossy(h).to_ascii_lowercase())
        .unwrap_or_default();
    let host = host
        .rsplit_once(':')
        .filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()))
        .map_or(host.as_str(), |(h, _)| h);
    for ct in header_values(view, "content-type") {
        let media = ct
            .split(|&b| b == b';')
            .next()
            .unwrap_or_default()
            .trim_ascii()
            .to_ascii_lowercase();
        if media.starts_with(b"multipart/") {
            if let Some(r) = check_multipart(view, cfg, ct, host) {
                return Some(r);
            }
        } else if media == b"application/x-www-form-urlencoded" {
            if let Some(r) = std::str::from_utf8(view.body)
                .ok()
                .and_then(|b| check_params(b, cfg))
            {
                return Some(r);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AdmissionConfig {
        AdmissionConfig::default()
    }

    fn get(target: &str) -> Verdict {
        check(
            &cfg(),
            &RequestView {
                target,
                headers: &[("host", b"app.example.com")],
                body: b"",
            },
        )
    }

    fn with_headers(headers: &[(&str, &[u8])], body: &[u8]) -> Verdict {
        check(
            &cfg(),
            &RequestView {
                target: "/upload",
                headers,
                body,
            },
        )
    }

    fn multipart(parts: &[(&str, Option<&str>)]) -> Vec<u8> {
        let mut b = Vec::new();
        for (name, filename) in parts {
            b.extend_from_slice(b"--XyZ\r\n");
            match filename {
                Some(f) => b.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: image/png\r\n\r\n").as_bytes()),
                None => b.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes()),
            }
            b.extend_from_slice(b"value\r\n");
        }
        b.extend_from_slice(b"--XyZ--\r\n");
        b
    }

    const MP: (&str, &[u8]) = ("content-type", b"multipart/form-data; boundary=XyZ");

    #[test]
    fn ordinary_requests_are_allowed() {
        for t in [
            "/",
            "/index.php",
            "/a/b/c.css?v=3",
            "/search?q=hello+world&page=2",
            "/p?x=%E4%B8%AD%E6%96%87",
            "/a%20b/c",
            "/file..name.txt",
            "/a/.hidden/b",
            "/wp-json/wp/v2/posts?per_page=10&_embed",
            "/?a[b][c]=1",
            "/api?filter=-1",
            "/p?-x=1",
            "/%7Euser/",
            "/x?q=a-b+c-d",
            "/redirect?next=/home",
            "/blog/2026/10/22/post-title",
            "/search?q=%2500",
        ] {
            assert_eq!(get(t), Verdict::Allow, "{t}");
        }
    }

    #[test]
    fn cgi_argument_injection_is_refused_in_every_known_spelling() {
        for t in [
            // CVE-2012-1823
            "/index.php?-s",
            "/index.php?-d+allow_url_include%3dOn+-d+auto_prepend_file%3dphp://input",
            "/x.php?-r+phpinfo()",
            // CVE-2024-4577: soft hyphen (U+00AD) as %AD, as UTF-8 %C2%AD, and encoded variants
            "/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input",
            "/index.php?%C2%ADd+allow_url_include%3d1",
            "/index.php?%e2%80%90d+x",
            "/index.php?%E2%88%92s",
            "/index.php?%EF%B9%A3n",
            "/index.php?%EF%BC%8Dn",
            // Space and + separators; leading words before the option
            "/index.php?a+-s",
            "/index.php?a%20-s",
            "/index.php?%2dd+open_basedir%3d%2f",
            // Lenient server that splits even with a literal '='
            "/index.php?-d+auto_prepend_file=php://input",
            "/index.php?x=1+-dauto_append_file=x",
            "/index.php?-d%20allow_url_include=1",
        ] {
            assert_eq!(get(t), Verdict::Reject(Rule::CgiArgumentInjection), "{t}");
        }
    }

    #[test]
    fn cgi_rule_does_not_fire_on_queries_with_a_literal_equals() {
        // RFC 3875: a query string with '=' is never turned into arguments.
        for t in [
            "/a?-x=1",
            "/a?q=-5",
            "/a?range=1-10&x=-",
            "/a?sort=-created",
            "/a?x=%AD",
        ] {
            assert_eq!(get(t), Verdict::Allow, "{t}");
        }
    }

    #[test]
    fn traversal_nul_and_overlong_forms_are_refused() {
        let cases: &[(&str, Rule)] = &[
            ("/a/../b", Rule::EncodedTraversal),
            ("/a/%2e%2e/b", Rule::EncodedTraversal),
            ("/a/%2E%2E%2Fb", Rule::EncodedTraversal),
            ("/a/..%2fb", Rule::EncodedTraversal),
            ("/a/%252e%252e/b", Rule::EncodedTraversal),
            ("/a/%25252e%25252e/b", Rule::EncodedTraversal),
            ("/a/..%5cb", Rule::EncodedTraversal),
            ("/a/%2e%2e%5c", Rule::EncodedTraversal),
            ("/a/..;/b", Rule::EncodedTraversal),
            ("/a/..", Rule::EncodedTraversal),
            ("/%2e%2e/etc/passwd", Rule::EncodedTraversal),
            ("/a%00.php", Rule::NulByte),
            ("/a%2500.php", Rule::NulByte),
            ("/a.php%00.jpg", Rule::NulByte),
            ("/a?x=%00", Rule::NulByte),
            ("/a/%c0%ae%c0%ae/b", Rule::OverlongUtf8),
            ("/a/%c0%af", Rule::OverlongUtf8),
            ("/a/%e0%80%ae", Rule::OverlongUtf8),
            ("/a/%c1%9c", Rule::OverlongUtf8),
            ("/a\\b", Rule::TargetControlByte),
            ("/a b", Rule::TargetControlByte),
            ("/a\u{00AD}b", Rule::TargetControlByte),
            ("/a\tb", Rule::TargetControlByte),
            ("/a#frag", Rule::TargetControlByte),
        ];
        for (t, rule) in cases {
            assert_eq!(get(t), Verdict::Reject(*rule), "{t}");
        }
        assert_eq!(
            get(&format!("/{}", "a".repeat(MAX_TARGET_BYTES))),
            Verdict::Reject(Rule::TargetTooLong)
        );
        assert_eq!(
            get(&format!("/{}", "a".repeat(MAX_TARGET_BYTES - 1))),
            Verdict::Allow
        );
        // Dots that are not a traversal.
        for t in ["/a/.../b", "/a/..a/b", "/a/a../b", "/a/.%2e./b"] {
            assert_eq!(get(t), Verdict::Allow, "{t}");
        }
    }

    #[test]
    fn php2shell_upload_progress_field_is_refused_in_every_multipart_spelling() {
        let bad = multipart(&[
            ("PHP_SESSION_UPLOAD_PROGRESS", None),
            ("file", Some("a.png")),
        ]);
        assert_eq!(
            with_headers(&[MP], &bad),
            Verdict::Reject(Rule::DeniedMultipartField)
        );
        // Case, position, quoting and file part variants.
        for (name, body) in [
            ("lower", multipart(&[("php_session_upload_progress", None)])),
            ("mixed", multipart(&[("Php_Session_Upload_Progress", None)])),
            (
                "second part",
                multipart(&[
                    ("a", None),
                    ("b", None),
                    ("PHP_SESSION_UPLOAD_PROGRESS", None),
                ]),
            ),
            (
                "as a file field",
                multipart(&[("PHP_SESSION_UPLOAD_PROGRESS", Some("x.png"))]),
            ),
        ] {
            assert_eq!(
                with_headers(&[MP], &body),
                Verdict::Reject(Rule::DeniedMultipartField),
                "{name}"
            );
        }
        // Unquoted name and bare-LF line endings (PHP accepts both).
        let unq = b"--XyZ\nContent-Disposition: form-data; name=PHP_SESSION_UPLOAD_PROGRESS\n\nv\n--XyZ--\n".to_vec();
        assert_eq!(
            with_headers(&[MP], &unq),
            Verdict::Reject(Rule::DeniedMultipartField)
        );
        // The same string inside a file's *content* is not a field name: no false positive.
        let mut ok = multipart(&[("file", Some("a.png"))]);
        let marker = b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"";
        let at = find(&ok, b"value", 0).unwrap_or(0);
        ok.splice(at..at, marker.iter().copied());
        assert_eq!(with_headers(&[MP], &ok), Verdict::Allow);
        // An ordinary upload passes.
        assert_eq!(
            with_headers(
                &[MP],
                &multipart(&[("title", None), ("file", Some("photo.png"))])
            ),
            Verdict::Allow
        );
    }

    const DENIED_PART: &str =
        "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nx\r\n";

    #[test]
    fn a_closing_delimiter_inside_field_content_does_not_hide_later_parts() {
        // PHP only recognises a delimiter at the start of a line; `prefix--XyZ--suffix` inside an
        // ordinary field is data, and the part after it is still parsed ($_POST gets populated).
        let hide = format!(
            "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nprefix--XyZ--suffix\r\n--XyZ\r\n{DENIED_PART}--XyZ--\r\n"
        );
        assert_eq!(
            with_headers(&[MP], hide.as_bytes()),
            Verdict::Reject(Rule::DeniedMultipartField)
        );
        // The same with LF-only line endings.
        let hide_lf = hide.replace("\r\n", "\n");
        assert_eq!(
            with_headers(&[MP], hide_lf.as_bytes()),
            Verdict::Reject(Rule::DeniedMultipartField)
        );
        // An embedded `--XyZ` (not closing) in the middle of a line is data too, not a part.
        let embedded = format!(
            "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nzz--XyZ\r\nqq--XyZ\r\n--XyZ\r\n{DENIED_PART}--XyZ--\r\n"
        );
        assert_eq!(
            with_headers(&[MP], embedded.as_bytes()),
            Verdict::Reject(Rule::DeniedMultipartField)
        );
        // Harmless content with the same embedded strings is still allowed (no false positive).
        let benign = "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nprefix--XyZ--suffix zz--XyZ\r\n--XyZ--\r\n";
        assert_eq!(with_headers(&[MP], benign.as_bytes()), Verdict::Allow);
        // ...and an embedded delimiter does not count towards the part limit either.
        let mut many = String::new();
        for i in 0..3 {
            many.push_str(&format!(
                "--XyZ\r\nContent-Disposition: form-data; name=\"f{i}\"\r\n\r\nv--XyZ\r\n"
            ));
        }
        many.push_str("--XyZ--\r\n");
        assert_eq!(with_headers(&[MP], many.as_bytes()), Verdict::Allow);
    }

    #[test]
    fn field_content_cannot_hide_the_part_count_limit() {
        let mut body = String::from(
            "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nprefix--XyZ--suffix\r\n",
        );
        for i in 0..=MAX_MULTIPART_PARTS {
            body.push_str(&format!(
                "--XyZ\r\nContent-Disposition: form-data; name=\"f{i}\"\r\n\r\nv\r\n"
            ));
        }
        body.push_str("--XyZ--\r\n");
        assert_eq!(
            with_headers(&[MP], body.as_bytes()),
            Verdict::Reject(Rule::MultipartTooManyParts)
        );
    }

    #[test]
    fn delimiters_are_recognised_at_line_start_with_lf_or_crlf_and_trailing_whitespace() {
        let denied_lf = DENIED_PART.replace("\r\n", "\n");
        // LF-only: hidden-part attempt and plain allow.
        let lf = format!(
            "--XyZ\nContent-Disposition: form-data; name=\"a\"\n\nprefix--XyZ--suffix\n--XyZ\n{denied_lf}--XyZ--\n"
        );
        assert_eq!(
            with_headers(&[MP], lf.as_bytes()),
            Verdict::Reject(Rule::DeniedMultipartField)
        );
        let lf_ok = "--XyZ\nContent-Disposition: form-data; name=\"a\"\n\nv\n--XyZ--\n";
        assert_eq!(with_headers(&[MP], lf_ok.as_bytes()), Verdict::Allow);
        // Transport padding (spaces/tabs) after the delimiters is legal and must not hide parts.
        let pad = format!(
            "--XyZ \t\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XyZ  \r\n{DENIED_PART}--XyZ-- \t\r\n"
        );
        assert_eq!(
            with_headers(&[MP], pad.as_bytes()),
            Verdict::Reject(Rule::DeniedMultipartField)
        );
        let pad_ok =
            "--XyZ \r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XyZ-- \r\n";
        assert_eq!(with_headers(&[MP], pad_ok.as_bytes()), Verdict::Allow);
        // A closing delimiter without a trailing line break at the end of the body.
        let bare_end = "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XyZ--";
        assert_eq!(with_headers(&[MP], bare_end.as_bytes()), Verdict::Allow);
        // An empty part (no content) followed directly by the next delimiter.
        let empty = format!(
            "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n--XyZ\r\n{DENIED_PART}--XyZ--\r\n"
        );
        assert_eq!(
            with_headers(&[MP], empty.as_bytes()),
            Verdict::Reject(Rule::DeniedMultipartField)
        );
    }

    /// Delimiters inside what would be one part's header block must not shrink the part count.
    #[test]
    fn delimiters_inside_part_headers_cannot_hide_parts_from_the_count() {
        let mut body = String::from("--XyZ\r\n");
        for _ in 0..=MAX_MULTIPART_PARTS {
            body.push_str("X-A: b\r\n--XyZ\r\n");
        }
        body.push_str("\r\nv\r\n--XyZ--\r\n");
        assert_eq!(
            with_headers(&[MP], body.as_bytes()),
            Verdict::Reject(Rule::MalformedMultipart)
        );
    }

    #[test]
    fn ambiguous_multipart_bodies_fail_closed() {
        for (name, body) in [
            // No closing delimiter at all.
            (
                "unterminated",
                "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n".to_string(),
            ),
            // A closing delimiter followed by junk on its line.
            (
                "junk after closing",
                "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XyZ--junk\r\n"
                    .to_string(),
            ),
            // A delimiter line followed by junk (a longer boundary that merely starts with ours).
            (
                "boundary prefix",
                "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XyZfoo\r\n--XyZ--\r\n"
                    .to_string(),
            ),
            // Another delimiter after the closing one: a parser that keeps going would see a part.
            (
                "part after closing",
                format!(
                    "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XyZ--\r\n--XyZ\r\n{DENIED_PART}--XyZ--\r\n"
                ),
            ),
            // A preamble before the first delimiter.
            (
                "preamble",
                "junk\r\n--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--XyZ--\r\n"
                    .to_string(),
            ),
            // A delimiter line inside what would be the part headers.
            (
                "delimiter in headers",
                format!(
                    "--XyZ\r\nX-A: b\r\n--XyZ\r\n{DENIED_PART}--XyZ--\r\n"
                ),
            ),
            // A part with no headers must not swallow the next delimiter into its "headers".
            (
                "headerless part",
                format!(
                    "--XyZ\r\n\r\nfoo\r\n--XyZ\r\nX-A: b\r\n\r\nv\r\n--XyZ\r\n{DENIED_PART}--XyZ--\r\n"
                ),
            ),
        ] {
            assert_ne!(
                with_headers(&[MP], body.as_bytes()),
                Verdict::Allow,
                "{name}"
            );
        }
    }

    #[test]
    fn the_deny_list_extends_at_runtime_and_multipart_can_be_blocked_per_host() {
        let body = multipart(&[("custom_progress_name", None)]);
        let hdrs: &[(&str, &[u8])] = &[MP, ("host", b"Shop.Example.com:443")];
        let view = RequestView {
            target: "/u",
            headers: hdrs,
            body: &body,
        };
        assert_eq!(check(&cfg(), &view), Verdict::Allow);
        let o = AdmissionOverlay {
            deny_multipart_fields: BTreeSet::from(["CUSTOM_PROGRESS_NAME".to_string()]),
            ..Default::default()
        };
        let c = cfg().tightened(&o).unwrap_or_default();
        assert_eq!(
            check(&c, &view),
            Verdict::Reject(Rule::DeniedMultipartField)
        );
        assert!(
            c.deny_multipart_fields
                .contains("PHP_SESSION_UPLOAD_PROGRESS"),
            "the baseline entry stays"
        );
        let o = AdmissionOverlay {
            block_multipart_hosts: BTreeSet::from(["shop.example.com".to_string()]),
            ..Default::default()
        };
        let c = cfg().tightened(&o).unwrap_or_default();
        assert_eq!(check(&c, &view), Verdict::Reject(Rule::MultipartBlocked));
        let other: &[(&str, &[u8])] = &[MP, ("host", b"other.example.com")];
        assert_eq!(
            check(
                &c,
                &RequestView {
                    target: "/u",
                    headers: other,
                    body: &body
                }
            ),
            Verdict::Allow
        );
    }

    #[test]
    fn an_overlay_can_only_tighten() {
        let base = cfg();
        let o = AdmissionOverlay {
            max_target_bytes: Some(1_000_000),
            max_params: Some(10),
            ..Default::default()
        };
        let c = base.tightened(&o).unwrap_or_default();
        assert_eq!(
            c.max_target_bytes, MAX_TARGET_BYTES,
            "a larger limit is ignored"
        );
        assert_eq!(c.max_params, 10);
        assert!(base
            .tightened(&AdmissionOverlay {
                max_params: Some(0),
                ..Default::default()
            })
            .is_err());
        for bad in ["a b", "x\n", "", "a;b"] {
            assert!(
                base.tightened(&AdmissionOverlay {
                    deny_multipart_fields: BTreeSet::from([bad.to_string()]),
                    ..Default::default()
                })
                .is_err(),
                "{bad:?}"
            );
        }
        assert!(base
            .tightened(&AdmissionOverlay {
                block_multipart_hosts: BTreeSet::from(["Upper.Case".to_string()]),
                ..Default::default()
            })
            .is_err());
        // The overlay type cannot even express removing a rule: unknown fields are errors.
        assert!(serde_json::from_str::<AdmissionOverlay>(
            r#"{"deny_multipart_fields":[],"disable_cgi_rule":true}"#
        )
        .is_err());
        let too_many: BTreeSet<String> = (0..300).map(|i| format!("f{i}")).collect();
        assert!(base
            .tightened(&AdmissionOverlay {
                deny_multipart_fields: too_many,
                ..Default::default()
            })
            .is_err());
    }

    #[test]
    fn as_overlay_round_trips_through_json_to_the_same_configuration() {
        let o = AdmissionOverlay {
            max_params: Some(50),
            deny_multipart_fields: BTreeSet::from(["X_PROGRESS".to_string()]),
            block_multipart_hosts: BTreeSet::from(["a.example.com".to_string()]),
            ..Default::default()
        };
        let c = cfg().tightened(&o).unwrap_or_default();
        let json = serde_json::to_string(&c.as_overlay()).unwrap_or_default();
        let back: AdmissionOverlay = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(cfg().tightened(&back).unwrap_or_default(), c);
    }

    #[test]
    fn multipart_shape_limits_and_filenames() {
        assert_eq!(
            with_headers(&[("content-type", b"multipart/form-data")], b"x"),
            Verdict::Reject(Rule::MalformedMultipart)
        );
        assert_eq!(
            with_headers(&[("content-type", b"multipart/form-data; boundary=")], b"x"),
            Verdict::Reject(Rule::MalformedMultipart)
        );
        let long = format!("multipart/form-data; boundary={}", "a".repeat(71));
        assert_eq!(
            with_headers(&[("content-type", long.as_bytes())], b"x"),
            Verdict::Reject(Rule::MalformedMultipart)
        );
        assert_eq!(
            with_headers(&[MP], b"no delimiters at all"),
            Verdict::Reject(Rule::MalformedMultipart)
        );
        // Part headers that never end.
        let unterminated = [
            b"--XyZ\r\nContent-Disposition: form-data; name=\"a\"".as_slice(),
            &vec![b'a'; 9000],
        ]
        .concat();
        assert_eq!(
            with_headers(&[MP], &unterminated),
            Verdict::Reject(Rule::MalformedMultipart)
        );
        // Part count.
        let many: Vec<(String, Option<&str>)> = (0..=MAX_MULTIPART_PARTS)
            .map(|i| (format!("f{i}"), None))
            .collect();
        let refs: Vec<(&str, Option<&str>)> = many.iter().map(|(n, f)| (n.as_str(), *f)).collect();
        assert_eq!(
            with_headers(&[MP], &multipart(&refs)),
            Verdict::Reject(Rule::MultipartTooManyParts)
        );
        assert_eq!(
            with_headers(&[MP], &multipart(&refs[..MAX_MULTIPART_PARTS])),
            Verdict::Allow
        );
        // Filenames.
        for f in ["a\0.php", "../../x.php", "a/b.php", "a\\b.php"] {
            assert_eq!(
                with_headers(&[MP], &multipart(&[("file", Some(f))])),
                Verdict::Reject(Rule::UploadFilename),
                "{f:?}"
            );
        }
        assert_eq!(
            with_headers(&[MP], &multipart(&[("file", Some(&"a".repeat(300)))])),
            Verdict::Reject(Rule::UploadFilename)
        );
        // Nesting in a field name.
        let deep = format!("a{}", "[b]".repeat(MAX_PARAM_NESTING + 1));
        assert_eq!(
            with_headers(&[MP], &multipart(&[(&deep, None)])),
            Verdict::Reject(Rule::ParamNesting)
        );
        // Oversized scan.
        let small = AdmissionConfig {
            max_multipart_scan_bytes: 64,
            ..cfg()
        };
        let big = multipart(&[("a", None), ("b", None), ("c", None)]);
        assert_eq!(
            check(
                &small,
                &RequestView {
                    target: "/u",
                    headers: &[MP],
                    body: &big
                }
            ),
            Verdict::Reject(Rule::MalformedMultipart)
        );
    }

    #[test]
    fn parameter_count_and_nesting_limits_apply_to_query_and_urlencoded_bodies() {
        let many = (0..=MAX_PARAMS)
            .map(|i| format!("p{i}=1"))
            .collect::<Vec<_>>()
            .join("&");
        assert_eq!(
            get(&format!("/a?{many}")),
            Verdict::Reject(Rule::TooManyParams)
        );
        let ok = (0..MAX_PARAMS)
            .map(|i| format!("p{i}=1"))
            .collect::<Vec<_>>()
            .join("&");
        assert_eq!(get(&format!("/a?{ok}")), Verdict::Allow);
        let deep = format!("a{}=1", "%5Bb%5D".repeat(MAX_PARAM_NESTING + 1));
        assert_eq!(
            get(&format!("/a?{deep}")),
            Verdict::Reject(Rule::ParamNesting)
        );
        assert_eq!(
            get(&format!("/a?{}=1", "a[b]".repeat(MAX_PARAM_NESTING))),
            Verdict::Allow,
            "exactly the limit is allowed"
        );
        let form: &[(&str, &[u8])] = &[("content-type", b"application/x-www-form-urlencoded")];
        assert_eq!(
            check(
                &cfg(),
                &RequestView {
                    target: "/p",
                    headers: form,
                    body: many.as_bytes()
                }
            ),
            Verdict::Reject(Rule::TooManyParams)
        );
        assert_eq!(
            check(
                &cfg(),
                &RequestView {
                    target: "/p",
                    headers: form,
                    body: deep.as_bytes()
                }
            ),
            Verdict::Reject(Rule::ParamNesting)
        );
        assert_eq!(
            check(
                &cfg(),
                &RequestView {
                    target: "/p",
                    headers: form,
                    body: b"a=1&b=2"
                }
            ),
            Verdict::Allow
        );
    }

    #[test]
    fn session_cookies_cookie_size_and_header_hygiene() {
        let ok = format!("theme=dark; PHPSESSID={}", "a1B2-,".repeat(8));
        assert_eq!(
            with_headers(&[("cookie", ok.as_bytes())], b""),
            Verdict::Allow
        );
        for bad in [
            "PHPSESSID=",
            "PHPSESSID=ab%00c",
            "PHPSESSID=../../etc",
            "PHPSESSID=a b",
            "x=1; PHPSESSID=<script>",
        ] {
            assert_eq!(
                with_headers(&[("cookie", bad.as_bytes())], b""),
                Verdict::Reject(Rule::MalformedSessionCookie),
                "{bad}"
            );
        }
        let huge = format!("PHPSESSID={}", "a".repeat(MAX_SESSION_ID_LEN + 1));
        assert_eq!(
            with_headers(&[("cookie", huge.as_bytes())], b""),
            Verdict::Reject(Rule::MalformedSessionCookie)
        );
        let at_limit = format!("PHPSESSID={}", "a".repeat(MAX_SESSION_ID_LEN));
        assert_eq!(
            with_headers(&[("cookie", at_limit.as_bytes())], b""),
            Verdict::Allow
        );
        let big_cookie = format!("a={}", "x".repeat(MAX_COOKIE_BYTES));
        assert_eq!(
            with_headers(&[("cookie", big_cookie.as_bytes())], b""),
            Verdict::Reject(Rule::CookieTooLarge)
        );
        // A cookie named differently is not validated as a PHP session id.
        assert_eq!(
            with_headers(&[("cookie", b"sid=<anything goes>")], b""),
            Verdict::Allow
        );

        for v in [&b"a\r\nX-Evil: 1"[..], b"a\nb", b"a\0b"] {
            assert_eq!(
                with_headers(&[("x-test", v)], b""),
                Verdict::Reject(Rule::HeaderInjection)
            );
        }
        assert_eq!(
            with_headers(&[("bad name", b"v")], b""),
            Verdict::Reject(Rule::HeaderInjection)
        );
        let many: Vec<(String, Vec<u8>)> = (0..=MAX_HEADER_COUNT)
            .map(|i| (format!("x-h{i}"), b"v".to_vec()))
            .collect();
        let refs: Vec<(&str, &[u8])> = many
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        assert_eq!(with_headers(&refs, b""), Verdict::Reject(Rule::HeaderFlood));
        assert_eq!(with_headers(&refs[..MAX_HEADER_COUNT], b""), Verdict::Allow);
        let fat = vec![b'x'; MAX_HEADER_BYTES];
        assert_eq!(
            with_headers(&[("x-fat", fat.as_slice())], b""),
            Verdict::Reject(Rule::HeaderFlood)
        );
    }

    #[test]
    fn every_rule_has_a_unique_label_and_a_client_error_status() {
        let labels: BTreeSet<&str> = Rule::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(labels.len(), Rule::ALL.len());
        for r in Rule::ALL {
            assert!((400..500).contains(&r.status()), "{r:?}");
        }
        assert_eq!(Rule::CgiArgumentInjection.status(), 403);
        assert_eq!(Rule::TargetTooLong.status(), 414);
    }

    #[test]
    fn decoding_is_total_and_bounded() {
        assert_eq!(pct_decode(b"%41%4a%zz%4"), b"AJ%zz%4".to_vec());
        assert_eq!(pct_decode(b"%"), b"%".to_vec());
        assert_eq!(pct_decode(b""), Vec::<u8>::new());
        // A pathological target of percent signs is linear and cannot panic.
        assert_eq!(get(&"%".repeat(MAX_TARGET_BYTES - 1)), Verdict::Allow);
        assert_eq!(get(&"%2f".repeat(2000)), Verdict::Allow);
    }
}
