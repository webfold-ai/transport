//! Is the CA we are about to rely on still trusted by the programs that decide whether browsers
//! accept its certificates?
//!
//! Two machine-readable signals exist, and this module reads both:
//!
//! * **Mozilla / NSS**, through the CCADB "Included CA Certificate Report" (CSV, one row per root
//!   in Mozilla's store, with the `Distrust for TLS After Date` and `Trust Bits` columns). A root
//!   missing from the report has been removed; one without the `Websites` trust bit no longer
//!   serves TLS; one with a distrust-after date stops being trusted for certificates issued after
//!   it.
//! * **Chrome**, through the Chrome Root Store (`root_store.textproto` in the Chromium tree: one
//!   `trust_anchors` block per root, with `constraints { sct_not_after_sec }` for a distrust-after
//!   and absence for removal).
//!
//! What this is **for**: noticing, from published data and before an incident reaches us, that a
//! CA we issue from has lost (or is about to lose) trust, so the renewal engine can start moving
//! ([`crate::ca_resilience::MultiCaIssuer::apply_trust`]) and operators are told. What it is **not**:
//! a trust decision about a certificate (that is a path validator's job) or a substitute for
//! reading the incident report.
//!
//! ## Failure discipline
//! * Every fetch is HTTPS with certificate verification on (the crate's TLS client), has a
//!   deadline and a byte cap, and does not follow redirects ([`HttpsSource`]).
//! * A document that does not parse, lacks the columns/fields this reader depends on, or is
//!   implausibly small is a [`TrustVerdict::Unknown`] — **never** a "removed" verdict. A parser
//!   that cannot read the data must not, by saying nothing, claim a CA lost trust.
//! * `Unknown` never escalates and never relaxes anything: no outage action is taken on a fetch
//!   or parse failure alone.
//! * A verdict is only as good as the roots it is told to watch. [`Observed`] feeds in the roots
//!   the chains we actually hold lead to, and an observed root the CA's configuration does not
//!   cover is reported ([`unwatched_anchors`]) rather than ignored.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::acme::days_from_civil;
use crate::ca_policy::{CaPolicy, RootRef};
use crate::x509::ChainTop;
use crate::BoxFuture;

/// Where Mozilla's CCADB publishes the Included CA Certificate Report (CSV).
pub const CCADB_INCLUDED_CSV: &str =
    "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportCSVFormat";
/// The Chrome Root Store source file, via Gitiles' base64 view. Several mirrors of the same path
/// are listed because Gitiles intermittently answers 503; they are tried in order.
pub const CHROME_ROOT_STORE_URLS: [&str; 2] = [
    "https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/data/ssl/chrome_root_store/root_store.textproto?format=TEXT",
    "https://chromium.googlesource.com/chromium/src.git/+/refs/heads/main/net/data/ssl/chrome_root_store/root_store.textproto?format=TEXT",
];

/// Largest CCADB report accepted (the real one is ~0.2 MiB).
pub const MAX_CCADB_BYTES: usize = 8 * 1024 * 1024;
/// Largest Chrome Root Store document accepted (the real one is ~0.1 MiB, base64).
pub const MAX_CHROME_BYTES: usize = 4 * 1024 * 1024;
/// A report with fewer roots than this is an error page or a truncation, not a root store.
const MIN_PLAUSIBLE_ROOTS: usize = 40;

// ── verdicts ──────────────────────────────────────────────────────────────────────────────

/// What a root program says about a CA, or the two programs together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustVerdict {
    /// Every watched root is trusted for TLS with no distrust date.
    Trusted,
    /// A watched root carries a future distrust-after date (or some, not all, are gone):
    /// certificates issued from it after `after` (unix seconds) will not be trusted.
    DistrustPending { after: i64 },
    /// No watched root can anchor a certificate issued now: removed, no longer trusted for TLS, or
    /// past its distrust-after date. Or a root our current certificates chain to is in that state.
    Distrusted { reason: String },
    /// There is not enough information: a fetch or parse failed, or the CA has no watched roots.
    Unknown { reason: String },
}

impl TrustVerdict {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            TrustVerdict::Trusted => "trusted",
            TrustVerdict::DistrustPending { .. } => "distrust_pending",
            TrustVerdict::Distrusted { .. } => "distrusted",
            TrustVerdict::Unknown { .. } => "unknown",
        }
    }

    /// Combine two programs' verdicts. `Trusted` only if both are; evidence of distrust from
    /// either wins; missing information from either (with no distrust evidence) is `Unknown`, so
    /// that one program's silence can never wash out the other's warning.
    #[must_use]
    pub fn combine(a: &TrustVerdict, b: &TrustVerdict) -> TrustVerdict {
        use TrustVerdict::{DistrustPending, Distrusted, Trusted, Unknown};
        match (a, b) {
            (Distrusted { reason: x }, Distrusted { reason: y }) => Distrusted {
                reason: format!("{x}; {y}"),
            },
            (Distrusted { .. }, _) => a.clone(),
            (_, Distrusted { .. }) => b.clone(),
            (DistrustPending { after: x }, DistrustPending { after: y }) => {
                DistrustPending { after: *x.min(y) }
            }
            (DistrustPending { .. }, _) => a.clone(),
            (_, DistrustPending { .. }) => b.clone(),
            (Unknown { reason: x }, Unknown { reason: y }) => Unknown {
                reason: format!("{x}; {y}"),
            },
            (Unknown { .. }, _) => a.clone(),
            (_, Unknown { .. }) => b.clone(),
            (Trusted, Trusted) => Trusted,
        }
    }
}

/// One CA's standing in each program and overall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaTrust {
    pub ca: String,
    pub mozilla: TrustVerdict,
    pub chrome: TrustVerdict,
    pub combined: TrustVerdict,
}

/// A root a held certificate chains to, attributed to the CA that issued it.
#[derive(Clone, Debug)]
pub struct Observed {
    pub ca: String,
    pub top: ChainTop,
}

// ── CCADB (Mozilla) ───────────────────────────────────────────────────────────────────────

/// One root in Mozilla's store, from the CCADB report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MozillaRoot {
    pub owner: String,
    pub name: String,
    /// SHA-256 fingerprint, lower-case hex.
    pub sha256: String,
    /// Whether the `Websites` trust bit is set.
    pub websites: bool,
    /// `Distrust for TLS After Date`, unix seconds at 00:00:00 UTC of that day.
    pub tls_distrust_after: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MozillaStore {
    pub roots: Vec<MozillaRoot>,
}

/// Parse an RFC 4180 CSV document: quoted fields, `""` escapes, line breaks inside quotes.
/// Bounded in rows, columns and field size.
fn parse_csv(text: &str) -> Result<Vec<Vec<String>>, String> {
    const MAX_ROWS: usize = 20_000;
    const MAX_COLS: usize = 128;
    const MAX_FIELD: usize = 64 * 1024;
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut was_quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if field.len() > MAX_FIELD {
            return Err("a CSV field is implausibly large".into());
        }
        match (quoted, c) {
            (true, '"') => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            }
            (true, c) => field.push(c),
            (false, '"') if field.is_empty() && !was_quoted => {
                quoted = true;
                was_quoted = true;
            }
            (false, ',') => {
                row.push(std::mem::take(&mut field));
                was_quoted = false;
                if row.len() > MAX_COLS {
                    return Err("a CSV row has too many columns".into());
                }
            }
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                was_quoted = false;
                rows.push(std::mem::take(&mut row));
                if rows.len() > MAX_ROWS {
                    return Err("the CSV has too many rows".into());
                }
            }
            (false, c) => field.push(c),
        }
    }
    if quoted {
        return Err("the CSV ends inside a quoted field".into());
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

/// `YYYY.MM.DD` (CCADB's date format) -> unix seconds at 00:00:00 UTC.
fn parse_ccadb_date(s: &str) -> Option<i64> {
    let mut it = s.trim().split('.');
    let (y, m, d): (i64, i64, i64) = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    if it.next().is_some()
        || !(1970..=9999).contains(&y)
        || !(1..=12).contains(&m)
        || !(1..=31).contains(&d)
    {
        return None;
    }
    Some(days_from_civil(y, m, d) * 86_400)
}

/// Parse the CCADB Included CA Certificate Report.
///
/// # Errors
/// A document that is not that report: missing columns, a malformed fingerprint or date, or fewer
/// roots than a real store has (an error page, a truncation). Never a partial result.
pub fn parse_ccadb(bytes: &[u8]) -> Result<MozillaStore, String> {
    if bytes.len() > MAX_CCADB_BYTES {
        return Err("the CCADB report is larger than expected".into());
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| "the CCADB report is not UTF-8".to_string())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let rows = parse_csv(text)?;
    let header = rows.first().ok_or("the CCADB report is empty")?;
    let col = |name: &str| {
        header
            .iter()
            .position(|h| h.trim() == name)
            .ok_or_else(|| format!("the CCADB report has no '{name}' column"))
    };
    let (c_owner, c_name, c_sha, c_bits, c_tls) = (
        col("Owner")?,
        col("Common Name or Certificate Name")?,
        col("SHA-256 Fingerprint")?,
        col("Trust Bits")?,
        col("Distrust for TLS After Date")?,
    );
    let mut roots = Vec::new();
    for (i, r) in rows.iter().enumerate().skip(1) {
        if r.len() == 1 && r[0].is_empty() {
            continue; // a blank line
        }
        let get = |c: usize| {
            r.get(c)
                .map(String::as_str)
                .ok_or_else(|| format!("row {i} is short"))
        };
        let sha = get(c_sha)?.trim().to_ascii_lowercase();
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("row {i} has a malformed SHA-256 fingerprint"));
        }
        let tls = get(c_tls)?.trim();
        let tls_distrust_after = if tls.is_empty() {
            None
        } else {
            Some(
                parse_ccadb_date(tls)
                    .ok_or_else(|| format!("row {i} has a malformed distrust date {tls:?}"))?,
            )
        };
        roots.push(MozillaRoot {
            owner: get(c_owner)?.trim().to_string(),
            name: get(c_name)?.trim().to_string(),
            sha256: sha,
            websites: get(c_bits)?
                .split(';')
                .any(|b| b.trim().eq_ignore_ascii_case("Websites")),
            tls_distrust_after,
        });
    }
    if roots.len() < MIN_PLAUSIBLE_ROOTS {
        return Err(format!(
            "the CCADB report lists only {} roots; refusing to treat it as the Mozilla root store",
            roots.len()
        ));
    }
    Ok(MozillaStore { roots })
}

// ── Chrome Root Store ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChromeAnchor {
    pub sha256: String,
    /// The `# CN=..., O=...` comment line above the block, when present (informational).
    pub label: Option<String>,
    /// The earliest `sct_not_after_sec` / `sct_all_after_sec` that applies to current Chrome
    /// versions: certificates with SCTs after it are distrusted.
    pub tls_distrust_after: Option<i64>,
    /// Whether a current-version constraint restricts DNS names (`permitted_dns_names`): the root
    /// is trusted only for those names, which this reader does not evaluate.
    pub name_constrained: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChromeStore {
    pub version_major: Option<u32>,
    pub anchors: Vec<ChromeAnchor>,
}

#[derive(Debug)]
enum Val {
    Str(Vec<u8>),
    Atom(String),
    Msg(Vec<(String, Val)>),
}

struct Tok<'a> {
    s: &'a [u8],
    i: usize,
    fields: usize,
    last_comment: Option<String>,
}

const MAX_TEXTPROTO_DEPTH: usize = 8;
const MAX_TEXTPROTO_FIELDS: usize = 100_000;

impl<'a> Tok<'a> {
    fn skip_ws(&mut self) {
        loop {
            while self.s.get(self.i).is_some_and(|b| b.is_ascii_whitespace()) {
                self.i += 1;
            }
            if self.s.get(self.i) == Some(&b'#') {
                let start = self.i + 1;
                while self.s.get(self.i).is_some_and(|b| *b != b'\n') {
                    self.i += 1;
                }
                let line = String::from_utf8_lossy(&self.s[start..self.i])
                    .trim()
                    .to_string();
                if line.starts_with("CN=") || line.starts_with("\"CN=") {
                    self.last_comment = Some(line.trim_matches('"').to_string());
                }
            } else {
                return;
            }
        }
    }

    fn ident(&mut self) -> Result<String, String> {
        self.skip_ws();
        let start = self.i;
        while self.s.get(self.i).is_some_and(|b| {
            b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.' || *b == b'-' || *b == b'+'
        }) {
            self.i += 1;
        }
        if start == self.i {
            return Err(format!("expected a field name at byte {start}"));
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn string(&mut self) -> Result<Vec<u8>, String> {
        let quote = self.s[self.i];
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let b = *self.s.get(self.i).ok_or("unterminated string")?;
            self.i += 1;
            if b == quote {
                return Ok(out);
            }
            if b != b'\\' {
                out.push(b);
                continue;
            }
            let e = *self.s.get(self.i).ok_or("unterminated escape")?;
            self.i += 1;
            match e {
                b'n' => out.push(b'\n'),
                b't' => out.push(b'\t'),
                b'r' => out.push(b'\r'),
                b'"' | b'\'' | b'\\' => out.push(e),
                b'x' | b'X' => {
                    let hex = std::str::from_utf8(
                        self.s.get(self.i..self.i + 2).ok_or("short \\x escape")?,
                    )
                    .map_err(|_| "bad \\x escape")?;
                    out.push(u8::from_str_radix(hex, 16).map_err(|_| "bad \\x escape")?);
                    self.i += 2;
                }
                b'0'..=b'7' => {
                    let end = (self.i + 2).min(self.s.len());
                    let digits = std::str::from_utf8(&self.s[self.i - 1..end.max(self.i)])
                        .map_err(|_| "bad octal escape")?;
                    let take = digits
                        .bytes()
                        .take(3)
                        .take_while(|d| (b'0'..=b'7').contains(d))
                        .count();
                    out.push(
                        u8::from_str_radix(&digits[..take], 8).map_err(|_| "bad octal escape")?,
                    );
                    self.i += take - 1;
                }
                _ => return Err("unknown string escape".into()),
            }
        }
    }

    fn message(&mut self, depth: usize, until_brace: bool) -> Result<Vec<(String, Val)>, String> {
        if depth > MAX_TEXTPROTO_DEPTH {
            return Err("text-proto nests too deeply".into());
        }
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            match self.s.get(self.i) {
                None if until_brace => return Err("unterminated message".into()),
                None => return Ok(out),
                Some(b'}') if until_brace => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b';' | b',') => {
                    self.i += 1;
                    continue;
                }
                Some(_) => {}
            }
            self.fields += 1;
            if self.fields > MAX_TEXTPROTO_FIELDS {
                return Err("text-proto has too many fields".into());
            }
            let comment = self.last_comment.take();
            let name = self.ident()?;
            self.skip_ws();
            let had_colon = self.s.get(self.i) == Some(&b':');
            if had_colon {
                self.i += 1;
                self.skip_ws();
            }
            let val = match self.s.get(self.i) {
                Some(b'{') => {
                    self.i += 1;
                    let mut fields = self.message(depth + 1, true)?;
                    if let Some(c) = comment {
                        fields.insert(0, ("#label".to_string(), Val::Str(c.into_bytes())));
                    }
                    Val::Msg(fields)
                }
                Some(b'"' | b'\'') => {
                    let mut v = self.string()?;
                    // Adjacent string literals concatenate.
                    loop {
                        self.skip_ws();
                        if matches!(self.s.get(self.i), Some(b'"' | b'\'')) {
                            v.extend(self.string()?);
                        } else {
                            break;
                        }
                    }
                    Val::Str(v)
                }
                Some(_) if had_colon => Val::Atom(self.ident()?),
                _ => return Err(format!("expected a value for '{name}'")),
            };
            out.push((name, val));
        }
    }
}

fn atom_u64(v: &Val) -> Option<u64> {
    match v {
        Val::Atom(a) => a.parse().ok(),
        _ => None,
    }
}

/// Parse the Chrome Root Store text-proto.
///
/// # Errors
/// Anything that is not that document, or that yields fewer anchors than a real store has.
pub fn parse_chrome_root_store(bytes: &[u8]) -> Result<ChromeStore, String> {
    if bytes.len() > MAX_CHROME_BYTES {
        return Err("the Chrome root store document is larger than expected".into());
    }
    let mut tok = Tok {
        s: bytes,
        i: 0,
        fields: 0,
        last_comment: None,
    };
    let top = tok.message(0, false)?;
    let mut store = ChromeStore::default();
    for (name, val) in &top {
        match (name.as_str(), val) {
            ("version_major", v) => {
                store.version_major = atom_u64(v).and_then(|n| u32::try_from(n).ok())
            }
            ("trust_anchors", Val::Msg(fields)) => {
                let mut sha = None;
                let mut label = None;
                let (mut after, mut constrained) = (None::<i64>, false);
                for (k, v) in fields {
                    match (k.as_str(), v) {
                        ("#label", Val::Str(s)) => {
                            label = Some(String::from_utf8_lossy(s).into_owned())
                        }
                        ("sha256_hex", Val::Str(s)) => {
                            sha = Some(String::from_utf8_lossy(s).to_ascii_lowercase())
                        }
                        ("constraints", Val::Msg(c)) => {
                            let has = |key: &str| c.iter().any(|(k, _)| k == key);
                            // A constraint scoped to *older* Chrome versions (max_version_exclusive without min_version) does not apply to current ones.
                            if has("max_version_exclusive") && !has("min_version") {
                                continue;
                            }
                            for (ck, cv) in c {
                                match ck.as_str() {
                                    "sct_not_after_sec" | "sct_all_after_sec" => {
                                        let t = atom_u64(cv)
                                            .and_then(|n| i64::try_from(n).ok())
                                            .ok_or("a distrust time is not a number")?;
                                        after = Some(after.map_or(t, |a| a.min(t)));
                                    }
                                    "permitted_dns_names" => constrained = true,
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                let sha256 = sha
                    .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                    .ok_or("a trust_anchors block has no valid sha256_hex")?;
                store.anchors.push(ChromeAnchor {
                    sha256,
                    label,
                    tls_distrust_after: after,
                    name_constrained: constrained,
                });
            }
            _ => {}
        }
    }
    if store.anchors.len() < MIN_PLAUSIBLE_ROOTS {
        return Err(format!("the Chrome root store document lists only {} anchors; refusing to treat it as the root store", store.anchors.len()));
    }
    Ok(store)
}

/// Gitiles serves a file as base64 with `?format=TEXT`.
///
/// # Errors
/// Not valid base64.
pub fn decode_gitiles(body: &[u8]) -> Result<Vec<u8>, String> {
    let text =
        std::str::from_utf8(body).map_err(|_| "the Gitiles response is not text".to_string())?;
    crate::pem::base64_decode(text).ok_or_else(|| "the Gitiles response is not base64".to_string())
}

// ── evaluation ────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
enum RootState {
    Trusted,
    /// A future distrust-after date.
    Pending(i64),
    /// Not usable for new certificates: removed, no TLS trust, or past its distrust-after date.
    Gone(String),
    /// The root cannot be looked up in this program's data.
    Unresolved(String),
}

fn day(t: i64) -> String {
    // civil-from-days (Howard Hinnant), for messages only.
    let z = t.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{m:02}-{d:02}", yoe + era * 400 + i64::from(m <= 2))
}

fn after_state(label: &str, after: Option<i64>, now: i64) -> RootState {
    match after {
        Some(t) if t <= now => RootState::Gone(format!(
            "{label} is past its distrust-after date {}",
            day(t)
        )),
        Some(t) => RootState::Pending(t),
        None => RootState::Trusted,
    }
}

fn mozilla_state(store: &MozillaStore, r: &RootRef, now: i64) -> RootState {
    let rows: Vec<&MozillaRoot> = match (&r.sha256, &r.name) {
        (Some(h), _) => store
            .roots
            .iter()
            .filter(|m| m.sha256.eq_ignore_ascii_case(h))
            .collect(),
        (_, Some(n)) => store
            .roots
            .iter()
            .filter(|m| m.name.eq_ignore_ascii_case(n.trim()))
            .collect(),
        _ => Vec::new(),
    };
    let what = r
        .sha256
        .as_deref()
        .map(|h| format!("root {}", &h[..16.min(h.len())]))
        .or_else(|| r.name.clone())
        .unwrap_or_default();
    if rows.is_empty() {
        return RootState::Gone(format!("{what} is not in Mozilla's root store"));
    }
    // Several rows (cross-signs share a name): the root is usable if any row is.
    let states: Vec<RootState> = rows
        .iter()
        .map(|m| {
            if !m.websites {
                RootState::Gone(format!(
                    "{what} no longer has the Websites trust bit in Mozilla's store"
                ))
            } else {
                after_state(&format!("{what} (Mozilla)"), m.tls_distrust_after, now)
            }
        })
        .collect();
    best(states)
}

fn chrome_state(
    store: &ChromeStore,
    mozilla: Option<&MozillaStore>,
    r: &RootRef,
    now: i64,
) -> RootState {
    // A name resolves to fingerprints through CCADB; Chrome lists fingerprints.
    let shas: Vec<String> = match (&r.sha256, &r.name) {
        (Some(h), _) => vec![h.to_ascii_lowercase()],
        (_, Some(n)) => {
            let from_ccadb: Vec<String> = mozilla
                .map(|m| {
                    m.roots
                        .iter()
                        .filter(|x| x.name.eq_ignore_ascii_case(n.trim()))
                        .map(|x| x.sha256.clone())
                        .collect()
                })
                .unwrap_or_default();
            if from_ccadb.is_empty() {
                // Fall back to the comment labels in the Chrome file itself.
                let by_label: Vec<String> = store
                    .anchors
                    .iter()
                    .filter(|a| {
                        a.label.as_deref().is_some_and(|l| {
                            l.strip_prefix("CN=").is_some_and(|rest| {
                                rest.split(',')
                                    .next()
                                    .is_some_and(|cn| cn.trim().eq_ignore_ascii_case(n.trim()))
                            })
                        })
                    })
                    .map(|a| a.sha256.clone())
                    .collect();
                if by_label.is_empty() {
                    return RootState::Unresolved(format!(
                        "cannot map '{n}' to a fingerprint for the Chrome root store"
                    ));
                }
                by_label
            } else {
                from_ccadb
            }
        }
        _ => {
            return RootState::Unresolved(
                "a trust root names neither a fingerprint nor a name".into(),
            )
        }
    };
    let what = r
        .name
        .clone()
        .or_else(|| {
            r.sha256
                .as_ref()
                .map(|h| format!("root {}", &h[..16.min(h.len())]))
        })
        .unwrap_or_default();
    let states: Vec<RootState> = shas
        .iter()
        .map(
            |sha| match store.anchors.iter().find(|a| &a.sha256 == sha) {
                None => RootState::Gone(format!("{what} is not in the Chrome Root Store")),
                Some(a) => after_state(&format!("{what} (Chrome)"), a.tls_distrust_after, now),
            },
        )
        .collect();
    best(states)
}

/// A root with several rows/fingerprints is usable if any of them is: prefer Trusted, then
/// Pending (earliest), then Unresolved, else Gone.
fn best(states: Vec<RootState>) -> RootState {
    if states.contains(&RootState::Trusted) {
        return RootState::Trusted;
    }
    if let Some(t) = states
        .iter()
        .filter_map(|s| {
            if let RootState::Pending(t) = s {
                Some(*t)
            } else {
                None
            }
        })
        .max()
    {
        return RootState::Pending(t);
    }
    if let Some(u) = states
        .iter()
        .find(|s| matches!(s, RootState::Unresolved(_)))
    {
        return u.clone();
    }
    states
        .into_iter()
        .next()
        .unwrap_or_else(|| RootState::Unresolved("no data".into()))
}

fn verdict_of(states: &[RootState], observed_bad: Option<String>) -> TrustVerdict {
    if let Some(why) = observed_bad {
        return TrustVerdict::Distrusted { reason: why };
    }
    if states.is_empty() {
        return TrustVerdict::Unknown {
            reason: "no trust_roots are configured for this CA".into(),
        };
    }
    let gone: Vec<&str> = states
        .iter()
        .filter_map(|s| {
            if let RootState::Gone(w) = s {
                Some(w.as_str())
            } else {
                None
            }
        })
        .collect();
    if gone.len() == states.len() {
        return TrustVerdict::Distrusted {
            reason: gone.join("; "),
        };
    }
    let earliest_pending = states
        .iter()
        .filter_map(|s| {
            if let RootState::Pending(t) = s {
                Some(*t)
            } else {
                None
            }
        })
        .min();
    if let Some(t) = earliest_pending {
        return TrustVerdict::DistrustPending { after: t };
    }
    if !gone.is_empty() {
        // Some, not all, of the watched roots are gone: a chain to one of them is already broken.
        return TrustVerdict::DistrustPending { after: i64::MIN };
    }
    if let Some(RootState::Unresolved(why)) = states
        .iter()
        .find(|s| matches!(s, RootState::Unresolved(_)))
    {
        return TrustVerdict::Unknown {
            reason: why.clone(),
        };
    }
    TrustVerdict::Trusted
}

/// `(Mozilla's complaint, Chrome's complaint)` about the root an observed chain leads to.
type ObservedProblems = (Option<String>, Option<String>);

/// The roots an observed certificate chain leads to, looked up in `moz`/`chrome` and judged:
/// `Some(why)` if the root our certificate depends on is already unusable.
fn observed_problem(
    moz: Option<&MozillaStore>,
    chrome: Option<&ChromeStore>,
    top: &ChainTop,
    now: i64,
) -> ObservedProblems {
    // A self-issued top is the root: judge it by fingerprint. Otherwise it is an intermediate and
    // its issuer is the root; judge that by name.
    let r = if top.self_issued {
        RootRef {
            sha256: Some(top.fingerprint.clone()),
            name: None,
        }
    } else {
        RootRef {
            sha256: None,
            name: top.issuer_cn.clone(),
        }
    };
    if r.sha256.is_none() && r.name.is_none() {
        return (None, None);
    }
    let bad = |s: RootState| {
        if let RootState::Gone(w) = s {
            Some(format!(
                "a certificate we hold chains to a root that is unusable: {w}"
            ))
        } else {
            None
        }
    };
    (
        moz.and_then(|m| bad(mozilla_state(m, &r, now))),
        chrome.and_then(|c| bad(chrome_state(c, moz, &r, now))),
    )
}

/// Evaluate every CA on the policy against the two programs. Each program is either its parsed
/// data or the reason it is unavailable; an unavailable program gives `Unknown`.
#[must_use]
pub fn evaluate(
    policy: &CaPolicy,
    mozilla: Result<&MozillaStore, &str>,
    chrome: Result<&ChromeStore, &str>,
    observed: &[Observed],
    now: i64,
) -> Vec<CaTrust> {
    let (moz, chr) = (mozilla.ok(), chrome.ok());
    policy
        .cas
        .iter()
        .map(|ca| {
            let mine: Vec<&Observed> = observed.iter().filter(|o| o.ca == ca.name).collect();
            let per_program = |available: Result<(), &str>,
                               judge: &dyn Fn(&RootRef) -> RootState,
                               pick: &dyn Fn(&ObservedProblems) -> Option<String>|
             -> TrustVerdict {
                if let Err(why) = available {
                    return TrustVerdict::Unknown {
                        reason: why.to_string(),
                    };
                }
                let states: Vec<RootState> = ca.trust_roots.iter().map(judge).collect();
                let observed_bad = mine
                    .iter()
                    .find_map(|o| pick(&observed_problem(moz, chr, &o.top, now)));
                verdict_of(&states, observed_bad)
            };
            let m = per_program(
                match &mozilla {
                    Ok(_) => Ok(()),
                    Err(e) => Err(*e),
                },
                &|r| mozilla_state(moz.unwrap_or(&MozillaStore::default()), r, now),
                &|p| p.0.clone(),
            );
            let c = per_program(
                match &chrome {
                    Ok(_) => Ok(()),
                    Err(e) => Err(*e),
                },
                &|r| chrome_state(chr.unwrap_or(&ChromeStore::default()), moz, r, now),
                &|p| p.1.clone(),
            );
            let combined = TrustVerdict::combine(&m, &c);
            CaTrust {
                ca: ca.name.clone(),
                mozilla: m,
                chrome: c,
                combined,
            }
        })
        .collect()
}

/// Observed roots the CA's configured `trust_roots` do not cover: the chain a certificate we hold
/// leads to a root nobody is watching. Returns `(ca, description)`.
#[must_use]
pub fn unwatched_anchors(policy: &CaPolicy, observed: &[Observed]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for o in observed {
        let Some(ca) = policy.get(&o.ca) else {
            continue;
        };
        let (fp, name) = if o.top.self_issued {
            (
                Some(o.top.fingerprint.as_str()),
                o.top.subject_cn.as_deref(),
            )
        } else {
            (None, o.top.issuer_cn.as_deref())
        };
        let covered = ca.trust_roots.iter().any(|r| {
            r.sha256
                .as_deref()
                .is_some_and(|h| fp.is_some_and(|f| f.eq_ignore_ascii_case(h)))
                || r.name
                    .as_deref()
                    .is_some_and(|n| name.is_some_and(|x| x.eq_ignore_ascii_case(n.trim())))
        });
        if !covered {
            let described = name.map_or_else(
                || {
                    format!(
                        "root {}",
                        &o.top.fingerprint[..16.min(o.top.fingerprint.len())]
                    )
                },
                str::to_string,
            );
            let d = format!(
                "certificates from '{}' chain to '{described}', which is not among its trust_roots",
                ca.name
            );
            if !out
                .iter()
                .any(|(c, x): &(String, String)| c == &o.ca && x == &d)
            {
                out.push((o.ca.clone(), d));
            }
        }
    }
    out
}

// ── fetching ──────────────────────────────────────────────────────────────────────────────

/// Fetches a published document. A trait so evaluation is testable offline.
pub trait SignalSource: Send + Sync {
    /// The body at `url`, at most `max_bytes`.
    ///
    /// # Errors
    /// Any failure, as text. A caller treats every error the same way: `Unknown`.
    fn fetch<'a>(
        &'a self,
        url: &'a str,
        max_bytes: usize,
    ) -> BoxFuture<'a, Result<Vec<u8>, String>>;
}

/// The real source: HTTPS only, certificate verification on (the crate's TLS client), a deadline,
/// a byte cap enforced while streaming, **no redirects** (a 3xx is an error, so a response cannot
/// bounce us to plain HTTP or another host), and a 200 required.
pub struct HttpsSource {
    pub timeout: Duration,
}

impl Default for HttpsSource {
    fn default() -> Self {
        HttpsSource {
            timeout: Duration::from_secs(60),
        }
    }
}

impl SignalSource for HttpsSource {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
        max_bytes: usize,
    ) -> BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async move {
            if !url.starts_with("https://") {
                return Err("refusing a non-HTTPS root-program source".into());
            }
            let work = async {
                let mut resp = crate::http_client::Client::new()
                    .get(url)
                    .send_streaming()
                    .await
                    .map_err(|e| e.to_string())?;
                if resp.status().as_u16() != 200 {
                    return Err(format!("HTTP {}", resp.status().as_u16()));
                }
                let mut body = Vec::new();
                while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
                    if body.len() + chunk.len() > max_bytes {
                        return Err(format!("the response exceeds {max_bytes} bytes"));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(body)
            };
            tokio::time::timeout(self.timeout, work)
                .await
                .map_err(|_| format!("timed out after {}s", self.timeout.as_secs()))?
        })
    }
}

/// What one pass of the watch found.
#[derive(Clone, Debug)]
pub struct TrustSnapshot {
    pub checked_at: i64,
    pub cas: Vec<CaTrust>,
    /// Why a program's data was unavailable, if it was (`None` = fetched and parsed).
    pub mozilla_error: Option<String>,
    pub chrome_error: Option<String>,
    /// Observed roots no `trust_roots` entry covers.
    pub unwatched: Vec<(String, String)>,
}

/// The distrust watch: fetch both programs' data, evaluate every CA, report.
pub struct TrustWatch {
    source: Arc<dyn SignalSource>,
    ccadb_url: String,
    chrome_urls: Vec<String>,
}

impl TrustWatch {
    #[must_use]
    pub fn new(source: Arc<dyn SignalSource>) -> Self {
        TrustWatch {
            source,
            ccadb_url: CCADB_INCLUDED_CSV.to_string(),
            chrome_urls: CHROME_ROOT_STORE_URLS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        }
    }

    /// The production watch over [`HttpsSource`].
    #[must_use]
    pub fn https() -> Self {
        Self::new(Arc::new(HttpsSource::default()))
    }

    /// Use other source URLs (a mirror, a test server).
    #[must_use]
    pub fn with_urls(mut self, ccadb_url: impl Into<String>, chrome_urls: Vec<String>) -> Self {
        self.ccadb_url = ccadb_url.into();
        self.chrome_urls = chrome_urls;
        self
    }

    async fn mozilla(&self) -> Result<MozillaStore, String> {
        let body = self
            .source
            .fetch(&self.ccadb_url, MAX_CCADB_BYTES)
            .await
            .map_err(|e| format!("CCADB fetch failed: {e}"))?;
        parse_ccadb(&body).map_err(|e| format!("CCADB data rejected: {e}"))
    }

    async fn chrome(&self) -> Result<ChromeStore, String> {
        let mut last = "no Chrome Root Store URL configured".to_string();
        for url in &self.chrome_urls {
            match self.source.fetch(url, MAX_CHROME_BYTES * 2).await {
                Ok(body) => match decode_gitiles(&body).and_then(|d| parse_chrome_root_store(&d)) {
                    Ok(store) => return Ok(store),
                    Err(e) => last = format!("Chrome Root Store data rejected: {e}"),
                },
                Err(e) => last = format!("Chrome Root Store fetch failed: {e}"),
            }
        }
        Err(last)
    }

    /// One pass. Never fails: unavailable data is reported inside the snapshot as `Unknown`.
    pub async fn check(&self, policy: &CaPolicy, observed: &[Observed], now: i64) -> TrustSnapshot {
        let (moz, chr) = (self.mozilla().await, self.chrome().await);
        let cas = evaluate(
            policy,
            moz.as_ref().map_err(String::as_str),
            chr.as_ref().map_err(String::as_str),
            observed,
            now,
        );
        TrustSnapshot {
            checked_at: now,
            cas,
            mozilla_error: moz.err(),
            chrome_error: chr.err(),
            unwatched: unwatched_anchors(policy, observed),
        }
    }
}

/// Which CAs' held certificates lead to which roots: for each `(ca, chain_pem)`, the top of the chain.
#[must_use]
pub fn observe(chains: impl IntoIterator<Item = (String, String)>) -> Vec<Observed> {
    let mut seen: HashMap<(String, String), ()> = HashMap::new();
    let mut out = Vec::new();
    for (ca, chain) in chains {
        if let Some(top) = crate::x509::chain_top(&chain) {
            if seen
                .insert((ca.clone(), top.fingerprint.clone()), ())
                .is_none()
            {
                out.push(Observed { ca, top });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca_policy::fixtures::{entry, policy};
    use crate::ca_policy::CaStatus;

    const CCADB: &str = include_str!("../tests/fixtures/ccadb_included_sample.csv");
    const CHROME: &str = include_str!("../tests/fixtures/chrome_root_store_sample.textproto");

    // 2026-10-22T00:00:00Z
    const NOW: i64 = 1_792_627_200;
    const ISRG_X1: &str = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6";
    const GTS_R1: &str = "d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf";
    const IZENPE: &str = "2530cc8e98321502";

    fn moz() -> MozillaStore {
        parse_ccadb(CCADB.as_bytes()).expect("the real-data fixture parses")
    }
    fn chr() -> ChromeStore {
        parse_chrome_root_store(CHROME.as_bytes()).expect("the real-data fixture parses")
    }

    fn ca_with(name: &str, roots: Vec<RootRef>) -> crate::ca_policy::CaEntry {
        let mut e = entry(name, CaStatus::Active, &format!("{name}.test"));
        e.trust_roots = roots;
        e
    }
    fn sha(h: &str) -> RootRef {
        RootRef {
            sha256: Some(h.into()),
            name: None,
        }
    }
    fn named(n: &str) -> RootRef {
        RootRef {
            sha256: None,
            name: Some(n.into()),
        }
    }

    #[test]
    fn the_ccadb_fixture_is_real_data_and_parses_with_its_distrust_dates() {
        let m = moz();
        assert!(m.roots.len() >= MIN_PLAUSIBLE_ROOTS);
        let isrg = m
            .roots
            .iter()
            .find(|r| r.sha256 == ISRG_X1)
            .expect("ISRG Root X1");
        assert_eq!(isrg.name, "ISRG Root X1");
        assert!(isrg.websites && isrg.tls_distrust_after.is_none());
        let izenpe = m
            .roots
            .iter()
            .find(|r| r.sha256.starts_with(IZENPE))
            .expect("Izenpe.com");
        assert_eq!(
            izenpe.tls_distrust_after,
            Some(1_776_211_200),
            "2026.04.15 00:00:00Z"
        );
        let entrust = m
            .roots
            .iter()
            .find(|r| r.name == "Entrust Root Certification Authority - G2")
            .expect("Entrust G2");
        assert!(!entrust.websites, "Email only now");
        assert_eq!(
            entrust.tls_distrust_after,
            Some(1_732_924_800),
            "2024.11.30"
        );
    }

    #[test]
    fn the_chrome_fixture_is_real_data_and_parses_constraints() {
        let c = chr();
        assert!(c.version_major.is_some());
        assert!(c.anchors.len() >= MIN_PLAUSIBLE_ROOTS);
        let isrg = c.anchors.iter().find(|a| a.sha256 == ISRG_X1).unwrap();
        assert_eq!(isrg.tls_distrust_after, None);
        assert_eq!(
            isrg.label.as_deref(),
            Some("CN=ISRG Root X1, O=Internet Security Research Group, C=US")
        );
        // Amazon Root CA 3 has a constraint for current versions (min_version) and one for older ones.
        let amazon = c
            .anchors
            .iter()
            .find(|a| {
                a.sha256 == "18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4"
            })
            .unwrap();
        assert_eq!(
            amazon.tls_distrust_after,
            Some(1_820_966_399),
            "the constraint for current Chrome applies"
        );
        // The Izenpe distrust date has passed.
        let izenpe = c
            .anchors
            .iter()
            .find(|a| a.label.as_deref().is_some_and(|l| l.contains("Izenpe")))
            .unwrap();
        assert!(izenpe.tls_distrust_after.is_some_and(|t| t < NOW));
    }

    #[test]
    fn a_trusted_root_is_trusted_in_both_programs() {
        let p = policy(vec![ca_with("le", vec![sha(ISRG_X1)])]);
        let (m, c) = (moz(), chr());
        let r = evaluate(&p, Ok(&m), Ok(&c), &[], NOW);
        assert_eq!(r[0].mozilla, TrustVerdict::Trusted);
        assert_eq!(r[0].chrome, TrustVerdict::Trusted);
        assert_eq!(r[0].combined, TrustVerdict::Trusted);
        // By name too: the name resolves to the fingerprint for Chrome.
        let p = policy(vec![
            ca_with("le", vec![named("ISRG Root X1")]),
            ca_with("gts", vec![sha(GTS_R1)]),
        ]);
        let r = evaluate(&p, Ok(&m), Ok(&c), &[], NOW);
        assert!(
            r.iter().all(|x| x.combined == TrustVerdict::Trusted),
            "{r:?}"
        );
    }

    #[test]
    fn a_root_past_its_distrust_after_date_is_distrusted_and_a_future_one_is_pending() {
        let (m, c) = (moz(), chr());
        // Izenpe: Mozilla's date (2026-04-15) and Chrome's (2026-04-14) are both in the past.
        let izenpe_sha = m
            .roots
            .iter()
            .find(|r| r.sha256.starts_with(IZENPE))
            .unwrap()
            .sha256
            .clone();
        let p = policy(vec![ca_with("izenpe", vec![sha(&izenpe_sha)])]);
        let r = &evaluate(&p, Ok(&m), Ok(&c), &[], NOW)[0];
        assert!(
            matches!(&r.mozilla, TrustVerdict::Distrusted { reason } if reason.contains("2026-04-15")),
            "{r:?}"
        );
        assert!(
            matches!(&r.chrome, TrustVerdict::Distrusted { reason } if reason.contains("distrust-after")),
            "{r:?}"
        );
        assert!(matches!(r.combined, TrustVerdict::Distrusted { .. }));
        // The same data evaluated *before* those dates is only pending.
        let early = 1_700_000_000; // 2023-11-14
        let r = &evaluate(&p, Ok(&m), Ok(&c), &[], early)[0];
        assert_eq!(
            r.mozilla,
            TrustVerdict::DistrustPending {
                after: 1_776_211_200
            }
        );
        assert!(
            matches!(r.combined, TrustVerdict::DistrustPending { after } if after < 1_776_211_200 + 1),
            "{r:?}"
        );
        // Amazon Root CA 3 (a Chrome constraint in 2027): pending in Chrome, trusted by Mozilla's listing.
        let p = policy(vec![ca_with(
            "amazon",
            vec![sha(
                "18ce6cfe7bf14e60b2e347b8dfe868cb31d02ebb3ada271569f50343b46db3a4",
            )],
        )]);
        let r = &evaluate(&p, Ok(&m), Ok(&c), &[], NOW)[0];
        assert_eq!(
            r.chrome,
            TrustVerdict::DistrustPending {
                after: 1_820_966_399
            }
        );
        assert!(
            matches!(r.combined, TrustVerdict::DistrustPending { .. }),
            "{r:?}"
        );
    }

    #[test]
    fn a_root_missing_from_a_program_is_distrusted_there() {
        let (m, c) = (moz(), chr());
        let ghost = "ab".repeat(32);
        let p = policy(vec![
            ca_with("ghost", vec![sha(&ghost)]),
            ca_with("ghostname", vec![named("No Such Root CA")]),
        ]);
        let r = evaluate(&p, Ok(&m), Ok(&c), &[], NOW);
        assert!(
            matches!(&r[0].mozilla, TrustVerdict::Distrusted { reason } if reason.contains("not in Mozilla's root store")),
            "{:?}",
            r[0]
        );
        assert!(
            matches!(&r[0].chrome, TrustVerdict::Distrusted { reason } if reason.contains("not in the Chrome Root Store")),
            "{:?}",
            r[0]
        );
        assert!(matches!(r[0].combined, TrustVerdict::Distrusted { .. }));
        // A root with no Websites bit (Entrust G2 is email-only in Mozilla).
        let entrust = m
            .roots
            .iter()
            .find(|r| r.name == "Entrust Root Certification Authority - G2")
            .unwrap()
            .sha256
            .clone();
        let p = policy(vec![ca_with("entrust", vec![sha(&entrust)])]);
        let r = &evaluate(&p, Ok(&m), Ok(&c), &[], NOW)[0];
        assert!(
            matches!(&r.mozilla, TrustVerdict::Distrusted { reason } if reason.contains("Websites")),
            "{r:?}"
        );
    }

    #[test]
    fn some_roots_gone_but_not_all_is_pending_and_all_gone_is_distrusted() {
        let (m, c) = (moz(), chr());
        let p = policy(vec![
            ca_with("mixed", vec![sha(ISRG_X1), sha(&"cd".repeat(32))]),
            ca_with(
                "alldead",
                vec![sha(&"cd".repeat(32)), sha(&"ef".repeat(32))],
            ),
        ]);
        let r = evaluate(&p, Ok(&m), Ok(&c), &[], NOW);
        assert!(
            matches!(r[0].combined, TrustVerdict::DistrustPending { .. }),
            "{:?}",
            r[0]
        );
        assert!(
            matches!(r[1].combined, TrustVerdict::Distrusted { .. }),
            "{:?}",
            r[1]
        );
    }

    #[test]
    fn unavailable_data_is_unknown_never_distrusted() {
        let (m, c) = (moz(), chr());
        let p = policy(vec![ca_with("le", vec![sha(ISRG_X1)])]);
        let both_down = &evaluate(&p, Err("fetch failed"), Err("fetch failed"), &[], NOW)[0];
        assert!(
            matches!(both_down.combined, TrustVerdict::Unknown { .. }),
            "{both_down:?}"
        );
        // One program down, the other happy: Unknown (we cannot call it Trusted) -- and crucially not Distrusted.
        let one_down = &evaluate(&p, Ok(&m), Err("503"), &[], NOW)[0];
        assert_eq!(one_down.mozilla, TrustVerdict::Trusted);
        assert!(
            matches!(one_down.combined, TrustVerdict::Unknown { .. }),
            "{one_down:?}"
        );
        // One program down, the other warning: the warning stands.
        let ghost = policy(vec![ca_with("g", vec![sha(&"ab".repeat(32))])]);
        let r = &evaluate(&ghost, Ok(&m), Err("503"), &[], NOW)[0];
        assert!(matches!(r.combined, TrustVerdict::Distrusted { .. }));
        // No roots configured: nothing to judge.
        let none = policy(vec![ca_with("none", vec![])]);
        assert!(matches!(
            evaluate(&none, Ok(&m), Ok(&c), &[], NOW)[0].combined,
            TrustVerdict::Unknown { .. }
        ));
        let _ = c;
    }

    #[test]
    fn garbage_truncations_and_error_pages_are_rejected_not_read_as_empty_stores() {
        assert!(parse_ccadb(b"").is_err());
        assert!(parse_ccadb(b"<html><body>503 Service Unavailable</body></html>").is_err());
        assert!(parse_ccadb(
            "\"Owner\",\"Common Name or Certificate Name\"\n\"x\",\"y\"\n".as_bytes()
        )
        .unwrap_err()
        .contains("column"));
        // The real header with a handful of rows: too few to be Mozilla's store.
        let few: String = CCADB.lines().take(6).collect::<Vec<_>>().join("\n");
        assert!(parse_ccadb(few.as_bytes()).unwrap_err().contains("only"));
        // A malformed fingerprint or date anywhere fails the whole document.
        let bad_sha = CCADB.replacen(
            ISRG_X1.to_ascii_uppercase().as_str(),
            "NOT-A-FINGERPRINT",
            1,
        );
        assert!(parse_ccadb(bad_sha.as_bytes())
            .unwrap_err()
            .contains("fingerprint"));
        let bad_date = CCADB.replacen("2026.04.15", "15/04/2026", 1);
        assert!(parse_ccadb(bad_date.as_bytes())
            .unwrap_err()
            .contains("date"));
        assert!(parse_ccadb(&vec![b'a'; MAX_CCADB_BYTES + 1]).is_err());
        // Chrome: not a text-proto, truncated mid-block, too few anchors, an anchor without a fingerprint.
        assert!(parse_chrome_root_store(b"<html>503</html>").is_err());
        assert!(parse_chrome_root_store(&CHROME.as_bytes()[..CHROME.len() / 2]).is_err());
        assert!(parse_chrome_root_store(
            b"version_major: 1\ntrust_anchors {\n sha256_hex: \"aa\"\n}\n"
        )
        .is_err());
        assert!(parse_chrome_root_store(b"trust_anchors { crs_root_id: 1 }")
            .unwrap_err()
            .contains("sha256_hex"));
        let deep = format!("{}{}", "a { ".repeat(40), "}".repeat(40));
        assert!(
            parse_chrome_root_store(deep.as_bytes()).is_err(),
            "nesting is bounded"
        );
        assert!(parse_chrome_root_store(b"a: \"unterminated").is_err());
    }

    #[test]
    fn a_constraint_scoped_to_older_chrome_versions_is_ignored_and_one_for_current_versions_applies(
    ) {
        let filler: String = (0..MIN_PLAUSIBLE_ROOTS)
            .map(|i| {
                format!("trust_anchors {{\n  sha256_hex: \"{i:064x}\"\n  crs_root_id: {i}\n}}\n")
            })
            .collect();
        let doc = format!(
            "{filler}\
             # CN=Old Only, O=X\ntrust_anchors {{\n sha256_hex: \"{a}\"\n constraints: {{ sct_not_after_sec: 100 max_version_exclusive: \"9.0\" }}\n}}\n\
             # CN=Current, O=X\ntrust_anchors {{\n sha256_hex: \"{b}\"\n constraints: {{ sct_not_after_sec: 200 min_version: \"9.0\" }}\n constraints: {{ sct_not_after_sec: 50 max_version_exclusive: \"9.0\" }}\n}}\n\
             trust_anchors {{\n sha256_hex: \"{c}\"\n constraints: {{ permitted_dns_names: \"example.com\" min_version: \"9.0\" }}\n}}\n",
            a = "a1".repeat(32),
            b = "b2".repeat(32),
            c = "c3".repeat(32)
        );
        let store = parse_chrome_root_store(doc.as_bytes()).unwrap();
        let get = |h: &str| {
            store
                .anchors
                .iter()
                .find(|a| a.sha256 == h.repeat(32))
                .unwrap()
        };
        assert_eq!(
            get("a1").tls_distrust_after,
            None,
            "a constraint for older versions says nothing about current ones"
        );
        assert_eq!(get("b2").tls_distrust_after, Some(200));
        assert_eq!(get("b2").label.as_deref(), Some("CN=Current, O=X"));
        assert!(get("c3").name_constrained && get("c3").tls_distrust_after.is_none());
    }

    #[test]
    fn the_csv_reader_handles_quotes_commas_and_embedded_newlines() {
        let rows = parse_csv("a,\"b,c\",\"d \"\"quoted\"\"\"\n\"line\nbreak\",x,\n").unwrap();
        assert_eq!(
            rows,
            vec![
                vec!["a", "b,c", "d \"quoted\""],
                vec!["line\nbreak", "x", ""]
            ]
        );
        assert!(parse_csv("\"open").is_err());
        assert_eq!(parse_csv("a,b").unwrap(), vec![vec!["a", "b"]]);
    }

    fn top(self_issued: bool, fp: &str, subject: Option<&str>, issuer: Option<&str>) -> ChainTop {
        ChainTop {
            fingerprint: fp.into(),
            self_issued,
            subject_cn: subject.map(str::to_string),
            issuer_cn: issuer.map(str::to_string),
            issuer_org: None,
        }
    }

    #[test]
    fn a_root_our_certificates_actually_chain_to_is_judged_even_if_the_configured_roots_look_fine()
    {
        let (m, c) = (moz(), chr());
        // The CA lists ISRG Root X1 (fine) but the certificates we hold chain to a removed root.
        let p = policy(vec![ca_with("le", vec![sha(ISRG_X1)])]);
        let removed = Observed {
            ca: "le".into(),
            top: top(
                true,
                &"12".repeat(32),
                Some("Some Removed Root"),
                Some("Some Removed Root"),
            ),
        };
        let r = &evaluate(&p, Ok(&m), Ok(&c), &[removed], NOW)[0];
        assert!(
            matches!(&r.combined, TrustVerdict::Distrusted { reason } if reason.contains("chains to a root that is unusable")),
            "{r:?}"
        );
        // An intermediate whose issuer is a healthy root is fine; one whose issuer is unknown to the stores is not.
        let healthy = Observed {
            ca: "le".into(),
            top: top(false, &"34".repeat(32), Some("R11"), Some("ISRG Root X1")),
        };
        assert_eq!(
            evaluate(&p, Ok(&m), Ok(&c), &[healthy], NOW)[0].combined,
            TrustVerdict::Trusted
        );
        let orphan = Observed {
            ca: "le".into(),
            top: top(false, &"56".repeat(32), Some("R11"), Some("Gone Root X9")),
        };
        assert!(matches!(
            evaluate(&p, Ok(&m), Ok(&c), &[orphan], NOW)[0].combined,
            TrustVerdict::Distrusted { .. }
        ));
        // Observations for another CA do not leak.
        let other = Observed {
            ca: "other".into(),
            top: top(true, &"12".repeat(32), None, None),
        };
        assert_eq!(
            evaluate(&p, Ok(&m), Ok(&c), &[other], NOW)[0].combined,
            TrustVerdict::Trusted
        );
    }

    #[test]
    fn a_chain_to_a_root_nobody_watches_is_reported() {
        let p = policy(vec![ca_with("le", vec![named("ISRG Root X1")])]);
        let ok = Observed {
            ca: "le".into(),
            top: top(false, "aa", Some("R11"), Some("ISRG Root X1")),
        };
        let new_root = Observed {
            ca: "le".into(),
            top: top(false, "bb", Some("YE1"), Some("ISRG Root YE")),
        };
        assert_eq!(unwatched_anchors(&p, std::slice::from_ref(&ok)), vec![]);
        let u = unwatched_anchors(&p, &[ok, new_root.clone(), new_root]);
        assert_eq!(u.len(), 1, "{u:?}");
        assert!(u[0].1.contains("ISRG Root YE"));
    }

    #[test]
    fn combining_programs_never_lets_silence_wash_out_a_warning() {
        use TrustVerdict::*;
        let d = || Distrusted {
            reason: "gone".into(),
        };
        let p = || DistrustPending { after: 100 };
        let u = || Unknown { reason: "?".into() };
        assert!(matches!(
            TrustVerdict::combine(&d(), &Trusted),
            Distrusted { .. }
        ));
        assert!(matches!(
            TrustVerdict::combine(&Trusted, &d()),
            Distrusted { .. }
        ));
        assert!(matches!(
            TrustVerdict::combine(&d(), &u()),
            Distrusted { .. }
        ));
        assert_eq!(
            TrustVerdict::combine(&p(), &DistrustPending { after: 50 }),
            DistrustPending { after: 50 }
        );
        assert!(matches!(
            TrustVerdict::combine(&p(), &Trusted),
            DistrustPending { .. }
        ));
        assert!(matches!(
            TrustVerdict::combine(&p(), &u()),
            DistrustPending { .. }
        ));
        assert!(matches!(
            TrustVerdict::combine(&Trusted, &u()),
            Unknown { .. }
        ));
        assert_eq!(TrustVerdict::combine(&Trusted, &Trusted), Trusted);
    }

    /// A source that serves canned bodies and records what it was asked for.
    struct Canned {
        bodies: HashMap<String, Result<Vec<u8>, String>>,
        asked: std::sync::Mutex<Vec<String>>,
    }
    impl SignalSource for Canned {
        fn fetch<'a>(
            &'a self,
            url: &'a str,
            _max: usize,
        ) -> BoxFuture<'a, Result<Vec<u8>, String>> {
            Box::pin(async move {
                self.asked.lock().unwrap().push(url.to_string());
                self.bodies
                    .get(url)
                    .cloned()
                    .unwrap_or_else(|| Err("404".into()))
            })
        }
    }

    fn b64(data: &[u8]) -> Vec<u8> {
        crate::acme::pem_wrap("X", data)
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>()
            .into_bytes()
    }

    #[tokio::test]
    async fn the_watch_fetches_both_programs_falls_back_between_chrome_mirrors_and_never_fails() {
        let p = policy(vec![ca_with("le", vec![sha(ISRG_X1)])]);
        let mut bodies = HashMap::new();
        bodies.insert(
            "https://ccadb.test/csv".to_string(),
            Ok(CCADB.as_bytes().to_vec()),
        );
        bodies.insert(
            "https://chrome.test/b".to_string(),
            Ok(b64(CHROME.as_bytes())),
        );
        bodies.insert("https://chrome.test/a".to_string(), Err("HTTP 503".into()));
        let src = Arc::new(Canned {
            bodies,
            asked: Default::default(),
        });
        let watch = TrustWatch::new(src.clone()).with_urls(
            "https://ccadb.test/csv",
            vec![
                "https://chrome.test/a".into(),
                "https://chrome.test/b".into(),
            ],
        );
        let s = watch.check(&p, &[], NOW).await;
        assert_eq!(s.cas[0].combined, TrustVerdict::Trusted);
        assert!(s.mozilla_error.is_none() && s.chrome_error.is_none());
        assert_eq!(
            src.asked.lock().unwrap().len(),
            3,
            "the first Chrome mirror failed, the second answered"
        );

        // Both sources broken (HTML error pages): Unknown with reasons, no verdict of distrust.
        let mut bodies = HashMap::new();
        bodies.insert(
            "https://ccadb.test/csv".to_string(),
            Ok(b"<html>Service Unavailable</html>".to_vec()),
        );
        bodies.insert(
            "https://chrome.test/a".to_string(),
            Ok(b64(b"<html>nope</html>")),
        );
        let watch = TrustWatch::new(Arc::new(Canned {
            bodies,
            asked: Default::default(),
        }))
        .with_urls(
            "https://ccadb.test/csv",
            vec!["https://chrome.test/a".into()],
        );
        let s = watch.check(&p, &[], NOW).await;
        assert!(
            matches!(s.cas[0].combined, TrustVerdict::Unknown { .. }),
            "{s:?}"
        );
        assert!(s
            .mozilla_error
            .as_deref()
            .is_some_and(|e| e.contains("rejected")));
        assert!(s
            .chrome_error
            .as_deref()
            .is_some_and(|e| e.contains("rejected")));
    }

    #[tokio::test]
    async fn the_https_source_refuses_plain_http_and_enforces_its_deadline_and_cap() {
        let src = HttpsSource {
            timeout: Duration::from_millis(300),
        };
        assert!(src
            .fetch("http://example.test/x", 100)
            .await
            .unwrap_err()
            .contains("non-HTTPS"));
        // A server that accepts and never answers (TLS never starts): the deadline fires.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}/x", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((c, _)) = listener.accept().await {
                held.push(c);
            }
        });
        let started = std::time::Instant::now();
        let e = src.fetch(&url, 100).await.unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5) && !e.is_empty(),
            "{e}"
        );
    }
}
