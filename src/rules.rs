//! Rule file parser and matcher.
//!
//! Format: see `examples/sluice.rules`. The parser is line-oriented and
//! whitespace-significant: an unindented line opens a stanza; indented
//! lines attach attributes to the stanza above.

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

/// A path with optional `#$slot` placeholders. Resolved per call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathTemplate {
    pub raw: String,
}

#[derive(Debug, Clone, Copy)]
pub struct PathCtx {
    pub call: u64,
    pub pid: i32,
    pub uid: u32,
    pub rule: usize,
    pub ts: u64,
    pub ts_ms: u64,
}

impl PathTemplate {
    /// Validate that all `#$slot` references name known slots.
    pub fn validate(&self) -> Result<(), String> {
        let mut chars = self.raw.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '#' && chars.peek() == Some(&'$') {
                chars.next();
                let mut name = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        name.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if name.is_empty() {
                    return Err("'#$' without a slot name".into());
                }
                match name.as_str() {
                    "call" | "pid" | "uid" | "rule" | "ts" | "ts_ms" => {}
                    other => return Err(format!("unknown system slot: #${other}")),
                }
            }
        }
        Ok(())
    }

    /// Substitute system slots into the path. Unknown slots are
    /// rejected at parse time, so this can never fail at runtime if
    /// validate() succeeded.
    pub fn resolve(&self, ctx: &PathCtx) -> PathBuf {
        let mut out = String::with_capacity(self.raw.len());
        let mut chars = self.raw.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '#' && chars.peek() == Some(&'$') {
                chars.next();
                let mut name = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        name.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                match name.as_str() {
                    "call" => out.push_str(&ctx.call.to_string()),
                    "pid" => out.push_str(&ctx.pid.to_string()),
                    "uid" => out.push_str(&ctx.uid.to_string()),
                    "rule" => out.push_str(&ctx.rule.to_string()),
                    "ts" => out.push_str(&ctx.ts.to_string()),
                    "ts_ms" => out.push_str(&ctx.ts_ms.to_string()),
                    _ => {} // validated at parse time
                }
            } else {
                out.push(c);
            }
        }
        PathBuf::from(out)
    }

    /// Does the template contain a slot that's unique per call?
    /// Used to decide if concurrent appends to the same resolved path
    /// are possible.
    pub fn is_per_call(&self) -> bool {
        self.raw.contains("#$call") || self.raw.contains("#$ts_ms")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SlotId {
    Num(u32),
    Name(String),
}

impl std::fmt::Display for SlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlotId::Num(n) => write!(f, "#{n}"),
            SlotId::Name(s) => write!(f, "#{s}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenPattern {
    Literal(String),
    Slot(SlotId),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExeMatch {
    BareName(String),
    Absolute(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EnvPolicy {
    #[default]
    None,
    Allow(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogPolicy {
    #[default]
    Full,
    ArgvOnly,
    ExitOnly,
}

/// What to do when a configured audit sink (logfile / stdoutfile /
/// stderrfile) cannot be opened or written. `Strict` (default) refuses
/// to execute when the configured audit can't be honored.
/// `BestEffort` logs to stderr and proceeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuditMode {
    #[default]
    Strict,
    BestEffort,
}

/// Resolution path for bare-name executables. Default is the classic
/// root-owned-only set; operators with custom toolchains either list
/// their dirs explicitly or set `exec_path = inherit` to use the
/// launcher's PATH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecPath {
    /// Use the launcher's PATH at exec time.
    Inherit,
    /// Use this explicit colon-separated absolute-paths list.
    Explicit(String),
}

impl Default for ExecPath {
    fn default() -> Self {
        ExecPath::Explicit("/bin:/usr/bin:/sbin:/usr/sbin".to_string())
    }
}

#[derive(Debug, Default)]
pub struct Defaults {
    pub timeout: Option<Duration>,
    pub cwd: Option<PathBuf>,
    pub env: EnvPolicy,
    pub log: LogPolicy,
    pub logfile: Option<PathTemplate>,
    pub stdoutfile: Option<PathTemplate>,
    pub stderrfile: Option<PathTemplate>,
    pub audit: AuditMode,
    pub exec_path: ExecPath,
}

#[derive(Debug)]
pub struct Rule {
    pub line_no: usize,
    pub exe: ExeMatch,
    pub tokens: Vec<TokenPattern>,
    pub slot_regex: HashMap<SlotId, Regex>,
    pub allow_dash: HashSet<SlotId>,
    pub allow_any: HashSet<SlotId>,
    pub timeout: Option<Duration>,
    pub cwd: Option<PathBuf>,
    pub env: Option<EnvPolicy>,
    pub log: Option<LogPolicy>,
    pub stdoutfile: Option<PathTemplate>,
    pub stderrfile: Option<PathTemplate>,
    pub exec_path: Option<ExecPath>,
}

#[derive(Debug)]
pub struct Rules {
    pub defaults: Defaults,
    pub rules: Vec<Rule>,
}

#[derive(Debug)]
pub struct Match<'r> {
    pub rule: &'r Rule,
    pub bindings: HashMap<SlotId, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Miss {
    NoRule,
    /// A rule would have matched but for a slot value starting with
    /// `-` on a slot not listed in `allow_dash`.
    OptionLike {
        line: usize,
        slot: SlotId,
    },
}

#[derive(Debug)]
pub struct ParseError {
    pub line_no: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line_no, self.message)
    }
}

impl std::error::Error for ParseError {}

const MAX_SLOT_VALUE_BYTES: usize = 4096;

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

pub fn parse(input: &str) -> Result<Rules, ParseError> {
    let mut defaults = Defaults::default();
    let mut rules: Vec<Rule> = Vec::new();
    let mut current: Stanza = Stanza::None;

    for (idx, raw) in input.lines().enumerate() {
        let line_no = idx + 1;
        if raw.starts_with([' ', '\t']) {
            if let Some((key, val)) = split_attr(raw, line_no)? {
                apply_attr(&mut current, &mut defaults, &mut rules, key, &val, line_no)?;
            }
            continue;
        }
        let stripped = strip_comment(raw);
        if stripped.trim().is_empty() {
            continue;
        }
        // New stanza
        let trimmed = stripped.trim_end();
        if trimmed == "defaults:" {
            current = Stanza::Defaults;
        } else {
            let rule = parse_rule_line(trimmed, line_no)?;
            rules.push(rule);
            current = Stanza::Rule(rules.len() - 1);
        }
    }

    for r in &rules {
        validate_slots(r)?;
    }
    Ok(Rules { defaults, rules })
}

enum Stanza {
    None,
    Defaults,
    Rule(usize),
}

fn strip_comment(line: &str) -> &str {
    // ';' starts a comment to end-of-line, but only when NOT inside
    // a quoted literal. Walk the line tracking quote state.
    let bytes = line.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_single {
            if c == b'\'' {
                in_single = false;
            }
        } else if in_double {
            if c == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if c == b'"' {
                in_double = false;
            }
        } else {
            match c {
                b'\\' if i + 1 < bytes.len() => {
                    i += 2;
                    continue;
                }
                b'\'' => in_single = true,
                b'"' => in_double = true,
                b';' => return &line[..i],
                _ => {}
            }
        }
        i += 1;
    }
    line
}

/// `None` for a blank or comment-only line.
fn split_attr(line: &str, line_no: usize) -> Result<Option<(&str, String)>, ParseError> {
    let body = line.trim_start();
    if body.is_empty() || body.starts_with(';') {
        return Ok(None);
    }
    let eq = match body.find(['=', ';']) {
        Some(i) if body.as_bytes()[i] == b'=' => i,
        _ => {
            return Err(ParseError {
                line_no,
                message: format!(
                    "attribute line missing '=': {:?}",
                    strip_unquoted_comment(body).trim_end()
                ),
            })
        }
    };
    let key = body[..eq].trim();
    if key.is_empty() {
        return Err(ParseError {
            line_no,
            message: "empty attribute key".into(),
        });
    }
    let val = attr_value(body[eq + 1..].trim_start(), line_no)?;
    Ok(Some((key, val)))
}

/// A value starting with a quote is one shell-quoted word, so it can
/// contain `;`. Otherwise quotes are literal and `;` starts a comment
/// unless escaped as `\;`.
fn attr_value(rest: &str, line_no: usize) -> Result<String, ParseError> {
    if !rest.starts_with(['\'', '"']) {
        return Ok(strip_unquoted_comment(rest).trim_end().to_string());
    }
    match tokenize(strip_comment(rest).trim_end(), line_no)?.as_slice() {
        [v] => Ok(v.clone()),
        _ => Err(ParseError {
            line_no,
            message: "quoted attribute value must be a single quoted string".into(),
        }),
    }
}

fn strip_unquoted_comment(s: &str) -> &str {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b';' => return &s[..i],
            _ => i += 1,
        }
    }
    s
}

fn apply_attr(
    current: &mut Stanza,
    defaults: &mut Defaults,
    rules: &mut [Rule],
    key: &str,
    val: &str,
    line_no: usize,
) -> Result<(), ParseError> {
    match current {
        Stanza::None => Err(ParseError {
            line_no,
            message: "indented attribute with no preceding stanza".into(),
        }),
        Stanza::Defaults => apply_default_attr(defaults, key, val, line_no),
        Stanza::Rule(idx) => apply_rule_attr(&mut rules[*idx], key, val, line_no),
    }
}

fn apply_default_attr(
    d: &mut Defaults,
    key: &str,
    val: &str,
    line_no: usize,
) -> Result<(), ParseError> {
    match key {
        "timeout" => d.timeout = Some(parse_duration(val, line_no)?),
        "cwd" => d.cwd = Some(expand_path_field(val, line_no)?),
        "env" => d.env = parse_env(val, line_no)?,
        "log" => d.log = parse_log(val, line_no)?,
        "logfile" => d.logfile = Some(parse_path_template(val, line_no)?),
        "stdoutfile" => d.stdoutfile = Some(parse_path_template(val, line_no)?),
        "stderrfile" => d.stderrfile = Some(parse_path_template(val, line_no)?),
        "audit" => d.audit = parse_audit(val, line_no)?,
        "exec_path" => d.exec_path = parse_exec_path(val, line_no)?,
        other => {
            return Err(ParseError {
                line_no,
                message: format!("unknown defaults attribute: {other}"),
            });
        }
    }
    Ok(())
}

fn parse_audit(val: &str, line_no: usize) -> Result<AuditMode, ParseError> {
    match val.trim() {
        "strict" => Ok(AuditMode::Strict),
        "best-effort" => Ok(AuditMode::BestEffort),
        other => Err(ParseError {
            line_no,
            message: format!("unknown audit mode: {other:?} (use strict|best-effort)"),
        }),
    }
}

fn parse_exec_path(val: &str, line_no: usize) -> Result<ExecPath, ParseError> {
    let v = val.trim();
    if v == "inherit" {
        return Ok(ExecPath::Inherit);
    }
    if v.is_empty() {
        return Err(ParseError {
            line_no,
            message: "exec_path is empty".into(),
        });
    }
    // Each entry must be an absolute path. Empty entries (a literal
    // "::" or a leading/trailing ":") and relative entries both expose
    // CWD-based attacks (executable picked up from working dir).
    for entry in v.split(':') {
        if entry.is_empty() {
            return Err(ParseError {
                line_no,
                message: "exec_path contains an empty entry — \
                    that resolves to the caller's cwd at exec time, \
                    which is exactly the attack we're avoiding"
                    .into(),
            });
        }
        if !entry.starts_with('/') {
            return Err(ParseError {
                line_no,
                message: format!(
                    "exec_path entry {entry:?} is not absolute — \
                     each entry must start with '/'"
                ),
            });
        }
    }
    Ok(ExecPath::Explicit(v.to_string()))
}

fn parse_path_template(val: &str, line_no: usize) -> Result<PathTemplate, ParseError> {
    let expanded = expand_env_vars(val).map_err(|e| ParseError {
        line_no,
        message: e,
    })?;
    let t = PathTemplate { raw: expanded };
    t.validate().map_err(|e| ParseError {
        line_no,
        message: format!("invalid path template: {e}"),
    })?;
    Ok(t)
}

/// Whitelist of environment variables that may appear in path-shaped
/// rule fields. Kept tiny on purpose: a rules file ought to be portable
/// between users on the same machine (so HOME) and able to land its
/// audit sinks on a user-private tmpfs (so XDG_RUNTIME_DIR), but not
/// reach into PATH or arbitrary process state where typos and shell
/// injection patterns become hard to reason about.
const ALLOWED_ENV_VARS: &[&str] = &["HOME", "XDG_RUNTIME_DIR"];

/// Expand `$HOME` / `${HOME}` and `$XDG_RUNTIME_DIR` / `${XDG_RUNTIME_DIR}`
/// at parse time. Any other `$NAME` or `${NAME}` is rejected so a typo
/// like `$HOMW` doesn't silently end up as a literal directory name.
/// Unset allowed vars are also rejected — better a loud parse error
/// than an empty string spliced into an audit path.
fn expand_env_vars(input: &str) -> Result<String, String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.find('$') {
        // `#$slot` is the per-call system-slot syntax handled by
        // PathTemplate::resolve — leave it alone.
        if idx > 0 && rest.as_bytes()[idx - 1] == b'#' {
            out.push_str(&rest[..idx + 1]);
            rest = &rest[idx + 1..];
            continue;
        }
        out.push_str(&rest[..idx]);
        let after = &rest[idx + 1..];
        let (name, advance, braced) = if let Some(after_brace) = after.strip_prefix('{') {
            let close = after_brace
                .find('}')
                .ok_or_else(|| format!("unterminated '${{' in {input:?}"))?;
            (&after_brace[..close], close + 2 + 1, true)
        } else {
            let end = after
                .bytes()
                .position(|b| !(b.is_ascii_alphanumeric() || b == b'_'))
                .unwrap_or(after.len());
            if end == 0 {
                out.push('$');
                rest = after;
                continue;
            }
            (&after[..end], end + 1, false)
        };
        if !ALLOWED_ENV_VARS.contains(&name) {
            let token = if braced {
                format!("${{{name}}}")
            } else {
                format!("${name}")
            };
            return Err(format!(
                "unsupported variable {token} in path \
                 (only $HOME and $XDG_RUNTIME_DIR are allowed)"
            ));
        }
        let val = std::env::var(name).map_err(|_| {
            format!("environment variable ${name} is not set; cannot expand path {input:?}")
        })?;
        out.push_str(&val);
        rest = &rest[idx + advance..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Same allowlisted env expansion as path templates, but for plain
/// path fields (e.g. `cwd`) that don't carry `#$` slots. Kept as a
/// thin wrapper so the call sites read symmetrically.
fn expand_path_field(val: &str, line_no: usize) -> Result<PathBuf, ParseError> {
    expand_env_vars(val)
        .map(PathBuf::from)
        .map_err(|e| ParseError {
            line_no,
            message: e,
        })
}

fn apply_rule_attr(r: &mut Rule, key: &str, val: &str, line_no: usize) -> Result<(), ParseError> {
    // Known control attributes win over slot-id parsing — `timeout`,
    // `cwd`, `env`, `log` are reserved names and cannot be used as
    // named slots in a rule.
    match key {
        "timeout" => {
            r.timeout = Some(parse_duration(val, line_no)?);
            return Ok(());
        }
        "cwd" => {
            r.cwd = Some(expand_path_field(val, line_no)?);
            return Ok(());
        }
        "env" => {
            r.env = Some(parse_env(val, line_no)?);
            return Ok(());
        }
        "log" => {
            r.log = Some(parse_log(val, line_no)?);
            return Ok(());
        }
        "logfile" => {
            return Err(ParseError {
                line_no,
                message: "logfile is defaults-only (one manifest per broker); \
                          move it under `defaults:`"
                    .into(),
            });
        }
        "stdoutfile" => {
            r.stdoutfile = Some(parse_path_template(val, line_no)?);
            return Ok(());
        }
        "stderrfile" => {
            r.stderrfile = Some(parse_path_template(val, line_no)?);
            return Ok(());
        }
        "exec_path" => {
            r.exec_path = Some(parse_exec_path(val, line_no)?);
            return Ok(());
        }
        "allow_dash" => {
            let slots = parse_slot_list(r, key, val, line_no)?;
            r.allow_dash.extend(slots);
            return Ok(());
        }
        "allow_any" => {
            let slots = parse_slot_list(r, key, val, line_no)?;
            r.allow_any.extend(slots);
            return Ok(());
        }
        _ => {}
    }
    if let Some(slot) = parse_slot_id_bare(key) {
        if !r.has_slot(&slot) {
            return Err(ParseError {
                line_no,
                message: format!("regex for {slot} but rule has no such slot"),
            });
        }
        let anchored = anchor_regex(val);
        let re = Regex::new(&anchored).map_err(|e| ParseError {
            line_no,
            message: format!("invalid regex for {slot}: {e}"),
        })?;
        r.slot_regex.insert(slot, re);
        return Ok(());
    }
    Err(ParseError {
        line_no,
        message: format!("unknown rule attribute: {key}"),
    })
}

fn parse_slot_list(
    r: &Rule,
    key: &str,
    val: &str,
    line_no: usize,
) -> Result<Vec<SlotId>, ParseError> {
    let mut out = Vec::new();
    for name in val.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        let slot = parse_slot_id_bare(name.strip_prefix('#').unwrap_or(name)).ok_or_else(|| {
            ParseError {
                line_no,
                message: format!("{key}: invalid slot name {name:?}"),
            }
        })?;
        if !r.has_slot(&slot) {
            return Err(ParseError {
                line_no,
                message: format!("{key} lists {slot} but rule has no such slot"),
            });
        }
        out.push(slot);
    }
    if out.is_empty() {
        return Err(ParseError {
            line_no,
            message: format!("{key} lists no slots"),
        });
    }
    Ok(out)
}

/// Run once all of a rule's attributes are known: they may come in any
/// order, so contradictions can't be caught line by line.
fn validate_slots(r: &Rule) -> Result<(), ParseError> {
    let err = |message: String| {
        Err(ParseError {
            line_no: r.line_no,
            message,
        })
    };
    for slot in r.slots() {
        let has_regex = r.slot_regex.contains_key(slot);
        let any = r.allow_any.contains(slot);
        let dash = r.allow_dash.contains(slot);
        if any && has_regex {
            return err(format!(
                "slot {slot} has both a regex and allow_any; drop one"
            ));
        }
        if any && dash {
            return err(format!(
                "slot {slot} is in both allow_any and allow_dash; allow_any already accepts '-'"
            ));
        }
        if dash && !has_regex {
            return err(format!(
                "allow_dash on slot {slot} needs a regex for it (or use allow_any)"
            ));
        }
        if !any && !has_regex {
            return err(format!(
                "slot {slot} has no regex; add `{} = <regex>`, or list it in allow_any to accept any value",
                slot_key(slot)
            ));
        }
    }
    Ok(())
}

fn slot_key(slot: &SlotId) -> String {
    match slot {
        SlotId::Num(n) => n.to_string(),
        SlotId::Name(s) => s.clone(),
    }
}

/// True when the slot regex, as written, starts with a literal `-` and
/// has no alternation, so every value it accepts is option-like.
pub fn requires_leading_dash(re: &Regex) -> bool {
    let full = re.as_str();
    let Some(raw) = full.strip_prefix("^(?:").and_then(|r| r.strip_suffix(")$")) else {
        return false;
    };
    if raw.contains('|') {
        return false;
    }
    let head = raw.trim_start_matches(['^', '(']).trim_start_matches("?:");
    head.starts_with('-') || head.starts_with("\\-")
}

fn anchor_regex(re: &str) -> String {
    format!("^(?:{re})$")
}

fn parse_duration(val: &str, line_no: usize) -> Result<Duration, ParseError> {
    let v = val.trim();
    let (num_part, unit) = v
        .find(|c: char| c.is_alphabetic())
        .map_or((v, ""), |i| v.split_at(i));
    let n: u64 = num_part.parse().map_err(|_| ParseError {
        line_no,
        message: format!("invalid duration: {val:?}"),
    })?;
    let d = match unit {
        "ms" => Duration::from_millis(n),
        "s" | "" => Duration::from_secs(n),
        "m" => Duration::from_secs(n * 60),
        "h" => Duration::from_secs(n * 3600),
        other => {
            return Err(ParseError {
                line_no,
                message: format!("unknown duration unit: {other:?}"),
            });
        }
    };
    Ok(d)
}

fn parse_env(val: &str, line_no: usize) -> Result<EnvPolicy, ParseError> {
    let v = val.trim();
    if v == "none" {
        return Ok(EnvPolicy::None);
    }
    let names: Vec<String> = v
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if names.is_empty() {
        return Err(ParseError {
            line_no,
            message: "env attribute is empty (use 'none' for empty env)".into(),
        });
    }
    for n in &names {
        if !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || n.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            return Err(ParseError {
                line_no,
                message: format!("invalid env var name: {n:?}"),
            });
        }
    }
    Ok(EnvPolicy::Allow(names))
}

fn parse_log(val: &str, line_no: usize) -> Result<LogPolicy, ParseError> {
    match val.trim() {
        "full" => Ok(LogPolicy::Full),
        "argv-only" => Ok(LogPolicy::ArgvOnly),
        "exit-only" => Ok(LogPolicy::ExitOnly),
        other => Err(ParseError {
            line_no,
            message: format!("unknown log policy: {other:?} (use full|argv-only|exit-only)"),
        }),
    }
}

fn parse_slot_id_bare(s: &str) -> Option<SlotId> {
    if s.is_empty() {
        return None;
    }
    if s.chars().all(|c| c.is_ascii_digit()) {
        s.parse::<u32>().ok().map(SlotId::Num)
    } else if is_ident(s) {
        Some(SlotId::Name(s.to_string()))
    } else {
        None
    }
}

fn parse_slot_token(tok: &str) -> Option<SlotId> {
    let rest = tok.strip_prefix('#')?;
    parse_slot_id_bare(rest)
}

fn is_ident(s: &str) -> bool {
    let mut it = s.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    it.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn parse_rule_line(line: &str, line_no: usize) -> Result<Rule, ParseError> {
    let toks = tokenize(line, line_no)?;
    let mut it = toks.into_iter();
    let first = it.next().ok_or_else(|| ParseError {
        line_no,
        message: "empty rule line".into(),
    })?;
    if parse_slot_token(&first).is_some() {
        return Err(ParseError {
            line_no,
            message: "executable token cannot be a slot".into(),
        });
    }
    let exe = if first.starts_with('/') {
        ExeMatch::Absolute(PathBuf::from(first))
    } else if first.contains('/') {
        return Err(ParseError {
            line_no,
            message: format!(
                "executable {first:?} contains '/' but is not absolute; use bare name or absolute path"
            ),
        });
    } else {
        ExeMatch::BareName(first)
    };
    let mut tokens = Vec::new();
    let mut seen_slots: HashMap<SlotId, ()> = HashMap::new();
    for t in it {
        if let Some(slot) = parse_slot_token(&t) {
            if seen_slots.insert(slot.clone(), ()).is_some() {
                return Err(ParseError {
                    line_no,
                    message: format!("duplicate slot {slot} in rule"),
                });
            }
            tokens.push(TokenPattern::Slot(slot));
        } else {
            tokens.push(TokenPattern::Literal(t));
        }
    }
    Ok(Rule {
        line_no,
        exe,
        tokens,
        slot_regex: HashMap::new(),
        allow_dash: HashSet::new(),
        allow_any: HashSet::new(),
        timeout: None,
        cwd: None,
        env: None,
        log: None,
        stdoutfile: None,
        stderrfile: None,
        exec_path: None,
    })
}

/// Shell-style tokenizer: split by unquoted whitespace, with `'…'`,
/// `"…"` quoting and `\x` escapes. Returns one token per shell word.
fn tokenize(line: &str, line_no: usize) -> Result<Vec<String>, ParseError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' if !in_token => {}
            ' ' | '\t' => {
                out.push(std::mem::take(&mut cur));
                in_token = false;
            }
            '\'' => {
                in_token = true;
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == '\'' {
                        closed = true;
                        break;
                    }
                    cur.push(c);
                }
                if !closed {
                    return Err(ParseError {
                        line_no,
                        message: "unterminated single-quoted string".into(),
                    });
                }
            }
            '"' => {
                in_token = true;
                let mut closed = false;
                while let Some(c) = chars.next() {
                    if c == '"' {
                        closed = true;
                        break;
                    }
                    if c == '\\' {
                        if let Some(next) = chars.next() {
                            cur.push(next);
                        }
                    } else {
                        cur.push(c);
                    }
                }
                if !closed {
                    return Err(ParseError {
                        line_no,
                        message: "unterminated double-quoted string".into(),
                    });
                }
            }
            '\\' => {
                in_token = true;
                if let Some(next) = chars.next() {
                    cur.push(next);
                } else {
                    return Err(ParseError {
                        line_no,
                        message: "trailing backslash".into(),
                    });
                }
            }
            _ => {
                in_token = true;
                cur.push(c);
            }
        }
    }
    if in_token {
        out.push(cur);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Matcher
// ---------------------------------------------------------------------------

impl Rules {
    /// First matching rule wins. Returns `None` if no rule matches.
    pub fn match_argv<'r>(&'r self, argv: &[String]) -> Option<Match<'r>> {
        self.check_argv(argv).ok()
    }

    /// Like [`Rules::match_argv`], but says why nothing matched.
    pub fn check_argv<'r>(&'r self, argv: &[String]) -> Result<Match<'r>, Miss> {
        if argv.is_empty() {
            return Err(Miss::NoRule);
        }
        let mut miss = Miss::NoRule;
        for r in &self.rules {
            match r.try_match(argv) {
                Tried::Matched(m) => return Ok(m),
                Tried::OptionLike(slot) if miss == Miss::NoRule => {
                    miss = Miss::OptionLike {
                        line: r.line_no,
                        slot,
                    };
                }
                _ => {}
            }
        }
        Err(miss)
    }
}

enum Tried<'r> {
    Matched(Match<'r>),
    OptionLike(SlotId),
    Missed,
}

impl Rule {
    pub fn slots(&self) -> impl Iterator<Item = &SlotId> {
        self.tokens.iter().filter_map(|t| match t {
            TokenPattern::Slot(id) => Some(id),
            TokenPattern::Literal(_) => None,
        })
    }

    fn has_slot(&self, slot: &SlotId) -> bool {
        self.slots().any(|s| s == slot)
    }

    fn try_match(&self, argv: &[String]) -> Tried<'_> {
        match self.try_match_inner(argv) {
            None => Tried::Missed,
            Some((m, None)) => Tried::Matched(m),
            Some((_, Some(slot))) => Tried::OptionLike(slot),
        }
    }

    /// The second element names the first slot whose value was refused
    /// only for starting with `-`; everything else about the rule matched.
    fn try_match_inner(&self, argv: &[String]) -> Option<(Match<'_>, Option<SlotId>)> {
        // Executable
        match &self.exe {
            ExeMatch::BareName(name) => {
                let argv0 = std::path::Path::new(&argv[0]);
                let basename = argv0.file_name()?.to_str()?;
                if basename != name {
                    return None;
                }
            }
            ExeMatch::Absolute(p) => {
                if std::path::Path::new(&argv[0]) != p {
                    return None;
                }
            }
        }
        // Arity
        if argv.len() - 1 != self.tokens.len() {
            return None;
        }
        // Tokens
        let mut bindings: HashMap<SlotId, String> = HashMap::new();
        let mut dash_refused: Option<SlotId> = None;
        for (i, tok) in self.tokens.iter().enumerate() {
            let v = &argv[i + 1];
            match tok {
                TokenPattern::Literal(s) => {
                    if v != s {
                        return None;
                    }
                }
                TokenPattern::Slot(id) => {
                    if v.len() > MAX_SLOT_VALUE_BYTES {
                        return None;
                    }
                    if !self.allow_any.contains(id) {
                        if !self.slot_regex.get(id)?.is_match(v) {
                            return None;
                        }
                        if v.starts_with('-') && !self.allow_dash.contains(id) {
                            dash_refused.get_or_insert_with(|| id.clone());
                        }
                    }
                    bindings.insert(id.clone(), v.clone());
                }
            }
        }
        Some((
            Match {
                rule: self,
                bindings,
            },
            dash_refused,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_basic() {
        let t = tokenize("git log --oneline -n #1", 1).unwrap();
        assert_eq!(t, vec!["git", "log", "--oneline", "-n", "#1"]);
    }

    #[test]
    fn tokenize_quotes() {
        let t = tokenize(r#"echo "hello world" 'and \"quoted\"'"#, 1).unwrap();
        assert_eq!(t, vec!["echo", "hello world", r#"and \"quoted\""#]);
    }

    #[test]
    fn parse_minimal_rule() {
        let r = parse("git log --oneline -n #1\n  1 = ^[0-9]+$\n").unwrap();
        assert_eq!(r.rules.len(), 1);
        assert_eq!(r.rules[0].exe, ExeMatch::BareName("git".into()));
        assert_eq!(r.rules[0].tokens.len(), 4);
    }

    #[test]
    fn parse_slot_regex() {
        let src = "git log -n #1\n  1 = ^[1-9][0-9]?$\n";
        let r = parse(src).unwrap();
        let rule = &r.rules[0];
        assert!(rule.slot_regex.contains_key(&SlotId::Num(1)));
    }

    #[test]
    fn parse_rejects_regex_for_unknown_slot() {
        let src = "git log -n #1\n  2 = ^.*$\n";
        let err = parse(src).unwrap_err();
        assert!(err.message.contains("no such slot"));
    }

    #[test]
    fn match_simple() {
        let r = parse("git log -n #1\n  1 = ^[0-9]+$\n").unwrap();
        let m = r.match_argv(&["git".into(), "log".into(), "-n".into(), "5".into()]);
        assert!(m.is_some());
        let no = r.match_argv(&["git".into(), "log".into(), "-n".into(), "abc".into()]);
        assert!(no.is_none());
    }

    #[test]
    fn alternation_is_anchored_on_every_branch() {
        let r = parse("git checkout #1\n  1 = main|develop\n").unwrap();
        let m = |v: &str| {
            r.match_argv(&["git".into(), "checkout".into(), v.into()])
                .is_some()
        };
        assert!(m("main"));
        assert!(m("develop"));
        assert!(!m("main--evil"));
        assert!(!m("--upload-pack=x develop"));
    }

    #[test]
    fn user_anchored_alternation_is_still_anchored() {
        let r = parse("git checkout #1\n  1 = ^main|develop$\n").unwrap();
        let m = |v: &str| {
            r.match_argv(&["git".into(), "checkout".into(), v.into()])
                .is_some()
        };
        assert!(m("main"));
        assert!(!m("mainX"));
        assert!(!m("Xdevelop"));
    }

    #[test]
    fn escaped_dollar_is_not_an_end_anchor() {
        let r = parse("echo #1\n  1 = ^[a-z]+\\$\n").unwrap();
        let m = |v: &str| r.match_argv(&["echo".into(), v.into()]).is_some();
        assert!(m("abc$"));
        assert!(!m("abc$;rm"));
    }

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn slot_without_regex_rejected() {
        let err = parse("rsync -a #src #dst\n  src = ^[a-z]+$\n").unwrap_err();
        assert!(
            err.message.contains("slot #dst has no regex"),
            "{}",
            err.message
        );
        assert_eq!(err.line_no, 1);
    }

    #[test]
    fn dash_value_refused_by_default() {
        let r = parse("git log #ref\n  ref = ^[A-Za-z0-9._/-]+$\n").unwrap();
        assert!(r.match_argv(&argv(&["git", "log", "main"])).is_some());
        assert_eq!(
            r.check_argv(&argv(&["git", "log", "-o/tmp/x"]))
                .unwrap_err(),
            Miss::OptionLike {
                line: 1,
                slot: SlotId::Name("ref".into())
            }
        );
    }

    #[test]
    fn allow_dash_accepts_option_matching_regex() {
        let r = parse("sort #opt #file\n  opt = ^-[rn]$\n  file = ^[a-z]+$\n  allow_dash = opt\n")
            .unwrap();
        assert!(r.match_argv(&argv(&["sort", "-r", "data"])).is_some());
        assert!(r.match_argv(&argv(&["sort", "-o", "data"])).is_none());
        assert!(r.match_argv(&argv(&["sort", "-r", "-data"])).is_none());
    }

    #[test]
    fn allow_any_accepts_anything() {
        let r = parse("git commit -m #msg\n  allow_any = #msg\n").unwrap();
        assert!(r
            .match_argv(&argv(&["git", "commit", "-m", "-- fix; it's \"done\""]))
            .is_some());
    }

    #[test]
    fn later_rule_still_matches_after_option_like_miss() {
        let r = parse("ls #1\n  1 = ^.+$\n\nls #1\n  1 = ^-l$\n  allow_dash = 1\n").unwrap();
        assert_eq!(r.match_argv(&argv(&["ls", "-l"])).unwrap().rule.line_no, 4);
        assert!(matches!(
            r.check_argv(&argv(&["ls", "-a"])),
            Err(Miss::OptionLike { line: 1, .. })
        ));
    }

    #[test]
    fn contradictory_slot_attributes_rejected() {
        let cases = [
            (
                "echo #1\n  1 = ^a$\n  allow_any = 1\n",
                "both a regex and allow_any",
            ),
            (
                "echo #1\n  allow_any = 1\n  allow_dash = 1\n",
                "allow_any already accepts",
            ),
            ("echo #1 #2\n  2 = ^a$\n  allow_dash = 1\n", "needs a regex"),
            ("echo #1\n  1 = ^a$\n  allow_dash = 2\n", "no such slot"),
            ("echo #1\n  1 = ^a$\n  allow_dash =\n", "lists no slots"),
        ];
        for (src, want) in cases {
            let err = parse(src).unwrap_err();
            assert!(err.message.contains(want), "{src:?}: {}", err.message);
        }
    }

    #[test]
    fn requires_leading_dash_detects_dash_only_regexes() {
        let r = parse(
            "x #a #b #c #d #e\n  a = ^-[rn]$\n  b = (?:-x)\n  c = \\-y\n  d = -a|b\n  e = [-a]\n",
        )
        .unwrap();
        let got: Vec<bool> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|n| requires_leading_dash(&r.rules[0].slot_regex[&SlotId::Name(n.to_string())]))
            .collect();
        assert_eq!(got, vec![true, true, true, false, false]);
    }

    #[test]
    fn per_rule_logfile_rejected() {
        let err = parse("git log\n  logfile = /var/log/sluice/m.jsonl\n").unwrap_err();
        assert!(err.message.contains("defaults-only"), "{}", err.message);
    }

    #[test]
    fn quoted_regex_may_contain_semicolon() {
        let r = parse("echo #1\n  1 = '^a;b$'   ; comment\n").unwrap();
        let m = |v: &str| r.match_argv(&["echo".into(), v.into()]).is_some();
        assert!(m("a;b"));
        assert!(!m("a"));
    }

    #[test]
    fn unquoted_value_quote_does_not_swallow_comment() {
        let r = parse("echo #1\n  1 = ^[^']+$   ; no quotes\n").unwrap();
        let m = |v: &str| r.match_argv(&["echo".into(), v.into()]).is_some();
        assert!(m("abc"));
        assert!(!m("a'c"));
    }

    #[test]
    fn escaped_semicolon_in_unquoted_value() {
        let r = parse("echo #1\n  1 = ^a\\;b$ ; comment\n").unwrap();
        assert!(r.match_argv(&["echo".into(), "a;b".into()]).is_some());
    }

    #[test]
    fn quoted_value_with_trailing_word_rejected() {
        let err = parse("echo #1\n  1 = '^a$' b\n").unwrap_err();
        assert!(
            err.message.contains("single quoted string"),
            "{}",
            err.message
        );
    }

    #[test]
    fn attribute_missing_equals_before_comment_rejected() {
        let err = parse("echo\n  timeout ; = 5s\n").unwrap_err();
        assert!(err.message.contains("missing '='"), "{}", err.message);
    }

    #[test]
    fn match_arity_mismatch() {
        let r = parse("git log -n #1\n  1 = ^[0-9]+$\n").unwrap();
        let no = r.match_argv(&["git".into(), "log".into(), "-n".into()]);
        assert!(no.is_none());
    }

    #[test]
    fn match_named_slot() {
        let r = parse("rsync -a #src #dst\n  src = ^[a-z]+$\n  dst = ^[a-z]+$\n").unwrap();
        let m = r.match_argv(&["rsync".into(), "-a".into(), "foo".into(), "bar".into()]);
        let m = m.unwrap();
        assert_eq!(m.bindings.get(&SlotId::Name("src".into())).unwrap(), "foo");
    }

    #[test]
    fn defaults_then_rule() {
        let src = "defaults:\n  timeout = 5s\n\ngit log -n #1\n  1 = ^[0-9]+$\n";
        let r = parse(src).unwrap();
        assert_eq!(r.defaults.timeout, Some(Duration::from_secs(5)));
        assert_eq!(r.rules.len(), 1);
    }

    #[test]
    fn comments_and_blanks() {
        let src = "; top comment\n\ngit log\n  ; rule comment\n";
        let r = parse(src).unwrap();
        assert_eq!(r.rules.len(), 1);
    }

    #[test]
    fn duplicate_slot_rejected() {
        let err = parse("cmd #1 #1\n").unwrap_err();
        assert!(err.message.contains("duplicate"));
    }

    #[test]
    fn absolute_exe_must_start_with_slash() {
        let err = parse("path/to/cmd\n").unwrap_err();
        assert!(err.message.contains("absolute"));
    }

    #[test]
    fn path_template_resolves_slots() {
        let t = PathTemplate {
            raw: "/var/log/sluice/#$pid/c#$call.out".into(),
        };
        t.validate().unwrap();
        let ctx = PathCtx {
            call: 42,
            pid: 1234,
            uid: 1000,
            rule: 7,
            ts: 1714929261,
            ts_ms: 1714929261123,
        };
        assert_eq!(
            t.resolve(&ctx),
            std::path::PathBuf::from("/var/log/sluice/1234/c42.out")
        );
    }

    #[test]
    fn path_template_rejects_unknown_slot() {
        let t = PathTemplate {
            raw: "/var/log/#$bogus.out".into(),
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn parse_stdoutfile() {
        let src = "git log -n #1\n  1 = ^[0-9]+$\n  stdoutfile = /var/log/sluice/c#$call.out\n";
        let r = parse(src).unwrap();
        assert!(r.rules[0].stdoutfile.is_some());
        assert!(r.rules[0].stdoutfile.as_ref().unwrap().is_per_call());
    }

    #[test]
    fn semicolon_inside_quotes_is_not_a_comment() {
        let src = "sh -c 'echo a; echo b'\n";
        let r = parse(src).unwrap();
        assert_eq!(r.rules.len(), 1);
        assert_eq!(r.rules[0].tokens.len(), 2);
    }

    #[test]
    fn parse_audit_mode_default_strict() {
        let r = parse("git log\n").unwrap();
        assert_eq!(r.defaults.audit, AuditMode::Strict);
    }

    #[test]
    fn parse_audit_mode_explicit() {
        let r = parse("defaults:\n  audit = best-effort\n\ngit log\n").unwrap();
        assert_eq!(r.defaults.audit, AuditMode::BestEffort);
    }

    #[test]
    fn parse_exec_path_default_is_classic() {
        let r = parse("git log\n").unwrap();
        match r.defaults.exec_path {
            ExecPath::Explicit(ref s) => assert_eq!(s, "/bin:/usr/bin:/sbin:/usr/sbin"),
            _ => panic!("expected explicit default"),
        }
    }

    #[test]
    fn parse_exec_path_inherit() {
        let r = parse("defaults:\n  exec_path = inherit\n\ngit log\n").unwrap();
        assert_eq!(r.defaults.exec_path, ExecPath::Inherit);
    }

    #[test]
    fn parse_exec_path_custom() {
        let r = parse("defaults:\n  exec_path = /opt/bin:/usr/bin\n\ngit log\n").unwrap();
        match r.defaults.exec_path {
            ExecPath::Explicit(ref s) => assert_eq!(s, "/opt/bin:/usr/bin"),
            _ => panic!(),
        }
    }

    #[test]
    fn parse_exec_path_rejects_relative_entry() {
        let err = parse("defaults:\n  exec_path = /bin:.:/usr/bin\n").unwrap_err();
        assert!(err.message.contains("not absolute"));
    }

    #[test]
    fn parse_exec_path_rejects_empty_entry() {
        let err = parse("defaults:\n  exec_path = /bin::/usr/bin\n").unwrap_err();
        assert!(err.message.contains("empty entry"));
    }

    #[test]
    fn parse_audit_mode_unknown() {
        let err = parse("defaults:\n  audit = lax\n").unwrap_err();
        assert!(err.message.contains("unknown audit mode"));
    }

    #[test]
    fn parse_rejects_bad_path_template() {
        let src = "git log\n  stdoutfile = /var/log/#$nope.out\n";
        let err = parse(src).unwrap_err();
        assert!(err.message.contains("unknown system slot"));
    }

    #[test]
    fn expands_home_in_stdoutfile() {
        std::env::set_var("HOME", "/home/test");
        let src = "git log\n  stdoutfile = $HOME/tmp/c#$call.out\n";
        let r = parse(src).unwrap();
        assert_eq!(
            r.rules[0].stdoutfile.as_ref().unwrap().raw,
            "/home/test/tmp/c#$call.out"
        );
    }

    #[test]
    fn expands_braced_home_in_logfile() {
        std::env::set_var("HOME", "/home/test");
        let src = "defaults:\n  logfile = ${HOME}/.local/state/sluice/manifest.jsonl\n\ngit log\n";
        let r = parse(src).unwrap();
        assert_eq!(
            r.defaults.logfile.as_ref().unwrap().raw,
            "/home/test/.local/state/sluice/manifest.jsonl"
        );
    }

    #[test]
    fn expands_xdg_runtime_dir() {
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        let src = "git log\n  stdoutfile = $XDG_RUNTIME_DIR/sluice/c#$call.out\n";
        let r = parse(src).unwrap();
        assert_eq!(
            r.rules[0].stdoutfile.as_ref().unwrap().raw,
            "/run/user/1000/sluice/c#$call.out"
        );
    }

    #[test]
    fn expands_home_in_cwd() {
        std::env::set_var("HOME", "/home/test");
        let src = "git log\n  cwd = $HOME/projects/repo\n";
        let r = parse(src).unwrap();
        assert_eq!(
            r.rules[0].cwd.as_ref().unwrap(),
            &PathBuf::from("/home/test/projects/repo")
        );
    }

    #[test]
    fn rejects_non_allowlisted_env_var() {
        let src = "git log\n  stdoutfile = $PATH/sluice.out\n";
        let err = parse(src).unwrap_err();
        assert!(err.message.contains("unsupported variable"));
        assert!(err.message.contains("$PATH"));
    }

    #[test]
    fn rejects_unset_home() {
        std::env::remove_var("HOME");
        let src = "git log\n  stdoutfile = $HOME/sluice.out\n";
        let err = parse(src).unwrap_err();
        assert!(err.message.contains("not set"));
        // Restore so other tests aren't affected.
        std::env::set_var("HOME", "/home/test");
    }

    #[test]
    fn rejects_unterminated_brace() {
        std::env::set_var("HOME", "/home/test");
        let src = "git log\n  stdoutfile = ${HOME/x.out\n";
        let err = parse(src).unwrap_err();
        assert!(err.message.contains("unterminated"));
    }

    #[test]
    fn lone_dollar_kept_literal() {
        let src = "git log\n  stdoutfile = /var/log/sluice$.out\n";
        let r = parse(src).unwrap();
        assert_eq!(
            r.rules[0].stdoutfile.as_ref().unwrap().raw,
            "/var/log/sluice$.out"
        );
    }
}
