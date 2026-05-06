//! Rule file parser and matcher.
//!
//! Format: see `examples/sluice.rules`. The parser is line-oriented and
//! whitespace-significant: an unindented line opens a stanza; indented
//! lines attach attributes to the stanza above.

use regex::Regex;
use std::collections::HashMap;
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
    pub timeout: Option<Duration>,
    pub cwd: Option<PathBuf>,
    pub env: Option<EnvPolicy>,
    pub log: Option<LogPolicy>,
    pub logfile: Option<PathTemplate>,
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
        let stripped = strip_comment(raw);
        if stripped.trim().is_empty() {
            continue;
        }
        let indented = stripped.starts_with(|c: char| c == ' ' || c == '\t');
        if indented {
            let (key, val) = split_attr(stripped, line_no)?;
            apply_attr(&mut current, &mut defaults, &mut rules, key, val, line_no)?;
        } else {
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

fn split_attr(line: &str, line_no: usize) -> Result<(&str, &str), ParseError> {
    let trimmed = line.trim();
    let eq = trimmed.find('=').ok_or_else(|| ParseError {
        line_no,
        message: format!("attribute line missing '=': {trimmed:?}"),
    })?;
    let key = trimmed[..eq].trim();
    let val = trimmed[eq + 1..].trim();
    if key.is_empty() {
        return Err(ParseError {
            line_no,
            message: "empty attribute key".into(),
        });
    }
    Ok((key, val))
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
        "cwd" => d.cwd = Some(PathBuf::from(val)),
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
    let t = PathTemplate {
        raw: val.to_string(),
    };
    t.validate().map_err(|e| ParseError {
        line_no,
        message: format!("invalid path template: {e}"),
    })?;
    Ok(t)
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
            r.cwd = Some(PathBuf::from(val));
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
            r.logfile = Some(parse_path_template(val, line_no)?);
            return Ok(());
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
        _ => {}
    }
    if let Some(slot) = parse_slot_id_bare(key) {
        if !r.tokens.iter().any(|t| matches!(t, TokenPattern::Slot(s) if s == &slot)) {
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

fn anchor_regex(re: &str) -> String {
    let starts = re.starts_with('^');
    let ends = re.ends_with('$');
    match (starts, ends) {
        (true, true) => re.to_string(),
        (true, false) => format!("{re}$"),
        (false, true) => format!("^{re}"),
        (false, false) => format!("^{re}$"),
    }
}

fn parse_duration(val: &str, line_no: usize) -> Result<Duration, ParseError> {
    let v = val.trim();
    let (num_part, unit) = v.find(|c: char| c.is_alphabetic()).map_or((v, ""), |i| v.split_at(i));
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
        if !n
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
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
        timeout: None,
        cwd: None,
        env: None,
        log: None,
        logfile: None,
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
        if argv.is_empty() {
            return None;
        }
        self.rules.iter().find_map(|r| r.try_match(argv))
    }
}

impl Rule {
    fn try_match(&self, argv: &[String]) -> Option<Match<'_>> {
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
                    if let Some(re) = self.slot_regex.get(id) {
                        if !re.is_match(v) {
                            return None;
                        }
                    }
                    bindings.insert(id.clone(), v.clone());
                }
            }
        }
        Some(Match {
            rule: self,
            bindings,
        })
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
        let r = parse("git log --oneline -n #1\n").unwrap();
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
    fn match_arity_mismatch() {
        let r = parse("git log -n #1\n").unwrap();
        let no = r.match_argv(&["git".into(), "log".into(), "-n".into()]);
        assert!(no.is_none());
    }

    #[test]
    fn match_named_slot() {
        let r = parse("rsync -a #src #dst\n  src = ^[a-z]+$\n  dst = ^[a-z]+$\n").unwrap();
        let m = r.match_argv(&[
            "rsync".into(),
            "-a".into(),
            "foo".into(),
            "bar".into(),
        ]);
        let m = m.unwrap();
        assert_eq!(
            m.bindings.get(&SlotId::Name("src".into())).unwrap(),
            "foo"
        );
    }

    #[test]
    fn defaults_then_rule() {
        let src = "defaults:\n  timeout = 5s\n\ngit log -n #1\n";
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
        let src = "git log -n #1\n  stdoutfile = /var/log/sluice/c#$call.out\n";
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
}
