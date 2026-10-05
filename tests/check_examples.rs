//! Smoke test: the shipped example rules file must parse cleanly.

#[test]
fn example_rules_parse() {
    let src = std::fs::read_to_string("examples/sluice.rules").unwrap();
    let rules = sluicify::rules::parse(&src).expect("examples/sluice.rules failed to parse");
    assert!(rules.rules.len() >= 4, "expected at least 4 rules");
}

#[test]
fn example_rules_match_git() {
    let src = std::fs::read_to_string("examples/sluice.rules").unwrap();
    let rules = sluicify::rules::parse(&src).unwrap();
    let argv: Vec<String> = [
        "git",
        "-C",
        "/var/repos/main",
        "log",
        "--oneline",
        "-n",
        "5",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert!(rules.match_argv(&argv).is_some());
}

#[test]
fn example_rules_reject_bad_n() {
    let src = std::fs::read_to_string("examples/sluice.rules").unwrap();
    let rules = sluicify::rules::parse(&src).unwrap();
    let argv: Vec<String> = [
        "git",
        "-C",
        "/var/repos/main",
        "log",
        "--oneline",
        "-n",
        "999",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert!(rules.match_argv(&argv).is_none());
}
