# waf-rules

Portable WAF detection rules for HTTP log analysis. 13 rules across three severity tiers mapped to OWASP Core Rule Set categories.

Built for offline forensic analysis of IIS W3C Extended logs, but works with any HTTP log format — just populate an `HttpEntry` struct and feed it to the engine.

## Rules

| ID | Severity | Title | OWASP CRS |
|----|----------|-------|-----------|
| WAF-1001 | HIGH | Known webshell filename in URI | CRS 932 |
| WAF-1002 | HIGH | SQL injection payload detected | CRS 942 |
| WAF-1003 | HIGH | OS command injection pattern | CRS 932 |
| WAF-1004 | HIGH | Cross-site scripting payload detected | CRS 941 |
| WAF-1005 | HIGH | Directory traversal sequence | CRS 930 |
| WAF-2001 | MEDIUM | Known vulnerability scanner user agent | CRS 913 |
| WAF-2002 | MEDIUM | Request for sensitive/config file | CRS 930 |
| WAF-2003 | MEDIUM | Uncommon or dangerous HTTP method | CRS 911 |
| WAF-2004 | MEDIUM | Request for non-IIS file extension | CRS 920 |
| WAF-3001 | LOW | Short User-Agent string | — |
| WAF-3002 | LOW | Missing or empty User-Agent | — |
| WAF-3003 | LOW | Large response body | — |
| WAF-3004 | LOW | Slow request processing | — |

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
waf-rules = { git = "https://github.com/moizl599/Portable_WAF_Rules" }
```

Basic usage:

```rust
use waf_rules::{RuleEngine, HttpEntry};

fn main() {
    let engine = RuleEngine::new();

    let entry = HttpEntry {
        method: "GET".into(),
        uri: "/admin/shell.aspx".into(),
        query: "cmd=;+whoami".into(),
        user_agent: "".into(),
        status: 200,
        response_bytes: 4096,
        time_taken_ms: 50,
    };

    let hits = engine.evaluate(&entry);
    for hit in &hits {
        println!("[{}] {} — {}", hit.severity, hit.rule_id, hit.title);
    }

    // Quick check — short-circuits on first match
    if engine.is_flagged(&entry) {
        println!("Entry is suspicious");
    }
}
```

## Custom thresholds

```rust
use waf_rules::{RuleEngine, Config};

let engine = RuleEngine::with_config(Config {
    min_ua_length: 50,          // default: 70
    max_response_bytes: 5_000_000, // default: 10,000,000
    slow_request_ms: 15_000,    // default: 30,000
});
```

## Custom rules

```rust
use waf_rules::{RuleEngine, Rule, Severity};

let mut engine = RuleEngine::new();

engine.add_rule(Rule::new(
    "CUSTOM-001",
    Severity::High,
    "Block debug endpoint",
    "Requests to internal debug endpoints",
    "",
    Box::new(|_entry, uri, _query| {
        uri.contains("/debug/") || uri.contains("/actuator/")
    }),
));
```

## Rules-only (no built-in rules)

```rust
use waf_rules::{RuleEngine, Rule, Severity};

let mut engine = RuleEngine::empty();
// Add only the rules you want
engine.add_rule(Rule::new(
    "MY-001", Severity::High,
    "Custom rule", "Description", "",
    Box::new(|_entry, uri, _query| uri.contains("/forbidden/")),
));
```

## Serde support

Enable serialization for `HttpEntry`, `RuleHit`, `Severity`, and `Config`:

```toml
[dependencies]
waf-rules = { git = "https://github.com/moizl599/waf-rules", features = ["serde"] }
```

## URL decoding

The engine URL-decodes and lowercases URI and query string fields before passing them to rule matchers. This catches encoded payloads like `%5c` (backslash for path traversal), `%3b` (semicolon for command injection), and `+` (space). Raw field values are preserved on the `HttpEntry` struct for display.

## License

MIT
