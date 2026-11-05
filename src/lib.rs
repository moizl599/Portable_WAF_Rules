//! # WAF Rules
//!
//! Portable WAF detection rules for HTTP/IIS log analysis.
//!
//! Provides 13 detection rules across three severity tiers (HIGH, MEDIUM, LOW)
//! mapped to OWASP Core Rule Set categories. Feed it any HTTP log entry and it
//! tells you which rules matched.
//!
//! ## Quick start
//!
//! ```rust
//! use waf_rules::{RuleEngine, HttpEntry};
//!
//! let engine = RuleEngine::new();
//!
//! let entry = HttpEntry {
//!     method: "GET".into(),
//!     uri: "/admin/shell.aspx".into(),
//!     query: "".into(),
//!     user_agent: "Mozilla/5.0".into(),
//!     status: 404,
//!     response_bytes: 0,
//!     time_taken_ms: 50,
//! };
//!
//! let hits = engine.evaluate(&entry);
//! for hit in &hits {
//!     println!("[{}] {} — {}", hit.severity, hit.rule_id, hit.title);
//! }
//! ```
//!
//! ## Custom rules
//!
//! ```rust
//! use waf_rules::{RuleEngine, Rule, Severity};
//!
//! let mut engine = RuleEngine::new(); // loads 13 built-in rules
//!
//! engine.add_rule(Rule::new(
//!     "CUSTOM-001",
//!     Severity::High,
//!     "Block /debug endpoint",
//!     "Requests to internal debug endpoints",
//!     "",
//!     Box::new(|_entry, uri_decoded, _query_decoded| {
//!         uri_decoded.contains("/debug/") || uri_decoded.contains("/actuator/")
//!     }),
//! ));
//! ```

// Re-export everything from the public API
mod rules;
mod engine;

pub use engine::{RuleEngine, RuleHit};
pub use rules::{Rule, Severity, Config, OWASP_CRS};

/// A normalized HTTP log entry. Feed this to [`RuleEngine::evaluate`].
///
/// All string fields should contain raw values from the log (URL-encoded).
/// The engine handles URL-decoding internally before matching.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HttpEntry {
    /// HTTP method (GET, POST, PUT, etc.)
    pub method: String,
    /// URI path (e.g. `/api/users`)
    pub uri: String,
    /// Query string without leading `?` (e.g. `id=1&name=test`)
    pub query: String,
    /// User-Agent header value
    pub user_agent: String,
    /// HTTP response status code (200, 404, 500, etc.)
    pub status: u16,
    /// Response body size in bytes
    pub response_bytes: u64,
    /// Server processing time in milliseconds
    pub time_taken_ms: u64,
}

/// URL-decode a log field. IIS logs store spaces as `+` and special
/// characters as `%XX`. Returns lowercase for case-insensitive matching.
pub(crate) fn url_decode(s: &str) -> String {
    if s.is_empty() || s == "-" {
        return String::new();
    }
    urlencoding::decode(&s.replace('+', " "))
        .unwrap_or_else(|_| s.replace('+', " ").into())
        .to_lowercase()
}

/// Decode `+` to space without lowercasing (for display/length checks).
pub(crate) fn decode_plus(s: &str) -> String {
    if s.is_empty() || s == "-" {
        return String::new();
    }
    s.replace('+', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("hello+world"), "hello world");
        assert_eq!(url_decode("%2Fetc%2Fpasswd"), "/etc/passwd");
        assert_eq!(url_decode("-"), "");
        assert_eq!(url_decode(""), "");
    }

    #[test]
    fn test_webshell_detection() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/uploads/shell.aspx".into(),
            method: "GET".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-1001"));
    }

    #[test]
    fn test_sqli_detection() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/search".into(),
            query: "id=1'+UNION+SELECT+username,password+FROM+users--".into(),
            method: "GET".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-1002"));
    }

    #[test]
    fn test_command_injection() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/api".into(),
            query: "file=%3b+whoami".into(),
            method: "GET".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-1003"));
    }

    #[test]
    fn test_xss_detection() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/page".into(),
            query: "name=%3Cscript%3Ealert(1)%3C%2Fscript%3E".into(),
            method: "GET".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-1004"));
    }

    #[test]
    fn test_path_traversal() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/files/..%5c..%5cwindows/system.ini".into(),
            method: "GET".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-1005"));
    }

    #[test]
    fn test_scanner_ua() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            user_agent: "Nmap Scripting Engine".into(),
            uri: "/".into(),
            method: "GET".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-2001"));
    }

    #[test]
    fn test_sensitive_file() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/.env".into(),
            method: "GET".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-2002"));
    }

    #[test]
    fn test_suspicious_method() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/api/data".into(),
            method: "TRACE".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-2003"));
    }

    #[test]
    fn test_non_iis_extension() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/admin/config.php".into(),
            method: "GET".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-2004"));
    }

    #[test]
    fn test_empty_ua() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/".into(),
            method: "GET".into(),
            user_agent: "".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-3002"));
    }

    #[test]
    fn test_short_ua() {
        let engine = RuleEngine::with_config(Config {
            min_ua_length: 70,
            ..Default::default()
        });
        let entry = HttpEntry {
            uri: "/".into(),
            method: "GET".into(),
            user_agent: "curl/7.68".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-3001"));
    }

    #[test]
    fn test_large_response() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/".into(),
            method: "GET".into(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120".into(),
            response_bytes: 15_000_000,
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-3003"));
    }

    #[test]
    fn test_slow_request() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/".into(),
            method: "GET".into(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120".into(),
            time_taken_ms: 45_000,
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "WAF-3004"));
    }

    #[test]
    fn test_clean_request_no_hits() {
        let engine = RuleEngine::new();
        let entry = HttpEntry {
            uri: "/index.html".into(),
            method: "GET".into(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into(),
            status: 200,
            response_bytes: 4096,
            time_taken_ms: 50,
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.is_empty(), "Clean request should have no hits, got: {:?}", hits);
    }

    #[test]
    fn test_custom_rule() {
        let mut engine = RuleEngine::new();
        engine.add_rule(Rule::new(
            "CUSTOM-001",
            Severity::High,
            "Block debug endpoint",
            "Internal debug endpoints",
            "",
            Box::new(|_entry, uri, _query| uri.contains("/debug/")),
        ));

        let entry = HttpEntry {
            uri: "/debug/vars".into(),
            method: "GET".into(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        assert!(hits.iter().any(|h| h.rule_id == "CUSTOM-001"));
    }

    #[test]
    fn test_multiple_hits() {
        let engine = RuleEngine::new();
        // A request that triggers multiple rules
        let entry = HttpEntry {
            uri: "/admin/shell.aspx".into(),
            query: "cmd=;+whoami".into(),
            method: "GET".into(),
            user_agent: "".into(),
            ..Default::default()
        };
        let hits = engine.evaluate(&entry);
        // Should hit webshell + command injection + empty UA at minimum
        assert!(hits.len() >= 3, "Expected 3+ hits, got {}: {:?}", hits.len(), hits);
    }
}
