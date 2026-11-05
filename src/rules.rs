use regex::Regex;
use crate::{HttpEntry, url_decode, decode_plus};

/// Severity level for a WAF rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    /// Sort key (High = 0, Medium = 1, Low = 2).
    pub fn order(&self) -> u8 {
        match self {
            Severity::High => 0,
            Severity::Medium => 1,
            Severity::Low => 2,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OWASP Core Rule Set category reference.
pub type OWASP_CRS = &'static str;

/// Configurable thresholds for rules that depend on them.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Config {
    /// Minimum User-Agent length before flagging. Default: 70.
    pub min_ua_length: usize,
    /// Response size threshold in bytes. Default: 10,000,000.
    pub max_response_bytes: u64,
    /// Slow request threshold in ms. Default: 30,000.
    pub slow_request_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_ua_length: 70,
            max_response_bytes: 10_000_000,
            slow_request_ms: 30_000,
        }
    }
}

/// A single WAF detection rule.
///
/// Each rule has an ID, severity, human-readable title and description,
/// an optional OWASP CRS reference, and a matcher function.
///
/// The matcher receives `(entry, uri_decoded, query_decoded)` where the
/// decoded strings are already URL-decoded and lowercased.
pub struct Rule {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub owasp_crs: String,
    pub matcher: Box<dyn Fn(&HttpEntry, &str, &str) -> bool + Send + Sync>,
}

impl Rule {
    /// Create a new rule.
    pub fn new(
        rule_id: &str,
        severity: Severity,
        title: &str,
        description: &str,
        owasp_crs: &str,
        matcher: Box<dyn Fn(&HttpEntry, &str, &str) -> bool + Send + Sync>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            title: title.into(),
            description: description.into(),
            owasp_crs: owasp_crs.into(),
            matcher,
        }
    }

    /// Test whether an entry matches this rule.
    /// `uri_decoded` and `query_decoded` must already be URL-decoded + lowercased.
    pub fn matches(&self, entry: &HttpEntry, uri_decoded: &str, query_decoded: &str) -> bool {
        (self.matcher)(entry, uri_decoded, query_decoded)
    }
}

impl std::fmt::Debug for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rule")
            .field("rule_id", &self.rule_id)
            .field("severity", &self.severity)
            .field("title", &self.title)
            .finish()
    }
}

// ---------------------------------------------------------------------------
//  Built-in rules
// ---------------------------------------------------------------------------

/// Build the 13 default WAF detection rules.
pub fn default_rules(config: &Config) -> Vec<Rule> {
    let re_webshell = Regex::new(
        r"(?i)(?:web)?shell\.aspx|cmd\.aspx|cmdshell|c99\.php|r57\.php|b374k|chopper|china_chopper|aspxspy|antsword|godzilla|behinder|jspwebshell|jspspy|devilzshell|wso\.php|alfa\.php|mini[\-_]?shell|phpspy|lamashell|filesman|leafmailer|adminer\.php|phpinfo\.php|eval-stdin\.php|tunnel\.aspx|regeorg|neo-regeorg|chisel|plink"
    ).unwrap();

    let re_sqli = Regex::new(
        r"(?i)(?:union[\s+]+(?:all[\s+]+)?select|select[\s+]+.*[\s+]+from[\s+]+information_schema|waitfor[\s+]+delay|exec[\s+]+(?:master\.\.)?xp_cmdshell|benchmark\s*\(|(?:and|or)[\s+]+[\d]+[\s+]*=[\s+]*[\d]+|(?:and|or)[\s+]+['\x22][\s+]*=[\s+]*['\x22]|having[\s+]+\d+[\s+]*=[\s+]*\d+|order[\s+]+by[\s+]+\d{2,}|0x5175616c79735f53514c49|convert\s*\(\s*int|cast\s*\([\s\S]*?\s+as\s+|declare[\s+]+@|';?\s*(?:drop|alter|create|truncate|insert|update|delete)[\s+])"
    ).unwrap();

    let re_cmd_injection = Regex::new(
        r"(?i)(?:;|\||`|&|\$\()\s*(?:cat|ls|dir|type|net|whoami|id|uname|ping|nslookup|curl|wget|nc|ncat|bash|sh|cmd|powershell|certutil|bitsadmin|regsvr32|mshta|rundll32)"
    ).unwrap();

    let re_xss = Regex::new(
        r"(?i)<\s*script|javascript\s*:|on(?:error|load|click|mouseover|focus)\s*=|<\s*img[^>]+onerror|<\s*svg[^>]+onload|<\s*iframe|document\.(?:cookie|write|location)|alert\s*\(|prompt\s*\(|confirm\s*\(|eval\s*\(|expression\s*\(|fromcharcode"
    ).unwrap();

    let re_path_traversal = Regex::new(r"\.\.[/\\]").unwrap();

    let re_scanner_ua = Regex::new(
        r"(?i)palo.alto.networks|cortex.xpanse|nmap|nikto|sqlmap|dirbuster|dirb[\s/]|gobuster|nuclei|masscan|zgrab|wpscan|joomscan|acunetix|nessus|openvas|qualys|rapid7|burpsuite|burp.suite|owasp.zap|zaproxy|arachni|w3af|skipfish|whatweb|python-httpx|python-requests|python-urllib|go-http-client|java/\d|libwww-perl|curl/\d|wget/\d|httpie|censys|shodan|binaryedge|crtsh|securitytrails"
    ).unwrap();

    let re_sensitive_files = Regex::new(
        r"(?i)(?:web\.config|\.env|\.git(?:/|$)|\.svn(?:/|$)|wp-config\.php|config\.php|\.htaccess|\.htpasswd|\.aws/credentials|\.ssh/|id_rsa|\.bash_history|passwd$|shadow$|boot\.ini|win\.ini|phpMyAdmin|phpmyadmin|/admin/|/manager/html|\.bak$|\.old$|\.orig$|\.save$|\.swp$|\.tmp$|\.sql$|\.dump$|\.tar\.gz$|\.zip$|crossdomain\.xml|clientaccesspolicy\.xml|WEB-INF|META-INF)"
    ).unwrap();

    let re_non_iis_ext = Regex::new(
        r"(?i)\.(?:php|jsp|jspx|do|action|cgi|pl|py|rb|cfm|jsf|faces|struts|yaws|lua)\d*(?:\?|$)"
    ).unwrap();

    let suspicious_methods: Vec<&'static str> = vec![
        "PUT", "DELETE", "TRACE", "CONNECT", "PATCH",
        "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
        "MOVE", "LOCK", "UNLOCK",
    ];

    let min_ua = config.min_ua_length;
    let max_resp = config.max_response_bytes;
    let slow_ms = config.slow_request_ms;

    vec![
        // ── HIGH ────────────────────────────────────────────────
        Rule::new(
            "WAF-1001", Severity::High,
            "Known webshell filename in URI",
            "Request URI contains a filename associated with web shells (shell.aspx, c99.php, jspwebshell.jsp, reGeorg tunnel, etc.)",
            "CRS 932",
            Box::new(move |_entry, uri, _q| re_webshell.is_match(uri)),
        ),
        Rule::new(
            "WAF-1002", Severity::High,
            "SQL injection payload detected",
            "URI or query string contains SQL injection patterns (UNION SELECT, WAITFOR DELAY, xp_cmdshell, etc.)",
            "CRS 942",
            Box::new(move |_entry, uri, q| {
                let combined = format!("{} {}", q, uri);
                re_sqli.is_match(&combined)
            }),
        ),
        Rule::new(
            "WAF-1003", Severity::High,
            "OS command injection pattern",
            "URI or query string contains OS command injection sequences (pipe/semicolon + system commands)",
            "CRS 932",
            Box::new(move |_entry, uri, q| {
                let combined = format!("{} {}", q, uri);
                re_cmd_injection.is_match(&combined)
            }),
        ),
        Rule::new(
            "WAF-1004", Severity::High,
            "Cross-site scripting payload detected",
            "URI or query contains XSS patterns (<script>, javascript:, event handlers, document.cookie, eval(), etc.)",
            "CRS 941",
            Box::new(move |_entry, uri, q| {
                let combined = format!("{} {}", q, uri);
                re_xss.is_match(&combined)
            }),
        ),
        Rule::new(
            "WAF-1005", Severity::High,
            "Directory traversal sequence in request",
            "URI or query string contains ../ or ..\\ sequences attempting path traversal",
            "CRS 930",
            Box::new(move |_entry, uri, q| {
                let combined = format!("{} {}", uri, q);
                re_path_traversal.is_match(&combined)
            }),
        ),

        // ── MEDIUM ──────────────────────────────────────────────
        Rule::new(
            "WAF-2001", Severity::Medium,
            "Known vulnerability scanner user agent",
            "User-Agent header matches a known security scanner or automated attack tool",
            "CRS 913",
            Box::new(move |entry, _, _| {
                let ua = entry.user_agent.to_lowercase();
                re_scanner_ua.is_match(&ua)
            }),
        ),
        Rule::new(
            "WAF-2002", Severity::Medium,
            "Request for sensitive or configuration file",
            "URI targets files that should not be publicly accessible (.env, web.config, .git/, .bak, .sql, etc.)",
            "CRS 930",
            Box::new(move |_entry, uri, _| re_sensitive_files.is_match(uri)),
        ),
        Rule::new(
            "WAF-2003", Severity::Medium,
            "Uncommon or dangerous HTTP method",
            "HTTP method is PUT, DELETE, TRACE, CONNECT, or a WebDAV method",
            "CRS 911",
            Box::new(move |entry, _, _| {
                let upper = entry.method.to_uppercase();
                suspicious_methods.contains(&upper.as_str())
            }),
        ),
        Rule::new(
            "WAF-2004", Severity::Medium,
            "Request for non-IIS file extension",
            "URI targets a file extension not native to IIS (.php, .jsp, .cgi, .action, .do, etc.)",
            "CRS 920",
            Box::new(move |_entry, uri, _| re_non_iis_ext.is_match(uri)),
        ),

        // ── LOW ─────────────────────────────────────────────────
        Rule::new(
            "WAF-3001", Severity::Low,
            &format!("User-Agent string shorter than {} characters", min_ua),
            "User-Agent is shorter than the configured minimum. Legitimate browsers typically send 70+ character UA strings.",
            "",
            Box::new(move |entry, _, _| {
                let ua = decode_plus(&entry.user_agent);
                !ua.is_empty() && ua.len() < min_ua
            }),
        ),
        Rule::new(
            "WAF-3002", Severity::Low,
            "Missing or empty User-Agent header",
            "User-Agent is empty or '-'. Legitimate browsers always send a User-Agent.",
            "",
            Box::new(move |entry, _, _| {
                entry.user_agent.is_empty() || entry.user_agent == "-"
            }),
        ),
        Rule::new(
            "WAF-3003", Severity::Low,
            "Large response body",
            "Server sent an unusually large response. May indicate data exfiltration.",
            "",
            Box::new(move |entry, _, _| entry.response_bytes > max_resp),
        ),
        Rule::new(
            "WAF-3004", Severity::Low,
            "Slow request processing",
            "Server took an unusually long time. May indicate time-based SQL injection or resource exhaustion.",
            "",
            Box::new(move |entry, _, _| entry.time_taken_ms > slow_ms),
        ),
    ]
}
