use crate::{HttpEntry, url_decode};
use crate::rules::{Rule, Severity, Config, default_rules};

/// Result of a rule matching against an entry.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RuleHit {
    /// Rule ID (e.g. "WAF-1001")
    pub rule_id: String,
    /// Severity level
    pub severity: Severity,
    /// Human-readable title
    pub title: String,
    /// OWASP CRS category reference
    pub owasp_crs: String,
}

/// The rule engine. Holds all rules and evaluates entries against them.
///
/// Thread-safe — can be shared across threads with `Arc<RuleEngine>`.
pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    /// Create a new engine with all 13 built-in rules using default thresholds.
    pub fn new() -> Self {
        Self::with_config(Config::default())
    }

    /// Create a new engine with custom thresholds.
    pub fn with_config(config: Config) -> Self {
        Self {
            rules: default_rules(&config),
        }
    }

    /// Create an empty engine (no rules). Add rules with [`add_rule`].
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a custom rule to the engine.
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get a reference to all loaded rules.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Evaluate a single HTTP entry against all rules.
    /// Returns a list of matching rule hits (empty if clean).
    pub fn evaluate(&self, entry: &HttpEntry) -> Vec<RuleHit> {
        let uri_decoded = url_decode(&entry.uri);
        let query_decoded = url_decode(&entry.query);

        let mut hits = Vec::new();
        for rule in &self.rules {
            if rule.matches(entry, &uri_decoded, &query_decoded) {
                hits.push(RuleHit {
                    rule_id: rule.rule_id.clone(),
                    severity: rule.severity,
                    title: rule.title.clone(),
                    owasp_crs: rule.owasp_crs.clone(),
                });
            }
        }
        hits
    }

    /// Evaluate an entry and return just the rule IDs that matched.
    pub fn evaluate_ids(&self, entry: &HttpEntry) -> Vec<String> {
        self.evaluate(entry)
            .into_iter()
            .map(|h| h.rule_id)
            .collect()
    }

    /// Check if any rule matches (short-circuits on first hit).
    pub fn is_flagged(&self, entry: &HttpEntry) -> bool {
        let uri_decoded = url_decode(&entry.uri);
        let query_decoded = url_decode(&entry.query);

        self.rules.iter().any(|r| r.matches(entry, &uri_decoded, &query_decoded))
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}
