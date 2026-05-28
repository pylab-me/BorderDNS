//! Domain blocking by exact name, suffix, or wildcard pattern.
//!
//! This module provides [`BlockMatcher`], a trie-based domain blocker that
//! supports the full pattern language from the Python reference:
//!
//! | Pattern          | Semantic                                      |
//! |------------------|-----------------------------------------------|
//! | `example.com`    | exact domain match                            |
//! | `**.doubleclick.net` | any domain ending with `.doubleclick.net` |
//! | `*.jddebug.com`  | exactly one subdomain of `jddebug.com`        |
//! | `**.umeng.**`    | `umeng` appears as a complete label anywhere  |
//! | `clientlog*.**`  | first label starts with `clientlog`           |
//!
//! The implementation is a reversed-label trie (rightmost label first) with
//! three child types per node:
//!
//! - **exact** — literal label match.
//! - **pattern** — label-level glob (`*` matches any characters within a
//!   single label).
//! - **multi** — `**` matches zero or more entire labels (self-loop).
//!
//! This is a faithful port of Python `structures/domain_rules.py`
//! `DomainRuleMatcher`, translated to idiomatic Rust with no regex dependency.

use std::collections::HashMap;
use std::io;
use std::path::Path;

// ─── Label-level glob matching ──────────────────────────────────

/// Match a single label against a glob pattern containing `*` wildcards.
///
/// `*` matches zero or more characters **within one label**.
/// This is NOT regex — it is a simple ordered-segment check.
///
/// Returns `false` if the pattern contains no `*` and doesn't match literally.
fn label_matches_glob(pattern: &str, target: &str) -> bool {
    if !pattern.contains('*') {
        return pattern.eq_ignore_ascii_case(target);
    }

    let pattern_lower = pattern.to_lowercase();
    let target_lower = target.to_lowercase();
    let parts: Vec<&str> = pattern_lower.split('*').collect();

    // All parts must appear in order in the target.
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // First part must be at the start.
            if !target_lower.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // Last part must be at the end.
            if !target_lower.ends_with(part) {
                return false;
            }
        } else {
            // Middle parts must be found in order after `pos`.
            if let Some(found) = target_lower[pos..].find(part) {
                pos += found + part.len();
            } else {
                return false;
            }
        }
    }
    true
}

// ─── Reversed-label trie ────────────────────────────────────────

/// An edge from a `**` (multi) or exact/pattern node to its child,
/// carrying the compiled glob segments for pattern edges.
#[derive(Debug, Clone)]
struct PatternEdge {
    /// Raw label pattern (e.g. `"clientlog*"`), kept for debug/display.
    raw: String,
    /// Child trie node.
    node: Box<TrieNode>,
}

/// A node in the reversed-label trie.
#[derive(Debug, Clone, Default)]
struct TrieNode {
    /// Exact-label children.
    exact_children: HashMap<String, Box<TrieNode>>,
    /// Glob-pattern children (single-label wildcards).
    pattern_children: Vec<PatternEdge>,
    /// `**` multi-label child (matches zero or more labels).
    multi_child: Option<Box<TrieNode>>,
    /// Whether this node is a terminal (rule ends here).
    terminal: bool,
    /// Whether this node was created by a `**` token.
    /// Controls the self-loop and skip-label semantics.
    is_multi: bool,
}

impl TrieNode {
    fn get_or_create_exact(&mut self, label: &str) -> &mut Box<TrieNode> {
        self.exact_children.entry(label.to_lowercase()).or_default()
    }

    fn get_or_create_pattern(&mut self, label: &str) -> &mut Box<TrieNode> {
        // Find or insert by index to satisfy the borrow checker.
        let idx = match self.pattern_children.iter().position(|e| e.raw == label) {
            Some(i) => i,
            None => {
                self.pattern_children.push(PatternEdge {
                    raw: label.to_string(),
                    node: Box::new(TrieNode::default()),
                });
                self.pattern_children.len() - 1
            }
        };
        &mut self.pattern_children[idx].node
    }

    fn get_or_create_multi(&mut self) -> &mut Box<TrieNode> {
        self.multi_child.get_or_insert_with(|| {
            Box::new(TrieNode {
                is_multi: true,
                ..TrieNode::default()
            })
        })
    }
}

// ─── Recursive match with memoization ───────────────────────────

/// Key for the memoization map: `(node pointer identity, label index)`.
///
/// We use `*const TrieNode` for pointer identity because nodes are
/// heap-allocated and stable after insertion.
type MemoKey = (*const TrieNode, usize);

/// Recursive trie match, ported from Python `_RuleNode._match_node`.
///
/// Algorithm overview:
///
/// 1. If the current node is terminal **and** we've consumed all labels
///    (or the node is a `**` multi node), return true.
/// 2. If this node is a `**` multi node, try staying at the same node
///    (skipping the current label) — this handles `**` matching multiple
///    consecutive labels.
/// 3. Try matching the current label against exact children.
/// 4. Try matching the current label against pattern children (glob).
/// 5. If this node is a `**` multi node, advance to the next label
///    without moving to a child — this handles `**` matching zero labels.
/// 6. Try the `**` multi child (if distinct from the node itself),
///    advancing to the next label.
fn match_node<'a>(
    node: &'a TrieNode,
    labels: &[String],
    index: usize,
    memo: &mut HashMap<MemoKey, bool>,
) -> bool {
    let key = (node as *const TrieNode, index);
    if let Some(&cached) = memo.get(&key) {
        return cached;
    }

    // Terminal check: rule ends here and we consumed all labels,
    // or this is a `**` node (which can match at any point).
    if node.terminal && (index == labels.len() || node.is_multi) {
        memo.insert(key, true);
        return true;
    }

    // `**` multi child: try staying at the multi node (self-loop).
    if let Some(ref multi) = node.multi_child {
        if match_node(multi, labels, index, memo) {
            memo.insert(key, true);
            return true;
        }
    }

    if index >= labels.len() {
        memo.insert(key, false);
        return false;
    }

    let label = &labels[index];

    // Exact child match.
    if let Some(exact_child) = node.exact_children.get(label.as_str()) {
        // If current node is `**` and the exact child is terminal,
        // we can stop here (the exact match plus multi skip).
        if node.is_multi && exact_child.terminal {
            memo.insert(key, true);
            return true;
        }
        if match_node(exact_child, labels, index + 1, memo) {
            memo.insert(key, true);
            return true;
        }
    }

    // Pattern child match (glob within a single label).
    for edge in &node.pattern_children {
        if label_matches_glob(&edge.raw, label) {
            // If current node is `**` and pattern child is terminal,
            // we can stop here.
            if node.is_multi && edge.node.terminal {
                memo.insert(key, true);
                return true;
            }
            if match_node(&edge.node, labels, index + 1, memo) {
                memo.insert(key, true);
                return true;
            }
        }
    }

    // `**` self-loop: skip the current label and stay at this node.
    if node.is_multi && match_node(node, labels, index + 1, memo) {
        memo.insert(key, true);
        return true;
    }

    // `**` multi child: skip the current label and move to multi child.
    if let Some(ref multi) = node.multi_child {
        if match_node(multi, labels, index + 1, memo) {
            memo.insert(key, true);
            return true;
        }
    }

    memo.insert(key, false);
    false
}

// ─── Public API ─────────────────────────────────────────────────

/// Domain blocking matcher with full wildcard pattern support.
///
/// Supports:
/// - Exact domain names (`"example.com"`)
/// - `**` multi-label wildcard (`"**.doubleclick.net"`)
/// - `*` single-label glob (`"*.jddebug.com"`)
/// - Combined patterns (`"**.umeng.**"`, `"clientlog*.**"`)
///
/// This is pure data matching — no DNS encoding, no response building.
/// Response construction belongs to the pipeline stage.
///
/// # Examples
///
/// ```text
/// let matcher = BlockMatcher::from_patterns(&[
///     "**.doubleclick.net",
///     "*.jddebug.com",
///     "**.umeng.**",
///     "clientlog*.**",
/// ]);
/// assert!(matcher.is_blocked("ad.doubleclick.net"));
/// assert!(matcher.is_blocked("foo.jddebug.com"));
/// assert!(matcher.is_blocked("abc.umeng.com"));
/// assert!(matcher.is_blocked("clientlog123.test.com"));
/// ```
#[derive(Debug, Clone)]
pub struct BlockMatcher {
    root: TrieNode,
    rule_count: usize,
}

impl BlockMatcher {
    /// Create a matcher from raw pattern rules.
    ///
    /// Rules are normalized:
    /// - Trailing dots are stripped.
    /// - Case is folded to lowercase.
    /// - A bare `*` (no dots) becomes `*.**` to prevent single-label-only matching.
    ///
    /// Pattern language:
    /// - No wildcards → exact match.
    /// - `**` → matches zero or more labels.
    /// - `*` within a label → matches any characters within that label.
    #[must_use]
    pub fn from_patterns(rules: &[&str]) -> Self {
        let mut matcher = Self::default();
        matcher.batch_add(rules);
        matcher
    }

    /// Add a single pattern rule.
    pub fn add_pattern(&mut self, rule: &str) {
        let normalized = normalize_rule(rule);
        if normalized.is_empty() {
            return;
        }
        let labels = split_labels_reversed(&normalized);
        let mut node = &mut self.root;
        for label in &labels {
            if label == "**" {
                node = node.get_or_create_multi();
            } else if label.contains('*') {
                node = node.get_or_create_pattern(label);
            } else {
                node = node.get_or_create_exact(label);
            }
        }
        if !node.terminal {
            node.terminal = true;
            self.rule_count += 1;
        }
    }

    /// Add multiple pattern rules at once.
    pub fn batch_add(&mut self, rules: &[&str]) {
        for rule in rules {
            self.add_pattern(rule);
        }
    }

    /// Load rules from a reader, one rule per line.
    ///
    /// Skips:
    /// - Empty lines and whitespace-only lines.
    /// - Lines starting with `#` (comments).
    /// - Lines where the first non-whitespace character is `#`.
    ///
    /// Returns the number of rules successfully loaded.
    pub fn load_rules_from_reader<R: io::BufRead>(&mut self, reader: R) -> usize {
        let mut loaded = 0;
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    self.add_pattern(trimmed);
                    loaded += 1;
                }
                Err(_) => continue,
            }
        }
        loaded
    }

    /// Load rules from a file path.
    ///
    /// File format: one pattern per line, `#` for comments, empty lines
    /// are skipped. Returns `Ok(count)` with the number of rules loaded,
    /// or `Err` if the file cannot be opened/read.
    pub fn load_rules_from_file<P: AsRef<Path>>(&mut self, path: P) -> io::Result<usize> {
        let file = std::fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        Ok(self.load_rules_from_reader(reader))
    }

    /// Backward-compatible constructor from exact domains and suffixes.
    ///
    /// Each exact domain is inserted as-is.
    /// Each suffix is wrapped as `**.{suffix}` to match the original semantics.
    #[must_use]
    pub fn new(exact_domains: &[&str], suffixes: &[&str]) -> Self {
        let mut matcher = Self::default();
        for d in exact_domains {
            matcher.add_pattern(d);
        }
        for s in suffixes {
            let suffix = s.strip_suffix('.').unwrap_or(s);
            let pattern = format!("**.{suffix}");
            matcher.add_pattern(&pattern);
        }
        matcher
    }

    /// Check if a domain should be blocked.
    #[must_use]
    pub fn is_blocked(&self, domain: &str) -> bool {
        let name = domain.strip_suffix('.').unwrap_or(domain).to_lowercase();
        if name.is_empty() {
            return false;
        }
        let labels = split_labels_reversed(&name);
        let mut memo = HashMap::new();
        match_node(&self.root, &labels, 0, &mut memo)
    }

    /// Whether this matcher has any rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rule_count == 0
    }

    /// Number of rules loaded.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
}

impl Default for BlockMatcher {
    fn default() -> Self {
        Self {
            root: TrieNode::default(),
            rule_count: 0,
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────

/// Normalize a rule string (Python `_normalize_rule` equivalent).
fn normalize_rule(rule: &str) -> String {
    let normalized = rule.strip_suffix('.').unwrap_or(rule).trim().to_lowercase();
    if normalized.is_empty() {
        return String::new();
    }
    // Bare wildcard (no dots) → append `.**` to prevent single-label-only match.
    if normalized.contains('*') && !normalized.contains('.') {
        return format!("{normalized}.**");
    }
    normalized
}

/// Split a domain into labels, reversed (rightmost label first).
/// This is the Python `_split_labels` equivalent.
fn split_labels_reversed(domain: &str) -> Vec<String> {
    domain
        .split('.')
        .filter(|l| !l.is_empty())
        .rev()
        .map(|l| l.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Exact match ───────────────────────────────────────────

    #[test]
    fn exact_match_basic() {
        let m = BlockMatcher::from_patterns(&["example.com"]);
        assert!(m.is_blocked("example.com"));
        assert!(!m.is_blocked("sub.example.com"));
        assert!(!m.is_blocked("notexample.com"));
    }

    #[test]
    fn exact_match_trailing_dot() {
        let m = BlockMatcher::from_patterns(&["example.com"]);
        assert!(m.is_blocked("example.com."));
    }

    #[test]
    fn exact_match_case_insensitive() {
        let m = BlockMatcher::from_patterns(&["Ads.Example.Com"]);
        assert!(m.is_blocked("ads.example.com"));
        assert!(m.is_blocked("ADS.EXAMPLE.COM"));
    }

    // ─── Suffix / `**` prefix match ────────────────────────────

    #[test]
    fn suffix_double_star_prefix() {
        let m = BlockMatcher::from_patterns(&["**.doubleclick.net"]);
        assert!(m.is_blocked("doubleclick.net"));
        assert!(m.is_blocked("ad.doubleclick.net"));
        assert!(m.is_blocked("tracker.ad.doubleclick.net"));
        assert!(!m.is_blocked("doubleclick-other.net"));
        assert!(!m.is_blocked("notdoubleclick.net"));
    }

    #[test]
    fn suffix_double_star_deep() {
        let m = BlockMatcher::from_patterns(&["**.akadns.net"]);
        assert!(m.is_blocked("akadns.net"));
        assert!(m.is_blocked("a.b.akadns.net"));
    }

    // ─── Single `*` prefix (exactly one label) ─────────────────

    #[test]
    fn single_star_prefix_exactly_one_label() {
        let m = BlockMatcher::from_patterns(&["*.jddebug.com"]);
        assert!(m.is_blocked("foo.jddebug.com"));
        assert!(m.is_blocked("bar.jddebug.com"));
        // `*` only matches within a single label, NOT multi-label.
        assert!(!m.is_blocked("a.b.jddebug.com"));
        assert!(!m.is_blocked("jddebug.com"));
    }

    #[test]
    fn single_star_prefix_cdntips() {
        let m = BlockMatcher::from_patterns(&["*.dlied1.cdntips.net"]);
        assert!(m.is_blocked("x.dlied1.cdntips.net"));
        assert!(!m.is_blocked("a.b.dlied1.cdntips.net"));
    }

    // ─── `**` label-contains: `**.umeng.**` ────────────────────

    #[test]
    fn multi_wildcard_label_contains() {
        let m = BlockMatcher::from_patterns(&["**.umeng.**"]);
        assert!(m.is_blocked("umeng.com"));
        assert!(m.is_blocked("abc.umeng.com"));
        assert!(m.is_blocked("x.y.umeng.co.uk"));
        assert!(!m.is_blocked("notumeng.com"));
        assert!(!m.is_blocked("umengs.com"));
    }

    // ─── First-label prefix: `clientlog*.**` ───────────────────

    #[test]
    fn first_label_prefix_glob() {
        let m = BlockMatcher::from_patterns(&["clientlog*.**"]);
        assert!(m.is_blocked("clientlog123.example.com"));
        assert!(m.is_blocked("clientlogabc.test.cn"));
        assert!(m.is_blocked("clientlog.com"));
        assert!(!m.is_blocked("notclientlog.com"));
    }

    // ─── Exact domains from testcases ──────────────────────────

    #[test]
    fn testcases_exact_domains() {
        let m = BlockMatcher::from_patterns(&[
            "10.ras.yahoo.com",
            "11.ras.yahoo.com",
            "3773406.fls.doubleclick.net",
        ]);
        assert!(m.is_blocked("10.ras.yahoo.com"));
        assert!(m.is_blocked("11.ras.yahoo.com"));
        assert!(m.is_blocked("3773406.fls.doubleclick.net"));
        assert!(!m.is_blocked("9.ras.yahoo.com"));
        assert!(!m.is_blocked("10.ras.other.com"));
    }

    // ─── All testcases patterns together ───────────────────────

    #[test]
    fn testcases_all_patterns() {
        let m = BlockMatcher::from_patterns(&[
            "**.umeng.**",
            "clientlog*.**",
            "**.akadns.net",
            "**.alibabadns.com",
            "**.alipaydns.com",
            "**.baiduyundns.cn",
            "**.baiduyundns.com",
            "**.baiduyundns.net",
            "**.bcedns.com",
            "**.bcedns.net",
            "**.bdydns.cn",
            "**.bdydns.com",
            "**.bdydns.net",
            "**.dnspao.com",
            "**.dnspod.com",
            "**.jomodns.com",
            "**.qiniudns.com",
            "**.wscdns.com",
            "**.tdnsv6.com",
            "**.gds.alibabadns.com",
            "*.jddebug.com",
            "*.dlied1.cdntips.net",
            "10.ras.yahoo.com",
            "11.ras.yahoo.com",
            "3773406.fls.doubleclick.net",
        ]);

        // **.umeng.**
        assert!(m.is_blocked("abc.umeng.com"));
        assert!(!m.is_blocked("notumeng.com"));

        // clientlog*.**
        assert!(m.is_blocked("clientlog123.example.com"));

        // **.akadns.net
        assert!(m.is_blocked("x.akadns.net"));
        assert!(m.is_blocked("akadns.net"));

        // **.gds.alibabadns.com
        assert!(m.is_blocked("foo.gds.alibabadns.com"));
        assert!(m.is_blocked("gds.alibabadns.com"));

        // *.jddebug.com
        assert!(m.is_blocked("foo.jddebug.com"));
        assert!(!m.is_blocked("a.b.jddebug.com"));

        // exact
        assert!(m.is_blocked("10.ras.yahoo.com"));
        assert!(m.is_blocked("3773406.fls.doubleclick.net"));
        assert!(!m.is_blocked("other.com"));
    }

    // ─── Backward-compatible `new()` constructor ───────────────

    #[test]
    fn backward_compat_new_constructor() {
        let m = BlockMatcher::new(&["exact.blocked.com"], &["suffix.blocked.com"]);
        assert!(m.is_blocked("exact.blocked.com"));
        assert!(m.is_blocked("sub.suffix.blocked.com"));
        assert!(m.is_blocked("suffix.blocked.com"));
        assert!(!m.is_blocked("not-blocked.com"));
    }

    // ─── Empty / defaults ──────────────────────────────────────

    #[test]
    fn empty_matcher() {
        let m = BlockMatcher::default();
        assert!(!m.is_blocked("anything.com"));
        assert!(m.is_empty());
        assert_eq!(m.rule_count(), 0);
    }

    #[test]
    fn rule_count() {
        let m = BlockMatcher::from_patterns(&["a.com", "**.b.com", "*.c.com"]);
        assert_eq!(m.rule_count(), 3);
    }

    // ─── Duplicate rules ───────────────────────────────────────

    #[test]
    fn duplicate_rules_not_counted_twice() {
        let mut m = BlockMatcher::default();
        m.add_pattern("example.com");
        m.add_pattern("example.com");
        assert_eq!(m.rule_count(), 1);
    }

    // ─── Edge: bare `*` normalization ──────────────────────────

    #[test]
    fn bare_star_becomes_multi() {
        // Bare `*` (no dots) → `*.**`, should match any domain.
        let m = BlockMatcher::from_patterns(&["*"]);
        assert!(m.is_blocked("anything.com"));
        assert!(m.is_blocked("a.b.c"));
    }

    // ─── Edge: empty domain ────────────────────────────────────

    #[test]
    fn empty_domain_not_blocked() {
        let m = BlockMatcher::from_patterns(&["**.example.com"]);
        assert!(!m.is_blocked(""));
        assert!(!m.is_blocked("."));
    }

    // ─── load_rules_from_reader ────────────────────────────────

    #[test]
    fn load_from_reader_basic() {
        let data = "**.doubleclick.net\n# comment line\n*.jddebug.com\n\n10.ras.yahoo.com\n";
        let mut m = BlockMatcher::default();
        let count = m.load_rules_from_reader(data.as_bytes());
        assert_eq!(count, 3);
        assert!(m.is_blocked("ad.doubleclick.net"));
        assert!(m.is_blocked("foo.jddebug.com"));
        assert!(m.is_blocked("10.ras.yahoo.com"));
    }

    #[test]
    fn load_from_reader_skips_comments_and_blanks() {
        let data = "# full comment\n  \n# another comment\n**.akadns.net\n";
        let mut m = BlockMatcher::default();
        let count = m.load_rules_from_reader(data.as_bytes());
        assert_eq!(count, 1);
        assert!(m.is_blocked("x.akadns.net"));
    }

    #[test]
    fn load_from_reader_mixed_patterns() {
        let data = "**.umeng.**\nclientlog*.**\n*.dlied1.cdntips.net\n10.ras.yahoo.com\n";
        let mut m = BlockMatcher::default();
        let count = m.load_rules_from_reader(data.as_bytes());
        assert_eq!(count, 4);
        assert!(m.is_blocked("abc.umeng.com"));
        assert!(m.is_blocked("clientlog123.test.com"));
        assert!(m.is_blocked("x.dlied1.cdntips.net"));
        assert!(m.is_blocked("10.ras.yahoo.com"));
    }

    // ─── load_rules_from_file ──────────────────────────────────

    #[test]
    fn load_from_file_ok() {
        let dir = std::env::temp_dir().join("border_dns_block_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("blocklist.txt");
        std::fs::write(&path, "# test rules\n**.umeng.**\n*.jddebug.com\n").unwrap();

        let mut m = BlockMatcher::default();
        let count = m.load_rules_from_file(&path).unwrap();
        assert_eq!(count, 2);
        assert!(m.is_blocked("abc.umeng.com"));
        assert!(m.is_blocked("foo.jddebug.com"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_file_not_found() {
        let mut m = BlockMatcher::default();
        let result = m.load_rules_from_file("/nonexistent/path/rules.txt");
        assert!(result.is_err());
    }

    // ─── Testcases file loading ────────────────────────────────

    #[test]
    fn load_from_testcases_file() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testcases");
        let mut m = BlockMatcher::default();
        let count = m.load_rules_from_file(path).unwrap();
        assert!(count > 0);

        // Verify all testcases pattern types work after file load.
        assert!(m.is_blocked("abc.umeng.com"));
        assert!(m.is_blocked("clientlog123.example.com"));
        assert!(m.is_blocked("x.akadns.net"));
        assert!(m.is_blocked("foo.gds.alibabadns.com"));
        assert!(m.is_blocked("foo.jddebug.com"));
        assert!(!m.is_blocked("a.b.jddebug.com"));
        assert!(m.is_blocked("10.ras.yahoo.com"));
        assert!(m.is_blocked("3773406.fls.doubleclick.net"));
    }
}
