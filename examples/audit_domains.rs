//! Audit a TSV of `id<TAB>domain<TAB>state` against the firewall.
//!
//! Answers "which of these domains does the firewall refuse, and under which
//! category" locally, so a large corpus can be checked for false positives
//! without issuing any requests.
//!
//!   cargo run --release --example audit_domains -- domains.tsv

use std::collections::BTreeMap;

fn main() {
    let path = std::env::args().nth(1).expect("usage: audit_domains <file.tsv>");
    let body = std::fs::read_to_string(&path).expect("read input");

    let mut blocked: Vec<(String, String, String, String)> = Vec::new();
    let mut by_category: BTreeMap<&str, usize> = BTreeMap::new();
    let mut total = 0usize;

    for line in body.lines() {
        let mut parts = line.split('\t');
        let (id, domain, state) = match (parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => continue,
        };
        total += 1;

        // is_url_bad is the gate the crawler applies, so it decides whether a page
        // can be fetched at all.
        if !spider_firewall::is_url_bad(domain) {
            continue;
        }

        // Which list caught it changes the remedy: an "ads" or "tracking" hit on a
        // real business is a false positive to allowlist, while a genuine
        // malware hit should stay blocked.
        let category = if spider_firewall::is_bad_website_url(domain) {
            "bad_website"
        } else if spider_firewall::is_ad_website_url(domain) {
            "ads"
        } else if spider_firewall::is_tracking_website_url(domain) {
            "tracking"
        } else if spider_firewall::is_gambling_website_url(domain) {
            "gambling"
        } else if spider_firewall::is_networking_url(domain) {
            "networking"
        } else {
            "other"
        };
        *by_category.entry(category).or_default() += 1;
        blocked.push((id.into(), domain.into(), state.into(), category.into()));
    }

    eprintln!("scanned {total} domains, {} blocked", blocked.len());
    eprintln!("by category:");
    for (cat, n) in &by_category {
        eprintln!("  {cat:<14} {n}");
    }

    println!("id\tdomain\tstate\tcategory");
    for (id, domain, state, category) in &blocked {
        println!("{id}\t{domain}\t{state}\t{category}");
    }
}
