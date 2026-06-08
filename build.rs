// build.rs
use hashbrown::HashSet;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct GithubContent {
    name: String,
    path: String,
    #[serde(rename = "type")]
    content_type: String,
}

/// Category bitmask flags — must stay in sync with lib.rs.
const CAT_BAD: u64 = 1;
const CAT_ADS: u64 = 2;
const CAT_TRACKING: u64 = 4;
const CAT_GAMBLING: u64 = 8;

// local domains to include past ignore. These are valid domains.
static WHITE_LIST_AD_DOMAINS: &[&str] = &[
    "anydesk.com",
    "firstaidbeauty.com",
    "teads.com",
    "appchair.com",
    "ninjacat.io",
    "oceango.net",
    "center.io",
    "bing.com",
    "unity3d.com",
    "adguard.com",
    "bitdefender.com",
    "blogspot.com",
    "bytedance.com",
    "comcast.net",
    "duckdns.org",
    "dyndns.org",
    "fontawesome.com",
    "grammarly.com",
    "onenote.com",
    "opendns.com",
    "surfshark.com",
    "teamviewer.com",
    "tencent.com",
    "tiktok.com",
    "yandex.net",
    "zoho.com",
    "tiktokcdn-us.com",
    "tiktokcdn.com",
    "tiktokv.com",
    "tiktokrow-cdn.com",
    "tiktokv.us",
    "wpengine.com",
    "ning.com",
    "rakuten.com",
    "naver.com",
    "panopto.com",
    "techsmith.com",
    "screencastify.com",
    "magix.com",
    "winzip.com",
    "webroot.com",
    "webrootcloudav.com",
    "webrootdns.net",
    "webrootmobile.com",
    "webrootmultiplatform.com",
    "webrootanywhere.com",
    "amazonpay.com",
    "douyin.com",
    "lemon8-app.com",
    "lemon8-app.us",
    "lemon8cdn.com",
    "strikingly.com",
    "mystrikingly.com",
    "framer.app",
    "framer.ai",
    "framer.website",
    "rt.com",
    "clickz.com",
    "ask.com",
    "sogou.com",
    "movavi.com",
    "bitbucket.io",
    "codesandbox.io",
    "godaddysites.com",
    "ngrok.io",
    "pythonanywhere.com",
    "repl.co",
    "stackblitz.io",
    "charter.net",
    "xe.com",
    "example3.com",
    "interactions.com",
    "nekansascitynews.com",
    "downriversundaytimes.com",
    "control.com",
    "newswithviews.com",
    "weeklyworldnews.com",
    "mmaglobal.com",
    "dickssportinggoods.com",
    "dickies.com",
    "dickblick.com",
    "dicksdrivein.com",
    "dickson-constant.com",
    "dicksonone.com",
    "dickclark.com",
    "salesforce.com",
    "webmd.com",
    "dynatrace.com",
    "newrelic.com",
    "sumologic.com",
    "embassysuites.com",
    "poe.com",
    "sierraspace.com"
];

type BuildResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn fetch_text(client: &Client, url: &str) -> String {
    client
        .get(url)
        .header("User-Agent", ua_generator::ua::spoof_ua())
        .send()
        .unwrap_or_else(|_| panic!("Failed to fetch {}", url))
        .text()
        .unwrap_or_else(|_| panic!("Failed to read {}", url))
}

/// Parse a hosts-format file (e.g. `0.0.0.0 domain` or `127.0.0.1 domain`),
/// skipping comments, localhost aliases, and ip6-* entries.
fn parse_hosts_lines(body: &str, out: &mut HashSet<String>) {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let _ip = match parts.next() {
            Some(v) => v,
            None => continue,
        };
        let domain = match parts.next() {
            Some(v) => v,
            None => continue,
        };
        if matches!(
            domain,
            "localhost" | "0.0.0.0" | "local" | "localhost.localdomain" | "broadcasthost"
        ) || domain.contains("ip6-")
        {
            continue;
        }
        out.insert(domain.to_string());
    }
}

/// Parse a plain-text domain list (one domain per line), skipping comments and
/// empty lines. Handles optional inline comments (e.g. `domain # note`).
fn parse_domain_lines(body: &str, out: &mut HashSet<String>) {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let domain = trimmed.split_whitespace().next().unwrap_or("");
        if !domain.is_empty() {
            out.insert(domain.to_string());
        }
    }
}

/// Like `fetch_text` but NON-FATAL: returns an empty string on failure instead of
/// panicking, emitting a `cargo:warning`. Used for feeds that are rate-limited or
/// revocable (e.g. Spamhaus DROP, ~1 download/day) so a transient fetch failure
/// cannot break the build — the source simply contributes no entries.
fn fetch_text_opt(client: &Client, url: &str) -> String {
    match client
        .get(url)
        .header("User-Agent", ua_generator::ua::spoof_ua())
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.text())
    {
        Ok(body) => body,
        Err(e) => {
            println!(
                "cargo:warning=spider_firewall: failed to fetch {} ({}); continuing with no entries from this source",
                url, e
            );
            String::new()
        }
    }
}

/// Convert an IPv4 CIDR (or a bare IPv4, treated as `/32`) to an inclusive
/// `(start, end)` u32 range. Returns `None` for anything not a valid IPv4 CIDR.
fn cidr_v4_to_range(s: &str) -> Option<(u32, u32)> {
    let (addr_str, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok()?),
        None => (s, 32u8),
    };
    if prefix > 32 {
        return None;
    }
    let addr: std::net::Ipv4Addr = addr_str.parse().ok()?;
    let base = u32::from(addr);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let start = base & mask;
    let end = start | !mask;
    Some((start, end))
}

/// Parse a Spamhaus DROP-style list of IPv4 CIDR ranges (e.g. `1.2.3.0/24 ; SBL123`).
/// Lines beginning with `;` or `#` are comments; inline `;`/whitespace comments are
/// stripped. Appends inclusive `(start, end)` u32 ranges, skipping invalid entries.
fn parse_cidr_v4_lines(body: &str, out: &mut Vec<(u32, u32)>) {
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        let token = trimmed.split([';', ' ', '\t']).next().unwrap_or("").trim();
        if token.is_empty() {
            continue;
        }
        if let Some(range) = cidr_v4_to_range(token) {
            out.push(range);
        }
    }
}

/// Sort and merge overlapping/adjacent `(start, end)` ranges into a minimal,
/// sorted, non-overlapping set (suitable for binary-search lookup at runtime).
fn merge_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        if let Some(last) = merged.last_mut() {
            // Merge when overlapping or directly adjacent (guarding u32 overflow).
            if s <= last.1 || (last.1 != u32::MAX && s <= last.1 + 1) {
                if e > last.1 {
                    last.1 = e;
                }
                continue;
            }
        }
        merged.push((s, e));
    }
    merged
}

fn main() -> BuildResult<()> {
    let client = Client::new();

    // Category flags
    let include_bad = env::var("CARGO_FEATURE_BAD").is_ok();
    let include_ads = env::var("CARGO_FEATURE_ADS").is_ok();
    let include_tracking = env::var("CARGO_FEATURE_TRACKING").is_ok();
    let include_gambling = env::var("CARGO_FEATURE_GAMBLING").is_ok();

    // Tier flags (large implies medium implies small via Cargo feature deps)
    let tier_small = env::var("CARGO_FEATURE_SMALL").is_ok();
    let tier_medium = env::var("CARGO_FEATURE_MEDIUM").is_ok();
    let tier_large = env::var("CARGO_FEATURE_LARGE").is_ok();

    let mut unique_entries = HashSet::<String>::new();
    let mut unique_ads_entries = HashSet::<String>::new();
    let mut unique_tracking_entries = HashSet::<String>::new();
    let mut unique_gambling_entries = HashSet::<String>::new();

    let need_shadow =
        tier_small && (include_bad || include_ads || include_tracking || include_gambling);
    let need_1hosts = tier_small && (include_ads || include_tracking);
    let need_spider = tier_small && include_bad;

    // ============================================================
    //  SMALL tier sources
    // ============================================================

    // ----------------------------
    // ShadowWhisperer/BlockLists
    // ----------------------------
    if need_shadow {
        let base_url = "https://api.github.com/repos/ShadowWhisperer/BlockLists/contents/RAW";
        let response = client
            .get(base_url)
            .header("User-Agent", ua_generator::ua::spoof_ua())
            .send()
            .expect("Failed to fetch directory listing");

        let contents: Vec<GithubContent> =
            response.json().expect("Failed to parse JSON response");

        let skip_list = vec![
            "Cryptocurrency",
            "Dating",
            "Fonts",
            "Microsoft",
            "Marketing",
            "Wild_Tracking",
            "Free",
        ];

        for item in contents {
            if skip_list.contains(&item.name.as_str()) {
                continue;
            }

            if item.content_type != "file" {
                continue;
            }

            let is_tracking = item.name == "Wild_Tracking" || item.name == "Tracking";
            let is_ads = item.name == "Wild_Ads" || item.name == "Ads";
            let is_gambling = item.name == "Gambling";
            let is_bad = !is_tracking && !is_ads && !is_gambling;

            // Skip downloads for disabled categories.
            if (is_tracking && !include_tracking)
                || (is_ads && !include_ads)
                || (is_gambling && !include_gambling)
                || (is_bad && !include_bad)
            {
                continue;
            }

            let file_url = format!(
                "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/{}",
                item.path
            );
            let file_response = client
                .get(&file_url)
                .send()
                .expect("Failed to fetch file content");
            let file_content = file_response.text().expect("Failed to read file content");

            if is_tracking {
                for line in file_content.lines() {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_tracking_entries.insert(s.to_string());
                    }
                }
            } else if is_ads {
                for line in file_content.lines() {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_ads_entries.insert(s.to_string());
                    }
                }
            } else if is_gambling {
                for line in file_content.lines() {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_gambling_entries.insert(s.to_string());
                    }
                }
            } else {
                for line in file_content.lines() {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_entries.insert(s.to_string());
                    }
                }
            }
        }
    }

    // ----------------------------
    // badmojr/1Hosts (Lite)
    // ----------------------------
    if need_1hosts {
        let base_url = "https://api.github.com/repos/badmojr/1Hosts/contents/Lite/";
        let response = client
            .get(base_url)
            .header("User-Agent", ua_generator::ua::spoof_ua())
            .send()
            .expect("Failed to fetch directory listing");

        let contents: Vec<GithubContent> =
            response.json().expect("Failed to parse JSON response");
        let skip_list = vec!["rpz", "domains.wildcards", "wildcards", "unbound.conf"];

        for item in contents {
            if skip_list.contains(&item.name.as_str()) {
                continue;
            }

            let want_domains = item.content_type == "file"
                && item.name == "domains.txt"
                && include_tracking;
            let want_adblock =
                item.content_type == "file" && item.name == "adblock.txt" && include_ads;

            if !want_domains && !want_adblock {
                continue;
            }

            let file_url = format!(
                "https://raw.githubusercontent.com/badmojr/1Hosts/master/{}",
                item.path
            );
            let file_response = client
                .get(&file_url)
                .send()
                .expect("Failed to fetch file content");
            let file_content = file_response.text().expect("Failed to read file content");

            if want_domains {
                for line in file_content.lines().skip(15) {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_tracking_entries.insert(s.to_string());
                    }
                }
            } else {
                for line in file_content.lines().skip(15) {
                    let s = line.trim();
                    if !s.is_empty() {
                        let mut ad_url = s.replacen("||", "", 1);
                        if ad_url.ends_with('^') {
                            ad_url.pop();
                        }
                        if !ad_url.is_empty() {
                            unique_ads_entries.insert(ad_url);
                        }
                    }
                }
            }
        }
    }

    // ----------------------------
    // spider-rs/bad_websites additional file
    // ----------------------------
    if need_spider {
        let additional_url =
            "https://raw.githubusercontent.com/spider-rs/bad_websites/main/websites.txt";
        let response = client
            .get(additional_url)
            .send()
            .expect("Failed to fetch additional file");

        let additional_content = response
            .text()
            .expect("Failed to read additional file content");

        for line in additional_content.lines() {
            let entry = line.trim_matches(|c| c == '"' || c == ',').trim();
            if !entry.is_empty() {
                unique_entries.insert(entry.to_string());
            }
        }
    }

    // ----------------------------
    // Steven Black Unified Hosts
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        );
        parse_hosts_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Malware
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/malware-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Phishing
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/phishing-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Scam
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/scam-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // URLhaus Filter — Malware Domains
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // StevenBlack hosts — Porn/Adult aggregate
    // Hosts-file format; dedups against the base StevenBlack hosts above.
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
        );
        parse_hosts_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // malware-filter — Phishing Domains (OpenPhish/IPThreat upstreams)
    // ----------------------------
    if tier_small && include_bad {
        let body = fetch_text(
            &client,
            "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt",
        );
        parse_hosts_lines(&body, &mut unique_entries);
    }

    // ============================================================
    //  MEDIUM tier sources (threat-intelligence hardening)
    // ============================================================

    // ----------------------------
    // Block List Project — Ransomware
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/ransomware-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Fraud
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/fraud-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Abuse
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/abuse-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Phishing.Database — Active Domains
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Stamparm/maltrail — Suspicious Domains
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/domain.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // phishdestroy/destroylist — Primary Active (DNS-verified, MIT)
    // ----------------------------
    if tier_medium && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/domains.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ============================================================
    //  LARGE tier sources (comprehensive protection)
    // ============================================================

    // ----------------------------
    // Block List Project — Redirect
    // ----------------------------
    if tier_large && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/redirect-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Block List Project — Tracking
    // ----------------------------
    if tier_large && include_tracking {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/tracking-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_tracking_entries);
    }

    // ----------------------------
    // Block List Project — Ads
    // ----------------------------
    if tier_large && include_ads {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/ads-nl.txt",
        );
        parse_domain_lines(&body, &mut unique_ads_entries);
    }

    // ----------------------------
    // HaGeZi Threat Intelligence Feeds — Malware/Phishing/Scam Domains
    // (Replaces the retired stamparm/maltrail aggregated malware/domain.txt.)
    // ----------------------------
    if tier_large && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
        );
        parse_domain_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // abuse.ch URLhaus — Full Hostfile
    // ----------------------------
    if tier_large && include_bad {
        let body = fetch_text(&client, "https://urlhaus.abuse.ch/downloads/hostfile/");
        parse_hosts_lines(&body, &mut unique_entries);
    }

    // ----------------------------
    // Apply whitelist to BAD only
    // ----------------------------
    let whitelist: HashSet<&'static str> = WHITE_LIST_AD_DOMAINS.iter().copied().collect();

    // Check if a domain or any of its parent domains are whitelisted.
    let is_whitelisted = |domain: &str| -> bool {
        if whitelist.contains(domain) {
            return true;
        }
        let mut h = domain;
        while let Some(dot) = h.find('.') {
            h = &h[dot + 1..];
            if !h.contains('.') {
                break;
            }
            if whitelist.contains(h) {
                return true;
            }
        }
        false
    };

    // ----------------------------
    // Merge into a single BTreeMap<String, u64> for the unified FST Map.
    // The value is a bitmask of categories.
    // BTreeMap gives us sorted iteration which fst::MapBuilder requires.
    // ----------------------------
    let mut unified = BTreeMap::<String, u64>::new();

    if include_bad {
        for domain in unique_entries
            .into_iter()
            .filter(|e| !is_whitelisted(e.as_str()))
        {
            *unified.entry(domain).or_insert(0) |= CAT_BAD;
        }
    }

    if include_ads {
        for domain in unique_ads_entries {
            *unified.entry(domain).or_insert(0) |= CAT_ADS;
        }
    }

    if include_tracking {
        for domain in unique_tracking_entries {
            *unified.entry(domain).or_insert(0) |= CAT_TRACKING;
        }
    }

    if include_gambling {
        for domain in unique_gambling_entries {
            *unified.entry(domain).or_insert(0) |= CAT_GAMBLING;
        }
    }

    // ----------------------------
    // Prune subdomains whose parent domain is already in the same categories.
    // e.g. "sub.example.com" with bitmask 1 is redundant if "example.com" has bitmask 1.
    // The lookup functions walk up parent domains, so these are still matched.
    // ----------------------------
    let keys_to_check: Vec<String> = unified.keys().cloned().collect();
    for key in &keys_to_check {
        let child_mask = match unified.get(key) {
            Some(&m) => m,
            None => continue,
        };
        // Walk up parent domains.
        let mut rest = key.as_str();
        while let Some(dot) = rest.find('.') {
            rest = &rest[dot + 1..];
            // Need at least one dot in the parent (i.e., "foo.tld" not just "tld").
            if !rest.contains('.') {
                break;
            }
            if let Some(&parent_mask) = unified.get(rest) {
                // Remove the child if the parent covers all its categories.
                if parent_mask & child_mask == child_mask {
                    unified.remove(key);
                    break;
                }
            }
        }
    }

    // ----------------------------
    // Write unified FST Map
    // ----------------------------
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let fst_path = out_dir.join("firewall.fst");

    let w = BufWriter::new(File::create(&fst_path)?);
    let mut builder = fst::MapBuilder::new(w)?;

    for (key, value) in &unified {
        if !key.is_empty() {
            builder.insert(key, *value)?;
        }
    }

    builder.finish()?;

    // ----------------------------
    // Generate Rust include file
    // ----------------------------
    let dest_rs = out_dir.join("bad_websites.rs");
    fs::write(
        &dest_rs,
        r#"
// Auto-generated by build.rs — unified FST map with category bitmasks.
pub static FIREWALL_FST_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/firewall.fst"));
"#,
    )?;

    // ----------------------------
    // IP blocking (feature = "ip") — known-bad IPv4 ranges.
    //
    // Source: The Spamhaus Project DROP list (https://www.spamhaus.org/drop/).
    // Free for any use including commercial under the DROP terms; attribution is
    // retained in the generated file + README. The feed is rate-limited
    // (~1 download/day) and revocable, so it is fetched NON-FATALLY: a failed or
    // rate-limited fetch yields zero ranges rather than breaking the build.
    // ----------------------------
    let include_ip = env::var("CARGO_FEATURE_IP").is_ok();
    let mut ip_ranges_v4: Vec<(u32, u32)> = Vec::new();
    if include_ip {
        let body = fetch_text_opt(&client, "https://www.spamhaus.org/drop/drop.txt");
        parse_cidr_v4_lines(&body, &mut ip_ranges_v4);
    }
    let ip_ranges_v4 = merge_ranges(ip_ranges_v4);

    let mut ip_rs = String::from(
        "// Auto-generated by build.rs — known-bad IPv4 ranges (inclusive (start, end) u32),\n\
         // sorted and merged for binary-search lookup.\n\
         // Source: The Spamhaus Project DROP list (https://www.spamhaus.org/drop/), used under\n\
         // the Spamhaus DROP terms (free for any use, attribution required).\n\
         // (c) The Spamhaus Project — https://www.spamhaus.org\n\
         pub static BAD_IP_RANGES_V4: &[(u32, u32)] = &[\n",
    );
    for (s, e) in &ip_ranges_v4 {
        ip_rs.push_str(&format!("    ({}, {}),\n", s, e));
    }
    ip_rs.push_str("];\n");
    fs::write(out_dir.join("bad_ips.rs"), ip_rs)?;

    Ok(())
}
