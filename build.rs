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
    // Stamparm/maltrail — Malware Domains
    // ----------------------------
    if tier_large && include_bad {
        let body = fetch_text(
            &client,
            "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/domain.txt",
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

    // ----------------------------
    // Merge into a single BTreeMap<String, u64> for the unified FST Map.
    // The value is a bitmask of categories.
    // BTreeMap gives us sorted iteration which fst::MapBuilder requires.
    // ----------------------------
    let mut unified = BTreeMap::<String, u64>::new();

    if include_bad {
        for domain in unique_entries
            .into_iter()
            .filter(|e| !whitelist.contains(e.as_str()))
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

    Ok(())
}
