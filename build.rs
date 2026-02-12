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

fn main() -> BuildResult<()> {
    let client = Client::new();

    let include_bad = env::var("CARGO_FEATURE_BAD").is_ok();
    let include_ads = env::var("CARGO_FEATURE_ADS").is_ok();
    let include_tracking = env::var("CARGO_FEATURE_TRACKING").is_ok();
    let include_gambling = env::var("CARGO_FEATURE_GAMBLING").is_ok();

    let mut unique_entries = HashSet::<String>::new();
    let mut unique_ads_entries = HashSet::<String>::new();
    let mut unique_tracking_entries = HashSet::<String>::new();
    let mut unique_gambling_entries = HashSet::<String>::new();

    let need_shadow = include_bad || include_ads || include_tracking || include_gambling;
    let need_1hosts = include_ads || include_tracking;
    let need_spider = include_bad;

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
