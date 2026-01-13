// build.rs
use hashbrown::HashSet;
use reqwest::blocking::Client;
use serde::Deserialize;
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

fn write_fst(path: &PathBuf, mut entries: Vec<String>) -> BuildResult<()> {
    // FST builder requires lexicographic order and no dups.
    entries.sort();
    entries.dedup();

    let w = BufWriter::new(File::create(path)?);
    let mut builder = fst::SetBuilder::new(w)?; // fst::Error now OK

    for s in entries {
        if !s.is_empty() {
            builder.insert(s)?; // fst::Error now OK
        }
    }

    builder.finish()?; // fst::Error now OK
    Ok(())
}

fn main() -> BuildResult<()> {
    let client = Client::new();

    let mut unique_entries = HashSet::<String>::new();
    let mut unique_ads_entries = HashSet::<String>::new();
    let mut unique_tracking_entries = HashSet::<String>::new();
    let mut unique_gambling_entries = HashSet::<String>::new();

    // ----------------------------
    // ShadowWhisperer/BlockLists
    // ----------------------------
    let base_url = "https://api.github.com/repos/ShadowWhisperer/BlockLists/contents/RAW";
    let response = client
        .get(base_url)
        .header("User-Agent", ua_generator::ua::spoof_ua())
        .send()
        .expect("Failed to fetch directory listing");

    let contents: Vec<GithubContent> = response.json().expect("Failed to parse JSON response");

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

        if item.content_type == "file" {
            let file_url = format!(
                "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/{}",
                item.path
            );
            let file_response = client
                .get(&file_url)
                .send()
                .expect("Failed to fetch file content");
            let file_content = file_response.text().expect("Failed to read file content");

            if item.name == "Wild_Tracking" || item.name == "Tracking" {
                for line in file_content.lines() {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_tracking_entries.insert(s.to_string());
                    }
                }
            } else if item.name == "Wild_Ads" || item.name == "Ads" {
                for line in file_content.lines() {
                    let s = line.trim();
                    if !s.is_empty() {
                        unique_ads_entries.insert(s.to_string());
                    }
                }
            } else if item.name == "Gambling" {
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
    let base_url = "https://api.github.com/repos/badmojr/1Hosts/contents/Lite/";
    let response = client
        .get(base_url)
        .header("User-Agent", ua_generator::ua::spoof_ua())
        .send()
        .expect("Failed to fetch directory listing");

    let contents: Vec<GithubContent> = response.json().expect("Failed to parse JSON response");
    let skip_list = vec!["rpz", "domains.wildcards", "wildcards", "unbound.conf"];

    for item in contents {
        if skip_list.contains(&item.name.as_str()) {
            continue;
        }

        if item.content_type == "file" && (item.name == "domains.txt" || item.name == "adblock.txt")
        {
            let file_url = format!(
                "https://raw.githubusercontent.com/badmojr/1Hosts/master/{}",
                item.path
            );
            let file_response = client
                .get(&file_url)
                .send()
                .expect("Failed to fetch file content");
            let file_content = file_response.text().expect("Failed to read file content");

            if item.name == "domains.txt" {
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

    // ----------------------------
    // Apply whitelist to BAD only
    // ----------------------------
    let whitelist: HashSet<&'static str> = WHITE_LIST_AD_DOMAINS.iter().copied().collect();

    let bad_vec: Vec<String> = unique_entries
        .into_iter()
        .filter(|e| !whitelist.contains(e.as_str()))
        .collect();

    let ads_vec: Vec<String> = unique_ads_entries.into_iter().collect();
    let tracking_vec: Vec<String> = unique_tracking_entries.into_iter().collect();
    let gambling_vec: Vec<String> = unique_gambling_entries.into_iter().collect();

    // ----------------------------
    // Write outputs
    // ----------------------------
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    let bad_fst_path = out_dir.join("bad_websites.fst");
    let ads_fst_path = out_dir.join("ads_websites.fst");
    let tracking_fst_path = out_dir.join("tracking_websites.fst");
    let gambling_fst_path = out_dir.join("gambling_websites.fst");

    write_fst(&bad_fst_path, bad_vec)?;
    write_fst(&ads_fst_path, ads_vec)?;
    write_fst(&tracking_fst_path, tracking_vec)?;
    write_fst(&gambling_fst_path, gambling_vec)?;

    // Tiny Rust include file (no giant static strings)
    let dest_rs = out_dir.join("bad_websites.rs");
    fs::write(
        &dest_rs,
        r#"
// Auto-generated by build.rs
pub static BAD_WEBSITES_FST_BYTES: &'static [u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/bad_websites.fst"));
pub static ADS_WEBSITES_FST_BYTES: &'static [u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ads_websites.fst"));
pub static TRACKING_WEBSITES_FST_BYTES: &'static [u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tracking_websites.fst"));
pub static GAMBLING_WEBSITES_FST_BYTES: &'static [u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/gambling_websites.fst"));
"#,
    )?;

    Ok(())
}
