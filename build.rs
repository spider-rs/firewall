use hashbrown::HashSet;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct GithubContent {
    /// The name of the package
    name: String,
    /// The path.
    path: String,
    /// The content type.
    #[serde(rename = "type")]
    content_type: String,
}

fn main() -> std::io::Result<()> {
    let client = Client::new();
    let mut unique_entries = HashSet::new();
    let mut unique_ads_entries = HashSet::new();
    let mut unique_tracking_entries = HashSet::new();
    let mut unique_gambling_entries = HashSet::new();

    // Fetch and process GitHub directory files
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
    ];

    for item in contents {
        // ignore these websites.
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
                    if !line.is_empty() {
                        unique_tracking_entries.insert(line.to_string());
                    }
                }
            } else if item.name == "Wild_Ads" || item.name == "Ads" {
                for line in file_content.lines() {
                    if !line.is_empty() {
                        unique_ads_entries.insert(line.to_string());
                    }
                }
            } else if item.name == "Gambling" {
                for line in file_content.lines() {
                    if !line.is_empty() {
                        unique_gambling_entries.insert(line.to_string());
                    }
                }
            } else {
                for line in file_content.lines() {
                    if !line.is_empty() {
                        unique_entries.insert(line.to_string());
                    }
                }
            }
        }
    }

    // fetch HOST1 content

    // Fetch and process GitHub directory files
    let base_url = "https://api.github.com/repos/badmojr/1Hosts/contents/Lite/";
    let response = client
        .get(base_url)
        .header("User-Agent", ua_generator::ua::spoof_ua())
        .send()
        .expect("Failed to fetch directory listing");

    let contents: Vec<GithubContent> = response.json().expect("Failed to parse JSON response");

    let skip_list = vec!["rpz", "domains.wildcards", "wildcards", "unbound.conf"];

    for item in contents {
        // ignore these websites.
        if skip_list.contains(&item.name.as_str()) {
            continue;
        }
        if item.content_type == "file" {
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
                    if !line.is_empty() {
                        unique_tracking_entries.insert(line.to_string());
                    }
                }
            } else if item.name == "adblock.txt" {
                for line in file_content.lines().skip(15) {
                    if !line.is_empty() {
                        let mut ad_url = line.replacen("||", "", 1);
                        ad_url.pop();

                        unique_ads_entries.insert(ad_url);
                    }
                }
            }
        }
    }

    // Fetch and process the additional text file
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
        let entry = line.trim_matches(|c| c == '"' || c == ',').to_owned();
        if !entry.is_empty() {
            unique_entries.insert(entry);
        }
    }

    let mut set = phf_codegen::Set::new();

    for entry in unique_entries {
        set.entry(entry);
    }

    let mut ads_set = phf_codegen::Set::new();

    for entry in unique_ads_entries {
        ads_set.entry(entry);
    }

    let mut tracking_set = phf_codegen::Set::new();

    for entry in unique_tracking_entries {
        tracking_set.entry(entry);
    }

    let mut gambling_set = phf_codegen::Set::new();

    for entry in unique_gambling_entries {
        gambling_set.entry(entry);
    }

    // Write to destination
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(out_dir).join("bad_websites.rs");

    fs::write(
        &dest_path,
        format!(
            "/// Bad websites that we should not connect to.\n\
            static BAD_WEBSITES: phf::Set<&'static str> = {};\n
            /// Ads websites that we should not connect to.\n\
            static ADS_WEBSITES: phf::Set<&'static str> = {};\n
            /// Tracking websites that we should not connect to.\n\
            static TRACKING_WEBSITES: phf::Set<&'static str> = {};\n
            /// Gambling websites that we should not connect to.\n\
            static GAMBLING_WEBSITES: phf::Set<&'static str> = {};",
            set.build(),
            ads_set.build(),
            tracking_set.build(),
            gambling_set.build()
        ),
    )?;

    Ok(())
}
