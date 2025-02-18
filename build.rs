use reqwest::blocking::Client;
use serde::Deserialize;
use hashbrown::HashSet;
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

    // Fetch and process GitHub directory files
    let base_url = "https://api.github.com/repos/ShadowWhisperer/BlockLists/contents/RAW";
    let response = client
        .get(base_url)
        .header("User-Agent", "request")
        .send()
        .expect("Failed to fetch directory listing");

    let contents: Vec<GithubContent> = response.json().expect("Failed to parse JSON response");

    for item in contents {
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
            for line in file_content.lines() {
                if !line.is_empty() {
                    unique_entries.insert(line.to_string());
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

    // Begin building the phf set from the unique entries
    let mut set = phf_codegen::Set::new();

    for entry in unique_entries {
        set.entry(entry);
    }

    // Write to destination
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = PathBuf::from(out_dir).join("bad_websites.rs");

    fs::write(
        &dest_path,
        format!(
            "/// Bad websites that we should not crawl.\n\
            static BAD_WEBSITES: phf::Set<&'static str> = {};",
            set.build()
        ),
    )?;

    Ok(())
}
