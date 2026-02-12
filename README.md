# spider_firewall

A Rust library to shield your system from malicious and unwanted websites by categorizing and blocking them.

## Installation

Add `spider_firewall` to your Cargo project with:

```sh
cargo add spider_firewall
```

## Size Tiers

The `small` tier is enabled by default. Enable `medium` or `large` for broader coverage — each tier includes all sources from the tier(s) below it.

| Tier | FST Size | Focus | Feature Flag |
|------|----------|-------|--------------|
| **small** (default) | ~13 MB | Ads, tracking, malware, phishing, scams | `small` |
| **medium** | ~26 MB | + ransomware, fraud, abuse, threat intel | `medium` |
| **large** | ~52 MB | + redirect/typosquatting, extended ads/tracking, full URLhaus | `large` |

```toml
# Default — small tier, all categories:
spider_firewall = "2.35"

# Medium tier:
spider_firewall = { version = "2.35", features = ["medium"] }

# Large tier:
spider_firewall = { version = "2.35", features = ["large"] }

# Small tier, only bad + ads (no tracking/gambling):
spider_firewall = { version = "2.35", default-features = false, features = ["default-tls", "bad", "ads", "small"] }
```

## Category Features

Categories can be toggled independently (all enabled by default):

| Feature | Description |
|---------|-------------|
| `bad` | Malware, phishing, scams, fraud, ransomware, abuse |
| `ads` | Advertising domains |
| `tracking` | Tracking and analytics domains |
| `gambling` | Gambling domains |

## Usage

### Checking for Bad Websites

You can check if a website is part of the bad websites list using the `is_bad_website_url` function.

```rust
use spider_firewall::is_bad_website_url;

fn main() {
    let u = url::Url::parse("https://badwebsite.com").expect("parse");
    let blocked = is_bad_website_url(u.host_str().unwrap_or_default());
    println!("Is blocked: {}", blocked);
}
```

### Adding a Custom Firewall

You can add your own websites to the block list using the `define_firewall!` macro. This allows you to categorize new websites under a predefined or new category.

```rust
use spider_firewall::is_bad_website_url;

// Add "bad.com" to a custom category.
define_firewall!("unknown", "bad.com");

fn main() {
    let u = url::Url::parse("https://bad.com").expect("parse");
    let blocked = is_bad_website_url(u.host_str().unwrap_or_default());
    println!("Is blocked: {}", blocked);
}
```

### Example with Custom Ads List

You can specify websites to be blocked under specific categories such as "ads".

```rust
use spider_firewall::is_ad_website_url;

// Add "ads.com" to the ads category.
define_firewall!("ads", "ads.com");

fn main() {
    let u = url::Url::parse("https://ads.com").expect("parse");
    let blocked = is_ad_website_url(u.host_str().unwrap_or_default());
    println!("Is blocked: {}", blocked);
}
```

## Blocklist Sources

### Small (default)

| Source | Categories | License |
|--------|-----------|---------|
| [ShadowWhisperer/BlockLists](https://github.com/ShadowWhisperer/BlockLists) | bad, ads, tracking, gambling | MIT |
| [badmojr/1Hosts Lite](https://github.com/badmojr/1Hosts) | ads, tracking | MPL-2.0 |
| [spider-rs/bad_websites](https://github.com/spider-rs/bad_websites) | bad | MIT |
| [Steven Black Unified Hosts](https://github.com/StevenBlack/hosts) | bad | MIT |
| [Block List Project — Malware](https://github.com/blocklistproject/Lists) | bad | MIT |
| [Block List Project — Phishing](https://github.com/blocklistproject/Lists) | bad | MIT |
| [Block List Project — Scam](https://github.com/blocklistproject/Lists) | bad | MIT |
| [URLhaus Filter (domains)](https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt) | bad | CC0/MIT |

### Medium (adds)

| Source | Categories | License |
|--------|-----------|---------|
| [Block List Project — Ransomware](https://github.com/blocklistproject/Lists) | bad | MIT |
| [Block List Project — Fraud](https://github.com/blocklistproject/Lists) | bad | MIT |
| [Block List Project — Abuse](https://github.com/blocklistproject/Lists) | bad | MIT |
| [Phishing.Database — Active Domains](https://github.com/mitchellkrogza/Phishing.Database) | bad | MIT |
| [Stamparm/maltrail — Suspicious](https://github.com/stamparm/maltrail) | bad | MIT |

### Large (adds)

| Source | Categories | License |
|--------|-----------|---------|
| [Block List Project — Redirect](https://github.com/blocklistproject/Lists) | bad | MIT |
| [Block List Project — Tracking](https://github.com/blocklistproject/Lists) | tracking | MIT |
| [Block List Project — Ads](https://github.com/blocklistproject/Lists) | ads | MIT |
| [Stamparm/maltrail — Malware](https://github.com/stamparm/maltrail) | bad | MIT |
| [abuse.ch URLhaus Hostfile](https://urlhaus.abuse.ch/downloads/hostfile/) | bad | CC0 |

## Build Time

The initial build can take longer, approximately 5-10 minutes, as it may involve compiling dependencies and generating necessary data files.

## Contributing

Contributions and improvements are welcome. Feel free to open issues or submit pull requests on the GitHub repository.

## License

This project is licensed under the MIT License.
