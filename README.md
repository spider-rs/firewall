# spider_firewall

A Rust library to shield your system from malicious and unwanted websites by categorizing and blocking them.

## Installation

Add `spider_firewall` to your Cargo project with:

```sh
cargo add spider_firewall
```

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

## Blockers sourced

1. https://github.com/ShadowWhisperer/BlockLists
1. https://github.com/badmojr/1Hosts

## Build Time

The initial build can take longer, approximately 5-10 minutes, as it may involve compiling dependencies and generating necessary data files.

## Contributing

Contributions and improvements are welcome. Feel free to open issues or submit pull requests on the GitHub repository.

## License

This project is licensed under the MIT License.