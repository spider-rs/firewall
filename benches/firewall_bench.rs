use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spider_firewall::*;

fn bench_is_bad_website_url(c: &mut Criterion) {
    c.bench_function("is_bad_website_url (hit)", |b| {
        b.iter(|| is_bad_website_url(black_box("wingwahlau.com")))
    });
    c.bench_function("is_bad_website_url (miss)", |b| {
        b.iter(|| is_bad_website_url(black_box("goodwebsite.com")))
    });
    // Deep subdomain miss — exercises the parent walk-up worst case.
    c.bench_function("is_bad_website_url (deep miss)", |b| {
        b.iter(|| is_bad_website_url(black_box("a.b.c.d.goodwebsite.com")))
    });
}

fn bench_is_ad_website_url(c: &mut Criterion) {
    c.bench_function("is_ad_website_url (hit)", |b| {
        b.iter(|| is_ad_website_url(black_box("admob.google.com")))
    });
    c.bench_function("is_ad_website_url (miss)", |b| {
        b.iter(|| is_ad_website_url(black_box("google.com")))
    });
}

fn bench_is_url_bad(c: &mut Criterion) {
    c.bench_function("is_url_bad (hit)", |b| {
        b.iter(|| is_url_bad(black_box("wingwahlau.com")))
    });
    c.bench_function("is_url_bad (miss)", |b| {
        b.iter(|| is_url_bad(black_box("goodwebsite.com")))
    });
}

fn bench_get_host_from_url(c: &mut Criterion) {
    c.bench_function("get_host_from_url", |b| {
        b.iter(|| get_host_from_url(black_box("https://example.com/path/to/page")))
    });
}

criterion_group!(
    benches,
    bench_is_bad_website_url,
    bench_is_ad_website_url,
    bench_is_url_bad,
    bench_get_host_from_url,
);
criterion_main!(benches);
