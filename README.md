# AWS CloudFront Sign Utility
Generating signed URLs for CloudFront links is a little more tricky than for S3. It's because signature generation for S3 URLs is handled a bit differently than CloudFront URLs. The Rusoto library is in maintenance mode and not accepting more features. Therefore we created this simple utility library to sign CloudFront URLs in Rust.

## Examples

Getting signed cookies.
```rust
use std::fs;
use std::borrow::Cow;
use cloudfront_sign::*;
let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
let options = SignedOptions {
    key_pair_id: Cow::from("SOMEKEYPAIRID"),
    private_key: Cow::from(private_key),
    ..Default::default()
};
let cookies = get_signed_cookie("https://example.com", &options).unwrap();
```

Getting signed URL.
```rust
use std::fs;
use std::borrow::Cow;
use cloudfront_sign::*;
let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
let options = SignedOptions {
    key_pair_id: Cow::from("SOMEKEYPAIRID"),
    private_key: Cow::from(private_key),
    ..Default::default()
};
let signed_url = get_signed_url("https://example.com", &options).unwrap();
```

Getting signed URL based on pattern matching.
```rust
use std::fs;
use std::borrow::Cow;
use cloudfront_sign::*;
let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
let options = SignedOptions {
    key_pair_id: Cow::from("SOMEKEYPAIRID"),
    private_key: Cow::from(private_key),
    resource: Some(Cow::from("https://*.example.com/test/*")),
    ..Default::default()
};
let signed_url = get_signed_url("https://test.example.com/test/data?a=b", &options).unwrap();
```
