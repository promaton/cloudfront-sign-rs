# AWS CloudFront Sign Utility
Generating signed URLs for CloudFront links is a little more tricky than for S3. It's because signature generation for S3 URLs is handled a bit differently than CloudFront URLs. The Rusoto library is in maintenance mode and not accepting more features. Therefore we created this simple utility library to sign CloudFront URLs in Rust.

## Requirements
OpenSSL need to be installed. 

```
# macOS
$ brew install openssl@1.1

# Arch Linux
$ sudo pacman -S pkg-config openssl

# Debian and Ubuntu
$ sudo apt-get install pkg-config libssl-dev

# Fedora
$ sudo dnf install pkg-config openssl-devel
```


## Examples

Getting signed cookies.
```rs
use std::fs;
use cloudfront_sign::*;
let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
let options = SignedOptions {
    key_pair_id: String::from("SOMEKEYPAIRID"),
    private_key: private_key,
    ..Default::default()
};
let cookies = get_signed_cookie("https://example.com", &options).unwrap();
```

Getting signed URLS.
```rs
use std::fs;
use cloudfront_sign::*;
let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
let options = SignedOptions {
    key_pair_id: String::from("SOMEKEYPAIRID"),
    private_key: private_key,
    ..Default::default()
};
let signed_url = get_signed_url("https://example.com", &options).unwrap();
```