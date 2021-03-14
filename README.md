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
