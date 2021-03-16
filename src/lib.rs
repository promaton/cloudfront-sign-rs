use openssl::{error::ErrorStack, hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
    u64,
};
use thiserror::Error;

/// Possible errors encoding signed CloudFront URLS
#[derive(Error, Debug)]
pub enum EncodingError {
    #[error("invalid key provided")]
    InvalidKeyError(#[from] ErrorStack),
    #[error("unknown error")]
    Unknown,
}

/// Options for getting a signed cookie from CloudFront
pub struct SignedOptions {
    pub key_pair_id: String,            // The access ID from CloudFront.
    pub private_key: String, // The private key for your CloudFront key_pair_id as PEM-encoded PKCS#1.
    pub date_less_than: u64, // The expiration date and time for the URL in Unix time format (in seconds) and Coordinated Universal Time (UTC). Defaults to 1800s from now.
    pub date_greater_than: Option<u64>, // An optional start date and time for the URL in Unix time format (in seconds) and Coordinated Universal Time (UTC).
    pub ip_address: Option<String>, // An optional IP address of the client making the GET request (can be a range).
}

impl Default for SignedOptions {
    fn default() -> SignedOptions {
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        SignedOptions {
            key_pair_id: String::new(),
            private_key: String::new(),
            date_less_than: since_epoch.as_secs() + 1800,
            date_greater_than: None,
            ip_address: None,
        }
    }
}

/// Create a custom policy valid until a unix timestamp (s)
/// https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-setting-signed-cookie-custom-policy.html
fn get_custom_policy(url: &str, options: &SignedOptions) -> String {
    let date_greater_than = options
        .date_greater_than
        .map(|date| format!(",\"DateGreaterThan\":{{\"AWS:EpochTime\":{:?}}}", date))
        .unwrap_or_default();

    let ip_address = options
        .ip_address
        .clone()
        .map(|ip_addres| format!(",\"IpAddress\":{{\"AWS:SourceIp\":{:?}}}", ip_addres))
        .unwrap_or_default();

    format!(
        "{{\"Statement\":[{{\"Resource\":\"{}\",\"Condition\":{{\"DateLessThan\":{{\"AWS:EpochTime\":{:?}}}{}{}}}}}]}}",
        url, options.date_less_than, date_greater_than, ip_address
    )
}

/// Get a CloudFront signed cookie
///
/// # Arguments
///
/// * `url` - A CloudFront URL for which the cookie is generated. Can be a wildcard, e.g. `https://some-cf-url.cloudfront.net/key/*`
///
/// # Examples
/// ```
/// use std::fs;
/// use cloudfront_sign::*;
/// let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
/// let options = SignedOptions {
///     key_pair_id: String::from("SOMEKEYPAIRID"),
///     private_key: private_key,
///     ..Default::default()
/// };
/// let cookies = get_signed_cookie("https://example.com", &options).unwrap();
/// ```
pub fn get_signed_cookie(
    url: &str,
    options: &SignedOptions,
) -> Result<HashMap<String, String>, EncodingError> {
    let mut headers: HashMap<String, String> = HashMap::new();
    let policy = get_custom_policy(url, options);
    let signature = create_policy_signature(&policy, &options.private_key)?;
    let policy_string = openssl::base64::encode_block(policy.as_bytes());

    headers.insert(
        String::from("CloudFront-Policy"),
        normalize_base64(&policy_string).parse().unwrap(),
    );
    headers.insert(
        String::from("CloudFront-Signature"),
        normalize_base64(&signature).parse().unwrap(),
    );
    headers.insert(
        String::from("CloudFront-Key-Pair-Id"),
        normalize_base64(&options.key_pair_id).parse().unwrap(),
    );

    Ok(headers)
}

/// Create signature for a given policy and private key PEM-encoded PKCS#1
fn create_policy_signature(policy: &str, private_key: &str) -> Result<String, EncodingError> {
    let rsa = Rsa::private_key_from_pem(private_key.as_bytes())?;
    let keypair = PKey::from_rsa(rsa)?;
    let mut signer = Signer::new(MessageDigest::sha1(), &keypair)?;
    signer.update(policy.as_bytes())?;
    Ok(openssl::base64::encode_block(&signer.sign_to_vec()?))
}

/// Create a URL safe Base64 encoded string.
/// See: http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-creating-signed-url-canned-policy.html
fn normalize_base64(input: &str) -> String {
    input.replace("+", "-").replace("=", "_").replace("/", "~")
}

/// Get a CloudFront signed URL
///
/// # Arguments
///
/// * `url` - A CloudFront URL for which the URL is generated. Can be a wildcard, e.g. `https://some-cf-url.cloudfront.net/key/*`
///
/// # Examples
/// ```
/// use std::fs;
/// use cloudfront_sign::*;
/// let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
/// let options = SignedOptions {
///     key_pair_id: String::from("SOMEKEYPAIRID"),
///     private_key: private_key,
///     ..Default::default()
/// };
/// let signed_url = get_signed_url("https://example.com", &options).unwrap();
/// ```
pub fn get_signed_url(url: &str, options: &SignedOptions) -> Result<String, EncodingError> {
    let policy = get_custom_policy(url, options);
    let signature = create_policy_signature(&policy, &options.private_key)?;
    let policy_string = openssl::base64::encode_block(policy.as_bytes());
    Ok(format!(
        "{}?Expires={}&Policy={}&Signature={}&Key-Pair-Id={}",
        url,
        options.date_less_than,
        normalize_base64(&policy_string),
        normalize_base64(&signature),
        normalize_base64(&options.key_pair_id)
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    #[should_panic]
    fn test_panic_empty_policy() {
        create_policy_signature("{}", "invalid_key").unwrap();
    }

    #[test]
    fn test_policy_date_less_time() {
        let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
        let date_less_than: u64 = 1;
        let options = SignedOptions {
            key_pair_id: String::from("SOMEKEYPAIRID"),
            private_key: private_key,
            date_less_than,
            ..Default::default()
        };
        let policy = get_custom_policy("https://example.com/test", &options);
        assert_eq!(policy, "{\"Statement\":[{\"Resource\":\"https://example.com/test\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":1}}}]}");
    }

    #[test]
    fn test_policy_date_greater_than() {
        let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
        let date_less_than: u64 = 1;
        let date_greater_than = Some(20);
        let options = SignedOptions {
            key_pair_id: String::from("SOMEKEYPAIRID"),
            private_key: private_key,
            date_less_than,
            date_greater_than,
            ..Default::default()
        };
        let policy = get_custom_policy("https://example.com/test", &options);
        assert_eq!(policy, "{\"Statement\":[{\"Resource\":\"https://example.com/test\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":1},\"DateGreaterThan\":{\"AWS:EpochTime\":20}}}]}");
    }

    #[test]
    fn test_ip_range_policy() {
        let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
        let date_less_than: u64 = 1;
        let ip_address = Some(String::from("192.0.2.0/24"));
        let options = SignedOptions {
            key_pair_id: String::from("SOMEKEYPAIRID"),
            private_key: private_key,
            date_less_than,
            ip_address,
            ..Default::default()
        };
        let policy = get_custom_policy("https://example.com/test", &options);
        assert_eq!(policy, "{\"Statement\":[{\"Resource\":\"https://example.com/test\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":1},\"IpAddress\":{\"AWS:SourceIp\":\"192.0.2.0/24\"}}}]}");
    }

    #[test]
    fn test_create_signed_url() {
        let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
        let date_less_than: u64 = 200;
        let options = SignedOptions {
            key_pair_id: String::from("SOMEKEYPAIRID"),
            private_key: private_key,
            date_less_than,
            ..Default::default()
        };
        let signed_url = get_signed_url("https://example.com", &options).unwrap();
        assert_eq!(signed_url, "https://example.com?Expires=200&Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsIkNvbmRpdGlvbiI6eyJEYXRlTGVzc1RoYW4iOnsiQVdTOkVwb2NoVGltZSI6MjAwfX19XX0=&Signature=Apw4PuuH0C5xnrZn8pU7JJk14JPRaNXLnJwmv6SL6RMC51qP2OxbYZxdDUyGW7+5EJ8hNIHObmaDlW0cUg6wocq1YOoqzMs1hFYTQbmhJc8wsjd/HCgiaI0oryb1oL/hDAQq22Ndl+5ue8OUeZxDJVFE0GAIpji/ubfmr2GV5ybEXQLWKWSh7k0wr5h27jt+QNDmQAlI3unPI5TiL3k9eZ+yl7G9jvzz3T3DsJgOb1TRqzyNx34smafA1En0dvrAAGRGbJVgD8vKDBJNnU8DqNho56w4Li2+pNLZHzfi2wa1gNb8+Dg5rpqBtpO0sf6d4gOD1oQYRRuYHYOBm7T4zw==&Key-Pair-Id=SOMEKEYPAIRID");
    }

    #[test]
    fn test_create_signed_cookie() {
        let private_key = fs::read_to_string("tests/data/private_key.pem").unwrap();
        let date_less_than: u64 = 200;
        let options = SignedOptions {
            key_pair_id: String::from("SOMEKEYPAIRID"),
            private_key: private_key,
            date_less_than,
            ..Default::default()
        };
        let cookies = get_signed_cookie("https://example.com", &options).unwrap();
        assert_eq!(cookies["CloudFront-Policy"], "eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsIkNvbmRpdGlvbiI6eyJEYXRlTGVzc1RoYW4iOnsiQVdTOkVwb2NoVGltZSI6MjAwfX19XX0_");
        assert_eq!(cookies["CloudFront-Signature"], "Apw4PuuH0C5xnrZn8pU7JJk14JPRaNXLnJwmv6SL6RMC51qP2OxbYZxdDUyGW7-5EJ8hNIHObmaDlW0cUg6wocq1YOoqzMs1hFYTQbmhJc8wsjd~HCgiaI0oryb1oL~hDAQq22Ndl-5ue8OUeZxDJVFE0GAIpji~ubfmr2GV5ybEXQLWKWSh7k0wr5h27jt-QNDmQAlI3unPI5TiL3k9eZ-yl7G9jvzz3T3DsJgOb1TRqzyNx34smafA1En0dvrAAGRGbJVgD8vKDBJNnU8DqNho56w4Li2-pNLZHzfi2wa1gNb8-Dg5rpqBtpO0sf6d4gOD1oQYRRuYHYOBm7T4zw__");
        assert_eq!(cookies["CloudFront-Key-Pair-Id"], "SOMEKEYPAIRID");
    }
}
