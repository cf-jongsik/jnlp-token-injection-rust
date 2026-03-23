use base64::prelude::*;
use hmac::{Hmac, Mac};
use js_sys::Date;
use once_cell::sync::OnceCell;
use regex::Regex;
use sha2::Sha256;
use std::collections::HashMap;
use urlencoding::decode;
use worker::*;

const HTTP_TICKET_REGEX: &str = r#"(<param\s+name="http_ticket"\s+value=")([^"]+)(")"#;

const HEADER_CF_CONNECTING_IP: &str = "CF-Connecting-IP";
const HEADER_X_FORWARDED_FOR: &str = "X-Forwarded-IP";
const HEADER_COOKIE: &str = "cookie";

const COOKIE_CF_AUTHORIZATION: &str = "CF_Authorization";

const ENV_DEBUG: &str = "DEBUG";
const SECRET_HMAC_SECRET: &str = "HMAC_SECRET";

static HTTP_TICKET_RE: OnceCell<Regex> = OnceCell::new();

#[derive(Debug)]
enum AppError {
    MissingAuthorization,
    MissingHmacSecret,
    DecodingError(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::MissingAuthorization => write!(f, "CF_Authorization not found in cookies"),
            AppError::MissingHmacSecret => write!(f, "HMAC_SECRET not configured"),
            AppError::DecodingError(e) => write!(f, "Decoding error: {}", e),
        }
    }
}

impl std::error::Error for AppError {}

fn get_http_ticket_regex() -> Result<&'static Regex> {
    HTTP_TICKET_RE.get_or_try_init(|| {
        Regex::new(HTTP_TICKET_REGEX).map_err(|e| {
            console_error!("Failed to compile regex: {}", e);
            Error::from(e.to_string())
        })
    })
}

fn is_debug_enabled(env: &Env) -> bool {
    env.var(ENV_DEBUG)
        .ok()
        .and_then(|debug| Some(debug.to_string() == "true"))
        .unwrap_or_default()
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let debug_enabled = is_debug_enabled(&env);
    let request_id = generate_request_id();

    if debug_enabled {
        console_log!(
            "[{}] Processing request: {} {}",
            request_id,
            req.method(),
            req.url()?
        );
    }

    let ip_address = extract_client_ip(&req);
    if !is_valid_ip(&ip_address) {
        console_warn!(
            "[{}] Invalid IP address detected: {}",
            request_id,
            ip_address
        );
    }
    if debug_enabled {
        console_log!("[{}] Client IP: {}", request_id, ip_address);
    }

    let cookies = parse_cookies(req.headers().get(HEADER_COOKIE)?.unwrap_or_default())
        .map_err(|e| Error::from(format!("Cookie parse error: {}", e)))?;
    if debug_enabled {
        console_log!("[{}] Cookie count: {}", request_id, cookies.len());
    }

    let cf_auth = cookies
        .get(COOKIE_CF_AUTHORIZATION)
        .ok_or_else(|| Error::from(AppError::MissingAuthorization.to_string()))?;
    if debug_enabled {
        let masked = mask_token(cf_auth);
        console_log!("[{}] CF_Authorization: {}", request_id, masked);
    }

    let mut response = Fetch::Request(req).send().await?;

    let body_text = match response.text().await.ok() {
        Some(body) => body,
        None => return create_response("", response.status_code(), response.headers()),
    };
    if debug_enabled {
        console_log!("[{}] Response body length: {}", request_id, body_text.len());
    }

    if !is_jnlp_file(&body_text) {
        if debug_enabled {
            console_log!("[{}] Not a JNLP file", request_id);
        }
        return create_response(&body_text, response.status_code(), response.headers());
    }

    let hmac_secret = env
        .secret(SECRET_HMAC_SECRET)
        .map_err(|_| Error::from(AppError::MissingHmacSecret.to_string()))?
        .to_string();

    let hmac_token = generate_simple_token(&ip_address, &hmac_secret);
    if debug_enabled {
        console_log!(
            "[{}] HMAC token generated for IP: {}",
            request_id,
            ip_address
        );
    }

    let modified_content = modify_jnlp_content(&body_text, &hmac_token, cf_auth)?;
    if debug_enabled {
        console_log!(
            "[{}] Modified content length: {}",
            request_id,
            modified_content.len()
        );
    }

    Response::ok(modified_content)
}

fn generate_request_id() -> String {
    let now = Date::now() as u64;
    let random = js_sys::Math::random() as u64;
    format!("{:x}{:x}", now, random)
}

fn mask_token(token: &str) -> String {
    let len = token.len();
    if len <= 6 {
        "***".to_string()
    } else if len < 10 {
        format!("{}...{}", &token[..2], &token[len - 2..])
    } else {
        format!("{}...{}", &token[..4], &token[len - 4..])
    }
}

fn is_valid_ip(ip: &str) -> bool {
    if ip.is_empty() || ip == "127.0.0.1" {
        return false;
    }
    ip.parse::<std::net::IpAddr>().is_ok()
}

fn extract_client_ip(req: &Request) -> String {
    req.headers()
        .get(HEADER_CF_CONNECTING_IP)
        .ok()
        .flatten()
        .or_else(|| {
            req.headers()
                .get(HEADER_X_FORWARDED_FOR)
                .ok()
                .flatten()
                .and_then(|xff| xff.split(',').next().map(|ip| ip.trim().to_string()))
        })
        .unwrap_or_else(|| {
            console_warn!("No client IP found in headers, using default");
            "127.0.0.1".to_string()
        })
}

fn create_response(body: &str, status: u16, headers: &Headers) -> Result<Response> {
    Ok(Response::ok(body)?
        .with_status(status)
        .with_headers(headers.clone()))
}

fn is_jnlp_file(body: &str) -> bool {
    body.contains("<jnlp") && body.contains("http_ticket")
}

fn generate_simple_token(ip_address: &str, hmac_secret: &str) -> String {
    let time_now = Date::now() / 1000.0;
    let message = format!("{}:{}", ip_address, time_now);

    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(message.as_bytes());

    let code = BASE64_URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{}-{}", time_now, code)
}

fn parse_cookies(cookie_header: String) -> Result<HashMap<String, String>> {
    if cookie_header.is_empty() {
        return Ok(HashMap::new());
    }

    let mut cookies = HashMap::new();
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if cookie.is_empty() {
            continue;
        }
        if let Some((key, value)) = cookie.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();
            if !key.is_empty() {
                cookies.insert(key, value);
            }
        }
    }
    Ok(cookies)
}

fn modify_jnlp_content(jnlp_content: &str, hmac_token: &str, cf_auth: &str) -> Result<String> {
    let regex = get_http_ticket_regex()?;

    let clean_cf_auth = decode(cf_auth)
        .map_err(|e| Error::from(AppError::DecodingError(e.to_string()).to_string()))?
        .replace('\n', "")
        .replace('\r', "")
        .trim()
        .to_string();

    let modified = regex.replace_all(jnlp_content, |caps: &regex::Captures| {
        let prefix = &caps[1];
        let original_value = &caps[2];
        let suffix = &caps[3];

        let new_value = format!("{}++{}++{}", original_value, hmac_token, clean_cf_auth);
        format!("{}{}{}", prefix, new_value, suffix)
    });

    Ok(modified.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cookies_simple() {
        let cookie = "CF_Authorization=token123; other=value".to_string();
        let cookies = parse_cookies(cookie).unwrap();
        assert_eq!(
            cookies.get("CF_Authorization"),
            Some(&"token123".to_string())
        );
    }

    #[test]
    fn test_parse_cookies_empty() {
        let cookies = parse_cookies("".to_string()).unwrap();
        assert!(cookies.is_empty());
    }

    #[test]
    fn test_is_jnlp_file() {
        assert!(is_jnlp_file(
            "<jnlp><param name=\"http_ticket\" value=\"x\" /></jnlp>"
        ));
        assert!(!is_jnlp_file("<html></html>"));
        assert!(!is_jnlp_file("<jnlp></jnlp>"));
    }

    #[test]
    fn test_mask_token() {
        assert_eq!(mask_token("short"), "***");
        assert_eq!(mask_token("abcdefghij"), "abcd...ghij");
        assert_eq!(mask_token("abcdefgh"), "ab...gh");
    }

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("::1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(!is_valid_ip(""));
        assert!(!is_valid_ip("127.0.0.1"));
        assert!(!is_valid_ip("not-an-ip"));
    }

    #[test]
    fn test_modify_jnlp_content() {
        HTTP_TICKET_RE
            .set(Regex::new(HTTP_TICKET_REGEX).unwrap())
            .ok();
        let content = r#"<param name="http_ticket" value="original" />"#;
        let result = modify_jnlp_content(content, "hmac123", "cfauth456").unwrap();
        assert!(result.contains("original++hmac123++cfauth456"));
    }

    #[test]
    #[cfg(target_arch = "wasm32")]
    fn test_generate_simple_token_format() {
        let token = generate_simple_token("192.168.1.1", "secret");
        let parts: Vec<&str> = token.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert!(parts[0].parse::<f64>().is_ok());
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_generate_simple_token_format() {
        // Skip test on non-WASM targets since js_sys::Date is not available
        // The token format is tested via the WASM-specific test above
    }
}
