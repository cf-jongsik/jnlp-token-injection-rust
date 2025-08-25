use base64::prelude::*;
use hmac::{Hmac, Mac};
use js_sys::Date;
use regex::Regex;
use sha2::Sha256;
use std::collections::HashMap;
use urlencoding::decode;
use worker::*;

const DEFAULT_HMAC_SECRET: &str = "default-secret";
const HTTP_TICKET_REGEX: &str = r#"(<param\s+name="http_ticket"\s+value=")([^"]+)(")"#;

fn is_debug_enabled(env: &Env) -> bool {
    env.var("DEBUG")
        .ok()
        .and_then(|debug| Some(debug.to_string() == "true"))
        .unwrap_or_default()
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let debug_enabled = is_debug_enabled(&env);
    let ip_address = extract_client_ip(&req);
    if debug_enabled {
        console_log!("Client IP: {}", ip_address);
    }

    let cookies = parse_cookies(req.headers().get("cookie")?.unwrap_or_default());
    if debug_enabled {
        console_log!("Cookies: {:#?}", cookies);
    }

    let cf_auth = cookies
        .get("CF_Authorization")
        .ok_or_else(|| worker::Error::from("CF_Authorization not found in cookies"))?;
    if debug_enabled {
        console_log!("CF_Authorization: {}", cf_auth);
    }

    let mut response = Fetch::Request(req).send().await?;

    let body_text = match response.text().await.ok() {
        Some(body) => body,
        None => return create_response("", response.status_code(), response.headers()),
    };
    if debug_enabled {
        console_log!("response body: {:#?}", body_text);
    }

    if !is_jnlp_file(&body_text) {
        console_log!("not a jnlp file");
        return create_response(&body_text, response.status_code(), response.headers());
    }

    let hmac_secret = env
        .secret("HMAC_SECRET")
        .ok()
        .map(|s| s.to_string())
        .unwrap_or_else(|| DEFAULT_HMAC_SECRET.to_string());

    if debug_enabled {
        console_log!("hmac_secret: {}", hmac_secret);
    }

    let hmac_token = generate_simple_token(&ip_address, &hmac_secret);
    if debug_enabled {
        console_log!(
            "hmacToken with clientIP: {} secret: {} = token: {}",
            ip_address,
            hmac_secret,
            hmac_token
        );
    }

    let modified_content = modify_jnlp_content(&body_text, &hmac_token, &cf_auth);
    if debug_enabled {
        console_log!("modified content: {:#?}", modified_content);
    }

    Response::ok(modified_content)
}

fn extract_client_ip(req: &Request) -> String {
    req.headers()
        .get("CF-Connecting-IP")
        .ok()
        .flatten()
        .or_else(|| {
            req.headers()
                .get("X-Forwarded-For")
                .ok()
                .flatten()
                .and_then(|xff| xff.split(',').next().map(|ip| ip.trim().to_string()))
        })
        .unwrap_or_else(|| {
            console_error!("No client IP found in headers, using default");
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

    let code = BASE64_STANDARD.encode(mac.finalize().into_bytes());
    format!("{}-{}", time_now, code)
}

fn parse_cookies(cookie_header: String) -> HashMap<String, String> {
    cookie_header
        .split(';')
        .filter_map(|cookie| {
            cookie
                .split_once('=')
                .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn modify_jnlp_content(jnlp_content: &str, hmac_token: &str, cf_auth: &str) -> String {
    let regex = Regex::new(HTTP_TICKET_REGEX).expect("Invalid regex");
    let clean_cf_auth = decode(cf_auth)
        .unwrap_or_default()
        .replace("\n", "")
        .trim()
        .to_string();
    let modified_content = regex.replace_all(jnlp_content, |caps: &regex::Captures| {
        let prefix = &caps[1];
        let original_value = &caps[2];
        let suffix = &caps[3];

        let new_value = format!("{}++{}++{}", original_value, hmac_token, clean_cf_auth);
        format!("{}{}{}", prefix, new_value, suffix)
    });

    modified_content.to_string()
}
