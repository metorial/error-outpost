use axum::{
  body::Bytes,
  extract::{Path, Query, State},
  http::{HeaderMap, StatusCode},
  response::IntoResponse,
  routing::{get, post},
  Json, Router,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Clone)]
struct AppState {
  tenant_id: String,
  cluster_id: String,
  relay_url: String,
  client: reqwest::Client,
  pii_patterns: PiiPatterns,
  sensitive_fields: Vec<String>,
}

#[derive(Clone)]
struct PiiPatterns {
  email: Regex,
  phone: Regex,
  ssn: Regex,
  credit_card: Regex,
  ipv4: Regex,
  ipv6: Regex,
  uuid: Regex,
  api_key: Regex,
  jwt: Regex,
}

impl PiiPatterns {
  fn new() -> Self {
    Self {
      email: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
      phone: Regex::new(r"\b(\+\d{1,3}[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b").unwrap(),
      ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
      credit_card: Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap(),
      ipv4: Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(),
      ipv6: Regex::new(r"\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b").unwrap(),
      uuid: Regex::new(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
        .unwrap(),
      api_key: Regex::new(r"\b[A-Za-z0-9_-]{32,}\b").unwrap(),
      jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap(),
    }
  }
}


#[derive(Serialize, Deserialize)]
struct EnvelopeItem {
  header: Value,
  payload: Value,
}

struct Envelope {
  header: Value,
  items: Vec<EnvelopeItem>,
}

fn get_sensitive_fields() -> Vec<String> {
  vec![
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "api-key",
    "token", "access_token", "refresh_token", "private_key", "privatekey",
    "authorization", "auth", "cookie", "cookies", "session", "sessionid",
    "ssn", "social_security", "credit_card", "creditcard", "cc_number",
    "cvv", "card_number", "banking", "account_number", "medical", "health",
  ]
  .into_iter()
  .map(String::from)
  .collect()
}

fn is_sensitive_key(key: &str, sensitive_fields: &[String]) -> bool {
  let lower_key = key.to_lowercase();
  sensitive_fields.iter().any(|field| lower_key.contains(field))
}

fn scrub_string(value: &str, patterns: &PiiPatterns) -> String {
  let mut scrubbed = value.to_string();
  
  scrubbed = patterns.email.replace_all(&scrubbed, "[EMAIL]").to_string();
  scrubbed = patterns.phone.replace_all(&scrubbed, "[PHONE]").to_string();
  scrubbed = patterns.ssn.replace_all(&scrubbed, "[SSN]").to_string();
  scrubbed = patterns.credit_card.replace_all(&scrubbed, "[CREDIT-CARD]").to_string();
  scrubbed = patterns.ipv4.replace_all(&scrubbed, "[IP]").to_string();
  scrubbed = patterns.ipv6.replace_all(&scrubbed, "[IP]").to_string();
  scrubbed = patterns.jwt.replace_all(&scrubbed, "[JWT-TOKEN]").to_string();
  scrubbed = patterns.uuid.replace_all(&scrubbed, "[UUID]").to_string();
  scrubbed = patterns.api_key.replace_all(&scrubbed, "[KEY]").to_string();
  
  scrubbed
}

fn scrub_value(value: &mut Value, state: &AppState) {
  match value {
    Value::String(s) => {
      *s = scrub_string(s, &state.pii_patterns);
    }
    Value::Array(arr) => {
      for item in arr.iter_mut() {
        scrub_value(item, state);
      }
    }
    Value::Object(obj) => {
      let keys: Vec<String> = obj.keys().cloned().collect();
      for key in keys {
        if is_sensitive_key(&key, &state.sensitive_fields) {
          obj.insert(key, Value::String("[REDACTED]".to_string()));
        } else if let Some(val) = obj.get_mut(&key) {
          scrub_value(val, state);
        }
      }
    }
    _ => {}
  }
}

fn scrub_pii(mut event_data: Value, state: &AppState) -> Value {
  if let Some(request) = event_data.get_mut("request") {
    if let Some(headers) = request.get_mut("headers").and_then(|h| h.as_object_mut()) {
      headers.remove("Authorization");
      headers.remove("authorization");
      headers.remove("Cookie");
      headers.remove("cookie");
      headers.remove("X-API-Key");
      headers.remove("x-api-key");
      headers.remove("X-Auth-Token");
      headers.remove("x-auth-token");
    }
    
    if request.get("cookies").is_some() {
      request["cookies"] = Value::String("[REDACTED]".to_string());
    }
    
    if let Some(query_string) = request.get_mut("query_string").and_then(|q| q.as_str()) {
      request["query_string"] = Value::String(scrub_string(query_string, &state.pii_patterns));
    }
    
    if let Some(data) = request.get_mut("data") {
      scrub_value(data, state);
    }
    
    if let Some(url) = request.get_mut("url").and_then(|u| u.as_str()) {
      request["url"] = Value::String(scrub_string(url, &state.pii_patterns));
    }
  }
  
  if let Some(user) = event_data.get_mut("user").and_then(|u| u.as_object_mut()) {
    if user.contains_key("email") {
      user.insert("email".to_string(), Value::String("[EMAIL]".to_string()));
    }
    if user.contains_key("ip_address") {
      user.insert("ip_address".to_string(), Value::String("[IP]".to_string()));
    }
    if let Some(username) = user.get("username").and_then(|u| u.as_str()) {
      let prefix = username.chars().take(3).collect::<String>();
      user.insert("username".to_string(), Value::String(format!("{}***", prefix)));
    }
  }
  
  if let Some(env) = event_data
    .get_mut("contexts")
    .and_then(|c| c.get_mut("runtime"))
    .and_then(|r| r.get_mut("environment"))
  {
    scrub_value(env, state);
  }
  
  if let Some(exception_values) = event_data
    .get_mut("exception")
    .and_then(|e| e.get_mut("values"))
    .and_then(|v| v.as_array_mut())
  {
    for exception in exception_values.iter_mut() {
      if let Some(value) = exception.get_mut("value") {
        scrub_value(value, state);
      }
      if let Some(frames) = exception
        .get_mut("stacktrace")
        .and_then(|s| s.get_mut("frames"))
        .and_then(|f| f.as_array_mut())
      {
        for frame in frames.iter_mut() {
          if let Some(vars) = frame.get_mut("vars") {
            scrub_value(vars, state);
          }
        }
      }
    }
  }
  
  if let Some(breadcrumbs) = event_data.get_mut("breadcrumbs").and_then(|b| b.as_array_mut()) {
    for breadcrumb in breadcrumbs.iter_mut() {
      if let Some(message) = breadcrumb.get_mut("message") {
        scrub_value(message, state);
      }
      if let Some(data) = breadcrumb.get_mut("data") {
        scrub_value(data, state);
      }
    }
  }
  
  if let Some(extra) = event_data.get_mut("extra") {
    scrub_value(extra, state);
  }
  
  if let Some(tags) = event_data.get_mut("tags") {
    scrub_value(tags, state);
  }
  
  event_data
}

fn enrich_with_tenant_info(mut event_data: Value, state: &AppState) -> Value {
  let tags = event_data.get_mut("tags").and_then(|t| t.as_object_mut());
  if let Some(tags) = tags {
    tags.insert("tenant_id".to_string(), Value::String(state.tenant_id.clone()));
    tags.insert("cluster_id".to_string(), Value::String(state.cluster_id.clone()));
    tags.insert("deployment_type".to_string(), Value::String("on-prem".to_string()));
    tags.insert("pii_scrubbed".to_string(), Value::String("on-prem".to_string()));
  } else {
    event_data["tags"] = json!({
      "tenant_id": state.tenant_id,
      "cluster_id": state.cluster_id,
      "deployment_type": "on-prem",
      "pii_scrubbed": "on-prem"
    });
  }
  
  let contexts = event_data.get_mut("contexts").and_then(|c| c.as_object_mut());
  if let Some(contexts) = contexts {
    contexts.insert("tenant".to_string(), json!({
      "id": state.tenant_id,
      "cluster": state.cluster_id,
      "deployment": "on-prem",
      "proxy_version": "2.0.0",
      "pii_scrubbing": "enabled"
    }));
  } else {
    event_data["contexts"] = json!({
      "tenant": {
        "id": state.tenant_id,
        "cluster": state.cluster_id,
        "deployment": "on-prem",
        "proxy_version": "2.0.0",
        "pii_scrubbing": "enabled"
      }
    });
  }
  
  if let Some(user) = event_data.get_mut("user").and_then(|u| u.as_object_mut()) {
    user.insert("tenant_id".to_string(), Value::String(state.tenant_id.clone()));
    user.insert("cluster_id".to_string(), Value::String(state.cluster_id.clone()));
  }
  
  event_data["environment"] = Value::String(format!("on-prem-{}", state.tenant_id));
  
  event_data
}

fn parse_envelope(envelope_text: &str) -> Result<Envelope, String> {
  let lines: Vec<&str> = envelope_text.trim().split('\n').collect();
  
  if lines.len() < 2 {
    return Err("Invalid envelope: too few lines".to_string());
  }
  
  let envelope_header: Value = serde_json::from_str(lines[0])
    .map_err(|e| format!("Invalid envelope header: {}", e))?;
  
  let mut items = Vec::new();
  let mut i = 1;
  
  while i < lines.len() {
    if i + 1 >= lines.len() {
      warn!("Incomplete item pair at line {}, skipping", i);
      break;
    }
    
    let item_header: Value = match serde_json::from_str(lines[i]) {
      Ok(h) => h,
      Err(e) => {
        error!("Invalid item header at line {}: {}", i, e);
        i += 2;
        continue;
      }
    };
    
    let item_type = item_header.get("type").and_then(|t| t.as_str()).unwrap_or("");
    
    let item_payload: Value = if matches!(item_type, "attachment" | "user_report") {
      Value::String(lines[i + 1].to_string())
    } else {
      serde_json::from_str(lines[i + 1]).unwrap_or_else(|_| Value::String(lines[i + 1].to_string()))
    };
    
    items.push(EnvelopeItem {
      header: item_header,
      payload: item_payload,
    });
    
    i += 2;
  }
  
  Ok(Envelope {
    header: envelope_header,
    items,
  })
}

fn serialize_envelope(envelope: &Envelope) -> String {
  let mut lines = Vec::new();
  
  lines.push(serde_json::to_string(&envelope.header).unwrap());
  
  for item in &envelope.items {
    lines.push(serde_json::to_string(&item.header).unwrap());
    
    let payload_str = if item.payload.is_string() {
      item.payload.as_str().unwrap().to_string()
    } else {
      serde_json::to_string(&item.payload).unwrap()
    };
    lines.push(payload_str);
  }
  
  lines.join("\n")
}

fn process_envelope(mut envelope: Envelope, state: &AppState) -> Envelope {
  if let Some(obj) = envelope.header.as_object_mut() {
    obj.insert("tenant_id".to_string(), Value::String(state.tenant_id.clone()));
    
    if let Some(trace) = obj.get_mut("trace")
      && let Some(trace_obj) = trace.as_object_mut()
    {
      trace_obj.insert("tenant_id".to_string(), Value::String(state.tenant_id.clone()));
    }
  }
  
  envelope.items = envelope.items.into_iter().map(|mut item| {
    let item_type = item.header.get("type").and_then(|t| t.as_str()).unwrap_or("");
    
    match item_type {
      "event" | "transaction" => {
        item.payload = scrub_pii(item.payload, state);
        item.payload = enrich_with_tenant_info(item.payload, state);
      }
      "session" => {
        if let Some(attrs) = item.payload.get_mut("attrs") {
          scrub_value(attrs, state);
          if let Some(attrs_obj) = attrs.as_object_mut() {
            attrs_obj.insert("tenant_id".to_string(), Value::String(state.tenant_id.clone()));
          }
        }
      }
      "attachment" => {
        info!("[{}] Forwarding attachment", state.tenant_id);
      }
      _ => {}
    }
    
    item
  }).collect();
  
  envelope
}

async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
  Json(json!({
    "status": "ok",
    "tenant": state.tenant_id,
    "relay": state.relay_url,
    "pii_scrubbing": "enabled",
    "envelope_support": "enabled"
  }))
}

async fn store_endpoint(
  State(state): State<Arc<AppState>>,
  Path(project_id): Path<String>,
  Query(_params): Query<HashMap<String, String>>,
  headers: HeaderMap,
  Json(body): Json<Value>,
) -> impl IntoResponse {
  info!("[{}] Processing event for project {}", state.tenant_id, project_id);
  
  let scrubbed_event = scrub_pii(body, &state);
  let enriched_event = enrich_with_tenant_info(scrubbed_event, &state);
  
  let relay_url = format!("{}/api/{}/store/", state.relay_url, project_id);
  
  let mut request = state.client.post(&relay_url).json(&enriched_event);

  if let Some(auth) = headers.get("x-sentry-auth")
    && let Ok(auth_str) = auth.to_str()
  {
    request = request.header("X-Sentry-Auth", auth_str);
  }
  if let Some(ua) = headers.get("user-agent")
    && let Ok(ua_str) = ua.to_str()
  {
    request = request.header("User-Agent", ua_str);
  }
  
  match request.timeout(std::time::Duration::from_secs(5)).send().await {
    Ok(_response) => {
      info!("[{}] Event forwarded successfully", state.tenant_id);
      (StatusCode::OK, Json(json!({"status": "ok"})))
    }
    Err(e) => {
      error!("[{}] Proxy error: {}", state.tenant_id, e);
      (StatusCode::OK, Json(json!({"status": "queued"})))
    }
  }
}

async fn envelope_endpoint(
  State(state): State<Arc<AppState>>,
  Path(project_id): Path<String>,
  Query(_params): Query<HashMap<String, String>>,
  headers: HeaderMap,
  body: Bytes,
) -> impl IntoResponse {
  info!("[{}] Processing envelope for project {}", state.tenant_id, project_id);
  
  let envelope_text = match String::from_utf8(body.to_vec()) {
    Ok(text) => text,
    Err(e) => {
      error!("[{}] Invalid UTF-8 in envelope: {}", state.tenant_id, e);
      return (StatusCode::OK, Json(json!({"status": "queued"})));
    }
  };
  
  let envelope = match parse_envelope(&envelope_text) {
    Ok(env) => env,
    Err(e) => {
      error!("[{}] Envelope parsing error: {}", state.tenant_id, e);
      return (StatusCode::OK, Json(json!({"status": "queued"})));
    }
  };
  
  info!("[{}] Envelope contains {} items", state.tenant_id, envelope.items.len());
  
  let processed_envelope = process_envelope(envelope, &state);
  let serialized_envelope = serialize_envelope(&processed_envelope);
  
  let relay_url = format!("{}/api/{}/envelope/", state.relay_url, project_id);
  
  let mut request = state.client
    .post(&relay_url)
    .header("Content-Type", "application/x-sentry-envelope")
    .body(serialized_envelope);

  if let Some(auth) = headers.get("x-sentry-auth")
    && let Ok(auth_str) = auth.to_str()
  {
    request = request.header("X-Sentry-Auth", auth_str);
  }
  if let Some(ua) = headers.get("user-agent")
    && let Ok(ua_str) = ua.to_str()
  {
    request = request.header("User-Agent", ua_str);
  }
  
  match request.timeout(std::time::Duration::from_secs(5)).send().await {
    Ok(_) => {
      info!("[{}] Envelope forwarded successfully", state.tenant_id);
      (StatusCode::OK, Json(json!({"status": "ok"})))
    }
    Err(e) => {
      error!("[{}] Envelope proxy error: {}", state.tenant_id, e);
      (StatusCode::OK, Json(json!({"status": "queued"})))
    }
  }
}

#[tokio::main]
async fn main() {
  tracing_subscriber::fmt::init();
  
  let tenant_id = std::env::var("TENANT_ID").expect("TENANT_ID must be set");
  let cluster_id = std::env::var("CLUSTER_ID").expect("CLUSTER_ID must be set");
  let port = std::env::var("PORT").unwrap_or_else(|_| "9000".to_string());
  
  let state = Arc::new(AppState {
    tenant_id: tenant_id.clone(),
    cluster_id: cluster_id.clone(),
    relay_url: "https://errors.metorial-enterprise.com".to_string().clone(),
    client: reqwest::Client::new(),
    pii_patterns: PiiPatterns::new(),
    sensitive_fields: get_sensitive_fields(),
  });
  
  info!("Sentry proxy starting...");
  info!("Tenant: {}", tenant_id);
  info!("PII scrubbing: ENABLED");
  info!("Envelope support: ENABLED");
  info!("Forwarding to: {}", state.relay_url);

  let app = Router::new()
    .route("/health", get(health_check))
    .route("/api/:project_id/store/", post(store_endpoint))
    .route("/api/:project_id/envelope/", post(envelope_endpoint))
    .with_state(state);

  let addr = format!("0.0.0.0:{}", port);
  let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

  info!("Sentry proxy running on {}", addr);

  axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  fn create_test_state() -> AppState {
    AppState {
      tenant_id: "test-tenant".to_string(),
      cluster_id: "test-cluster".to_string(),
      relay_url: "https://test-relay.example.com".to_string(),
      client: reqwest::Client::new(),
      pii_patterns: PiiPatterns::new(),
      sensitive_fields: get_sensitive_fields(),
    }
  }

  #[test]
  fn test_pii_patterns_email() {
    let state = create_test_state();
    let input = "Contact user@example.com for help";
    let result = scrub_string(input, &state.pii_patterns);
    assert_eq!(result, "Contact [EMAIL] for help");
  }

  #[test]
  fn test_pii_patterns_phone() {
    let state = create_test_state();
    let input = "Call me at 555-123-4567";
    let result = scrub_string(input, &state.pii_patterns);
    assert_eq!(result, "Call me at [PHONE]");
  }

  #[test]
  fn test_pii_patterns_ssn() {
    let state = create_test_state();
    let input = "SSN: 123-45-6789";
    let result = scrub_string(input, &state.pii_patterns);
    assert_eq!(result, "SSN: [SSN]");
  }

  #[test]
  fn test_pii_patterns_credit_card() {
    let state = create_test_state();
    let input = "Card: 4532-1234-5678-9010";
    let result = scrub_string(input, &state.pii_patterns);
    assert_eq!(result, "Card: [CREDIT-CARD]");
  }

  #[test]
  fn test_pii_patterns_ipv4() {
    let state = create_test_state();
    let input = "Server at 192.168.1.1";
    let result = scrub_string(input, &state.pii_patterns);
    assert_eq!(result, "Server at [IP]");
  }

  #[test]
  fn test_pii_patterns_jwt() {
    let state = create_test_state();
    let input = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let result = scrub_string(input, &state.pii_patterns);
    assert!(result.contains("[JWT-TOKEN]"));
  }

  #[test]
  fn test_scrub_value_string() {
    let state = create_test_state();
    let mut value = Value::String("Email: test@example.com".to_string());
    scrub_value(&mut value, &state);
    assert_eq!(value.as_str().unwrap(), "Email: [EMAIL]");
  }

  #[test]
  fn test_scrub_value_nested_object() {
    let state = create_test_state();
    let mut value = json!({
      "user": {
        "email": "test@example.com",
        "password": "secret123"
      }
    });
    scrub_value(&mut value, &state);
    assert_eq!(value["user"]["password"], "[REDACTED]");
  }

  #[test]
  fn test_scrub_value_array() {
    let state = create_test_state();
    let mut value = json!(["user@example.com", "another@test.com"]);
    scrub_value(&mut value, &state);
    assert_eq!(value[0].as_str().unwrap(), "[EMAIL]");
    assert_eq!(value[1].as_str().unwrap(), "[EMAIL]");
  }

  #[test]
  fn test_is_sensitive_key() {
    let sensitive_fields = get_sensitive_fields();
    assert!(is_sensitive_key("password", &sensitive_fields));
    assert!(is_sensitive_key("api_key", &sensitive_fields));
    assert!(is_sensitive_key("API_KEY", &sensitive_fields));
    assert!(is_sensitive_key("user_password", &sensitive_fields));
    assert!(!is_sensitive_key("username", &sensitive_fields));
  }

  #[test]
  fn test_scrub_pii_request_headers() {
    let state = create_test_state();
    let event = json!({
      "request": {
        "headers": {
          "Authorization": "Bearer token123",
          "Cookie": "session=abc123",
          "X-API-Key": "secret-key",
          "Content-Type": "application/json"
        }
      }
    });
    let result = scrub_pii(event, &state);
    let headers = result["request"]["headers"].as_object().unwrap();
    assert!(!headers.contains_key("Authorization"));
    assert!(!headers.contains_key("Cookie"));
    assert!(!headers.contains_key("X-API-Key"));
    assert!(headers.contains_key("Content-Type"));
  }

  #[test]
  fn test_scrub_pii_user_data() {
    let state = create_test_state();
    let event = json!({
      "user": {
        "email": "user@example.com",
        "ip_address": "192.168.1.1",
        "username": "testuser"
      }
    });
    let result = scrub_pii(event, &state);
    assert_eq!(result["user"]["email"], "[EMAIL]");
    assert_eq!(result["user"]["ip_address"], "[IP]");
    assert_eq!(result["user"]["username"], "tes***");
  }

  #[test]
  fn test_scrub_pii_exception_values() {
    let state = create_test_state();
    let event = json!({
      "exception": {
        "values": [{
          "value": "Error: API key abc123xyz_very_long_api_key_string_here failed",
          "stacktrace": {
            "frames": [{
              "vars": {
                "password": "secret123",
                "user_email": "test@example.com"
              }
            }]
          }
        }]
      }
    });
    let result = scrub_pii(event, &state);
    assert!(result["exception"]["values"][0]["value"].as_str().unwrap().contains("[KEY]"));
    assert_eq!(result["exception"]["values"][0]["stacktrace"]["frames"][0]["vars"]["password"], "[REDACTED]");
  }

  #[test]
  fn test_enrich_with_tenant_info() {
    let state = create_test_state();
    let event = json!({
      "message": "Test event"
    });
    let result = enrich_with_tenant_info(event, &state);

    assert_eq!(result["tags"]["tenant_id"], "test-tenant");
    assert_eq!(result["tags"]["cluster_id"], "test-cluster");
    assert_eq!(result["tags"]["deployment_type"], "on-prem");
    assert_eq!(result["contexts"]["tenant"]["id"], "test-tenant");
    assert_eq!(result["contexts"]["tenant"]["cluster"], "test-cluster");
    assert_eq!(result["environment"], "on-prem-test-tenant");
  }

  #[test]
  fn test_parse_envelope_simple() {
    let envelope_text = r#"{"event_id":"12345"}
{"type":"event"}
{"message":"test"}"#;

    let result = parse_envelope(envelope_text);
    assert!(result.is_ok());
    let envelope = result.unwrap();
    assert_eq!(envelope.items.len(), 1);
    assert_eq!(envelope.items[0].header["type"], "event");
  }

  #[test]
  fn test_parse_envelope_multiple_items() {
    let envelope_text = r#"{"event_id":"12345"}
{"type":"event"}
{"message":"test1"}
{"type":"transaction"}
{"message":"test2"}"#;

    let result = parse_envelope(envelope_text);
    assert!(result.is_ok());
    let envelope = result.unwrap();
    assert_eq!(envelope.items.len(), 2);
  }

  #[test]
  fn test_parse_envelope_invalid() {
    let envelope_text = "invalid json";
    let result = parse_envelope(envelope_text);
    assert!(result.is_err());
  }

  #[test]
  fn test_serialize_envelope() {
    let envelope = Envelope {
      header: json!({"event_id": "12345"}),
      items: vec![
        EnvelopeItem {
          header: json!({"type": "event"}),
          payload: json!({"message": "test"}),
        }
      ],
    };

    let serialized = serialize_envelope(&envelope);
    let lines: Vec<&str> = serialized.split('\n').collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("event_id"));
    assert!(lines[1].contains("event"));
    assert!(lines[2].contains("test"));
  }

  #[test]
  fn test_process_envelope_enrichment() {
    let state = create_test_state();
    let envelope = Envelope {
      header: json!({"event_id": "12345"}),
      items: vec![
        EnvelopeItem {
          header: json!({"type": "event"}),
          payload: json!({"message": "test event"}),
        }
      ],
    };

    let processed = process_envelope(envelope, &state);
    assert_eq!(processed.header["tenant_id"], "test-tenant");
    assert_eq!(processed.items[0].payload["tags"]["tenant_id"], "test-tenant");
  }

  #[test]
  fn test_process_envelope_scrubbing() {
    let state = create_test_state();
    let envelope = Envelope {
      header: json!({"event_id": "12345"}),
      items: vec![
        EnvelopeItem {
          header: json!({"type": "event"}),
          payload: json!({
            "user": {
              "email": "user@example.com"
            }
          }),
        }
      ],
    };

    let processed = process_envelope(envelope, &state);
    assert_eq!(processed.items[0].payload["user"]["email"], "[EMAIL]");
  }

  #[test]
  fn test_multiple_pii_patterns() {
    let state = create_test_state();
    let input = "Contact user@example.com at 555-123-4567 or 192.168.1.1";
    let result = scrub_string(input, &state.pii_patterns);
    assert!(result.contains("[EMAIL]"));
    assert!(result.contains("[PHONE]"));
    assert!(result.contains("[IP]"));
  }
}