#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

fn v2_notification(request: &Value) -> bool {
    request.is_object()
        && request.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
        && request.get("id").is_none()
}

fn envelope_is_valid(request: &Value) -> bool {
    let Some(method) = request.get("method") else {
        return false;
    };
    if method.as_str().is_none() {
        return false;
    }
    match request.get("params") {
        None => true,
        Some(params) => params.is_null() || params.is_array() || params.is_object(),
    }
}

fn verify_batch_response(requests: &[Value], body: Option<&Value>) {
    if requests.len() > 1_000 || requests.is_empty() {
        return;
    }
    let non_notifications: Vec<_> = requests
        .iter()
        .filter(|request| !v2_notification(request))
        .collect();

    if non_notifications.is_empty() {
        assert!(
            body.is_none(),
            "batch containing only notifications must produce no body"
        );
        return;
    }

    let Some(responses) = body.and_then(|b| b.as_array()) else {
        return;
    };

    assert_eq!(
        responses.len(),
        non_notifications.len(),
        "response count must equal non-notification request count"
    );
    let null_val = Value::new_null();
    for (req, resp) in non_notifications.iter().zip(responses.iter()) {
        let req_id = req.get("id").unwrap_or(&null_val);
        let resp_id = resp.get("id").unwrap_or(&null_val);
        assert_eq!(req_id, resp_id, "request id must be preserved in response");
        assert!(
            resp.get("result").is_some() || resp.get("error").is_some(),
            "response must contain result or error"
        );
    }
}

fn verify_single_response(request: &Value, body: Option<&Value>) {
    if v2_notification(request) {
        if envelope_is_valid(request) {
            assert!(body.is_none(), "notification must produce no response body");
            return;
        }
        assert!(
            body.is_some(),
            "refused notification envelope must be reported"
        );
    }
    let Some(resp) = body else {
        return;
    };
    let null_val = Value::new_null();
    let req_id = request.get("id").unwrap_or(&null_val);
    let resp_id = resp.get("id").unwrap_or(&null_val);
    assert_eq!(
        req_id, resp_id,
        "single request id must be preserved in response"
    );
    assert!(
        resp.get("result").is_some() || resp.get("error").is_some(),
        "single response must contain result or error"
    );
}

fn verify_deep_nesting(handler: &bitcoin_rs_rpc::Handler) {
    let mut deep_array = Vec::with_capacity(20_000);
    for _ in 0..10_000 {
        deep_array.push(b'[');
    }
    for _ in 0..10_000 {
        deep_array.push(b']');
    }
    let deep_resp = bitcoin_rs_rpc::handle_json(handler, &deep_array);
    assert!(
        deep_resp.body.is_some(),
        "depth 10000 array must return error response without panic"
    );

    let mut deep_obj = Vec::with_capacity(30_000);
    for _ in 0..10_000 {
        deep_obj.extend_from_slice(br#"{"a":"#);
    }
    deep_obj.extend_from_slice(b"1");
    for _ in 0..10_000 {
        deep_obj.push(b'}');
    }
    let deep_obj_resp = bitcoin_rs_rpc::handle_json(handler, &deep_obj);
    assert!(
        deep_obj_resp.body.is_some(),
        "depth 10000 object must return error response without panic"
    );
}

fuzz_target!(|data: &[u8]| {
    let context = Arc::new(bitcoin_rs_rpc::context::Context::new());
    let handler = bitcoin_rs_rpc::Handler::new(context);

    let response = bitcoin_rs_rpc::handle_json(&handler, data);

    let Ok(json_str) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(parsed) = sonic_rs::from_str::<Value>(json_str) {
        if let Some(requests) = parsed.as_array() {
            verify_batch_response(requests, response.body.as_ref());
        } else if parsed.is_object() {
            verify_single_response(&parsed, response.body.as_ref());
        }
    }

    if !data.is_empty() && data[0] % 64 == 0 {
        verify_deep_nesting(&handler);
    }
});
