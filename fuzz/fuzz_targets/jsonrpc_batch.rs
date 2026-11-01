#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

fn verify_batch_response(requests: &[Value], body: Option<&Value>) {
    if requests.len() > 1_000 || requests.is_empty() {
        return;
    }
    let non_notifications: Vec<_> = requests
        .iter()
        .filter(|req| {
            let is_v2 = req.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0");
            !is_v2 || req.get("id").is_some()
        })
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

fn verify_single_response(req_obj: &sonic_rs::Object, body: Option<&Value>) {
    let is_v2 = req_obj.get(&"jsonrpc").and_then(|v| v.as_str()) == Some("2.0");
    if is_v2 && req_obj.get(&"id").is_none() {
        assert!(body.is_none(), "notification must produce no response body");
        return;
    }
    let Some(resp) = body else {
        return;
    };
    let null_val = Value::new_null();
    let req_id = req_obj.get(&"id").unwrap_or(&null_val);
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
        } else if let Some(req_obj) = parsed.as_object() {
            verify_single_response(req_obj, response.body.as_ref());
        }
    }

    if !data.is_empty() && data[0] % 64 == 0 {
        verify_deep_nesting(&handler);
    }
});
