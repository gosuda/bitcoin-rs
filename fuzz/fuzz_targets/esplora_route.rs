#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;

fn check_status(status: u16, path: &str, service: &str) {
    let valid = status == 200
        || status == 204
        || (400..=499).contains(&status)
        || status == 500
        || status == 503;
    assert!(
        valid,
        "unexpected HTTP status {status} for path {path:?} in {service}"
    );
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    let (path, query) = s.split_once('?').unwrap_or((s, ""));

    let context = Arc::new(bitcoin_rs_serving::context::Context::new());
    let handler = bitcoin_rs_serving::Handler::new(Arc::clone(&context));

    let rest_get = bitcoin_rs_serving::rest::route(&context, path, query, true);
    check_status(rest_get.status, path, "REST GET");

    let rest_post = bitcoin_rs_serving::rest::route_post(&context, path, b"{}", true);
    check_status(rest_post.status, path, "REST POST");

    let esp_pub = bitcoin_rs_serving::esplora::route(
        &handler,
        bitcoin_rs_serving::esplora::Surface::Public,
        path,
        query,
    );
    check_status(esp_pub.status, path, "Esplora Public");

    let esp_back = bitcoin_rs_serving::esplora::route(
        &handler,
        bitcoin_rs_serving::esplora::Surface::Backend,
        path,
        query,
    );
    check_status(esp_back.status, path, "Esplora Backend");
});
