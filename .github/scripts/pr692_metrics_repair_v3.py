from pathlib import Path


metrics = Path("crates/node/src/metrics.rs")
text = metrics.read_text()
text = text.replace("    static SERVER_TEST_LOCK: Mutex<()> = Mutex::new(());\n", "")
text = text.replace(
    "    // MetricsServer::bind installs a process-global recorder. Serialize only\n"
    "    // these server tests so another test cannot change the recorder between\n"
    "    // the occupied-bind precondition and its assertion. Production is unchanged.\n",
    "    // Metrics server tests share the process-global router with the run-level\n"
    "    // lifecycle regression, so all of them serialize on METRICS_TEST_LOCK.\n",
)
text = text.replace(
    "/// Process-global Prometheus scrape listener bound by [`start_metrics`].",
    "/// Process-global Prometheus scrape listener for one node lifecycle.",
    1,
)
needle = "pub(crate) fn start_metrics(\n"
if needle not in text:
    raise SystemExit("start_metrics marker missing")
text = text.replace(needle, "#[cfg(test)]\n" + needle, 1)
metrics.write_text(text)
