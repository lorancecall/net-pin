//! The memory feature on the service's control pipe: a request `{"feature": "ram", "body": ...}`
//! goes to the running daemon loop, which answers with its state. Every other request is net-pin's.
use crate::ram::ondemand::{Reply, Request};
use anyhow::{Context, Result};
use serde_json::Value;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};

pub const FEATURE: &str = "ram";

/// The daemon loop's sender; the service replaces it each time the loop (re)starts.
pub type Slot = Arc<Mutex<Option<Sender<crate::ram::daemon::Msg>>>>;

/// The body of a memory request, or None for a network request (pure; tested).
pub fn body_of(v: &Value) -> Option<Value> {
    (v.get("feature").and_then(Value::as_str) == Some(FEATURE)).then(|| v.get("body").cloned().unwrap_or(Value::Null))
}

fn answer(slot: &Slot, body: Value) -> Result<Reply> {
    let req: Request = serde_json::from_value(body).context("bad request")?;
    let tx = slot.lock().unwrap().clone()
        .context("the memory feature is not running: off (`net-pin feature memory on`), or waiting (see net-pin.log)")?;
    let (rtx, rrx) = channel();
    tx.send(crate::ram::daemon::Msg::Req(req, rtx)).ok().context("the memory feature is not running")?;
    rrx.recv().context("no reply")
}

/// The reply to one memory request.
pub fn handle(slot: &Slot, body: Value) -> Value {
    let r = answer(slot, body).unwrap_or_else(|e| Reply { ok: false, message: format!("{e:#}"), state: Default::default(), failed: vec![] });
    serde_json::to_value(r).unwrap_or(Value::Null)
}

/// Serves the pipe with only this feature (`net-pin ram daemon`, run without the service).
pub fn serve(tx: Sender<crate::ram::daemon::Msg>) {
    let slot: Slot = Arc::new(Mutex::new(Some(tx)));
    crate::pipe::serve(Arc::new(move |v: Value| match body_of(&v) {
        Some(b) => handle(&slot, b),
        None => serde_json::json!({ "ok": false, "message": "only the memory feature runs here (net-pin ram daemon)" }),
    }));
}

fn request(req: &Request) -> Result<Value> {
    Ok(serde_json::json!({ "feature": FEATURE, "body": serde_json::to_value(req)? }))
}

/// Client side: sends one request to the service.
pub fn call(req: &Request) -> Result<Reply> {
    Ok(serde_json::from_value(crate::pipe::call(&request(req)?)?)?)
}

/// `call` that waits up to `wait` for a busy service (each new family takes the service a scan).
pub fn call_wait(req: &Request, wait: std::time::Duration) -> Result<Reply> {
    Ok(serde_json::from_value(crate::pipe::call_wait(&request(req)?, wait)?)?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn memory_requests_are_told_apart() {
        let v = serde_json::json!({ "feature": "ram", "body": { "cmd": "status" } });
        assert_eq!(super::body_of(&v).unwrap()["cmd"], "status");
        assert!(super::body_of(&serde_json::json!({ "cmd": "status" })).is_none());
    }
}
