//! The service's control pipe `\\.\pipe\net-pin`: one JSON request line, one JSON reply line. SYSTEM and administrators get full access,
//! interactive users read / write (the tray and the `net-pin` command).
use anyhow::{Context, Result};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::FromRawHandle;
use std::sync::Arc;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::*;
use windows::core::{HSTRING, w};

pub const PATH: &str = r"\\.\pipe\net-pin";
const SDDL: windows::core::PCWSTR = w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)");

/// Request body in, reply out (runs on the pipe thread).
pub type Handler = Arc<dyn Fn(Value) -> Value + Send + Sync>;

/// Serves requests forever on its own thread, one at a time.
pub fn serve(handler: Handler) {
    std::thread::spawn(move || loop {
        if let Err(e) = serve_one(&handler) {
            crate::log(format!("pipe: {e:#}"));
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });
}

fn serve_one(handler: &Handler) -> Result<()> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(SDDL, SDDL_REVISION_1, &mut sd, None)?; }
    let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: false.into() };
    let h = unsafe {
        CreateNamedPipeW(&HSTRING::from(PATH), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, Some(&sa))
    };
    unsafe { let _ = LocalFree(Some(HLOCAL(sd.0))); }
    if h.is_invalid() { anyhow::bail!("CreateNamedPipeW failed"); }
    // ERROR_PIPE_CONNECTED (client came first) is fine too.
    if let Err(e) = unsafe { ConnectNamedPipe(h, None) } {
        if e.code().0 as u32 != 0x8007_0217 { unsafe { let _ = CloseHandle(h); } return Err(e.into()); }
    }
    let file = unsafe { std::fs::File::from_raw_handle(h.0) };
    let mut line = String::new();
    BufReader::new(&file).read_line(&mut line)?;
    let reply = match serde_json::from_str::<Value>(&line) {
        Ok(v) => handler(v),
        Err(e) => serde_json::json!({ "ok": false, "message": format!("bad request: {e}") }),
    };
    let mut w = &file;
    writeln!(w, "{reply}")?;
    w.flush()?;
    unsafe { let _ = FlushFileBuffers(HANDLE(h.0)); let _ = DisconnectNamedPipe(h); }
    Ok(())
}

/// Whether the service's pipe is there (the service runs).
pub fn available() -> bool { std::path::Path::new(PATH).exists() }

/// Client side: sends one request to the service and returns its reply.
pub fn call(body: &Value) -> Result<Value> {
    // A service that just started may not have its pipe yet; one that is busy has no free instance.
    let mut tries = 0;
    let f = loop {
        match std::fs::OpenOptions::new().read(true).write(true).open(PATH) {
            Ok(f) => break f,
            Err(_) if tries < 20 => { tries += 1; std::thread::sleep(std::time::Duration::from_millis(250)); }
            Err(e) => return Err(e).context("the net-pin service is not running"),
        }
    };
    let mut w = &f;
    writeln!(w, "{body}")?;
    let mut line = String::new();
    BufReader::new(&f).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}
