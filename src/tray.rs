#![windows_subsystem = "windows"]
//! net-pin tray: shows where traffic goes, switches the internet network and routing on / off.
//!
//! The tray never touches the network itself (it runs un-elevated): it reads the `status.json` the
//! service writes after every pass, and sends requests to the service over its pipe.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::time::SystemTime;

use net_pin::service::{self, Reply, Request};
use serde::Deserialize;
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{CreateMutexW, GetCurrentProcess, SetProcessWorkingSetSize};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, MB_ICONWARNING, MB_OK, MSG, MessageBoxW, MsgWaitForMultipleObjects, PM_REMOVE, PeekMessageW,
    QS_ALLINPUT, TranslateMessage, WM_QUIT,
};
use windows::core::{HSTRING, w};
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_NAME: &str = "net-pin-tray";

fn status_path() -> PathBuf { net_pin::status_path() }

#[derive(Deserialize, Default)]
struct Status {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    level: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    time: String,
    /// Where general internet goes now (None: Windows decides).
    #[serde(default)]
    internet: Option<String>,
    #[serde(default)]
    networks: Vec<String>,
    #[serde(default)]
    problems: Vec<String>,
}

fn read_status() -> Option<Status> {
    let text = std::fs::read_to_string(status_path()).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

fn status_mtime() -> Option<SystemTime> {
    std::fs::metadata(status_path()).and_then(|m| m.modified()).ok()
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Look {
    Ok,
    Blocked,
    Problem,
    Off,
    Pending,
    Missing,
}

fn look_of(st: Option<&Status>, running: bool) -> Look {
    if !running { return Look::Missing; }
    match st.map(|s| s.level.as_str()) {
        None => Look::Missing,
        Some("ok") => Look::Ok,
        Some("blocked") => Look::Blocked,
        Some("off") => Look::Off,
        Some(_) => Look::Problem,
    }
}

fn pin_icon(look: Look) -> Icon {
    Icon::from_rgba(pin_rgba(look, 32), 32, 32).expect("icon")
}

fn seg_dist(px: f32, py: f32, (ax, ay): (f32, f32), (bx, by): (f32, f32)) -> f32 {
    let (dx, dy) = (bx - ax, by - ay);
    let t = (((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
    ((px - ax - t * dx).powi(2) + (py - ay - t * dy).powi(2)).sqrt()
}

fn in_circle(x: f32, y: f32, (cx, cy, r): (f32, f32, f32)) -> bool { (x - cx).powi(2) + (y - cy).powi(2) <= r * r }

/// A pushpin stuck into a small network (a hub and three linked nodes), colored by state, `n` x `n`
/// RGBA; `Missing` gets a red dot. Geometry is laid out on a 32 px grid and scaled.
fn pin_rgba(look: Look, n: usize) -> Vec<u8> {
    const SS: usize = 4; // supersampling per axis
    let k = 32.0 / n as f32;
    let rgb: [u8; 3] = match look {
        Look::Ok => [20, 184, 166],      // teal-500
        Look::Blocked => [245, 158, 11], // amber-500
        Look::Problem => [239, 68, 68],  // red-500
        Look::Off | Look::Missing => [148, 163, 184], // slate-400
        Look::Pending => [96, 165, 250], // blue-400
    };
    let hub = (11.5f32, 20.5f32, 4.0f32);
    let leaves = [(3.8f32, 28.2f32, 2.8f32), (21.5, 28.0, 2.8), (3.6, 11.2, 2.8)];
    // The pin points from the top right down to the hub: round head, neck, plate across the axis,
    // then a thin needle.
    let head = (24.5f32, 7.5f32, 4.8f32);
    let neck = ((24.5f32, 7.5f32), (19.8f32, 12.2f32), 1.9f32);
    let plate = ((16.4f32, 9.1f32), (22.9f32, 15.6f32), 1.5f32);
    let needle = ((19.6f32, 12.4f32), (14.0f32, 18.0f32), 0.75f32);
    let badge = (26.5f32, 24.5f32, 4.3f32);
    let mut px = vec![0u8; n * n * 4];
    for y in 0..n {
        for x in 0..n {
            let (mut hit, mut red) = (0u32, 0u32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let fx = (x as f32 + (sx as f32 + 0.5) / SS as f32) * k;
                    let fy = (y as f32 + (sy as f32 + 0.5) / SS as f32) * k;
                    if look == Look::Missing && in_circle(fx, fy, badge) { red += 1; continue; }
                    let node = in_circle(fx, fy, hub) || leaves.iter().any(|&l| in_circle(fx, fy, l));
                    let link = leaves.iter().any(|&(lx, ly, _)| seg_dist(fx, fy, (hub.0, hub.1), (lx, ly)) <= 0.95);
                    let pin = in_circle(fx, fy, head) || [neck, plate, needle].iter().any(|&(a, b, r)| seg_dist(fx, fy, a, b) <= r);
                    if node || link || pin { hit += 1; }
                }
            }
            let total = (SS * SS) as u32;
            let i = (y * n + x) * 4;
            let (color, cov) = if red > hit { ([239u8, 68, 68], red + hit) } else { (rgb, hit + red) };
            if cov > 0 {
                px[i..i + 3].copy_from_slice(&color);
                px[i + 3] = (255 * cov.min(total) / total) as u8;
            }
        }
    }
    px
}

/// An .ico with 32-bit BMP entries (BGRA, bottom-up, plus an empty AND mask).
#[cfg(test)]
fn ico_bytes(look: Look, sizes: &[usize]) -> Vec<u8> {
    let images: Vec<Vec<u8>> = sizes
        .iter()
        .map(|&n| {
            let rgba = pin_rgba(look, n);
            let mut b = Vec::new();
            for v in [40u32, n as u32, 2 * n as u32] { b.extend_from_slice(&v.to_le_bytes()); }
            b.extend_from_slice(&1u16.to_le_bytes()); // planes
            b.extend_from_slice(&32u16.to_le_bytes()); // bit count
            b.extend_from_slice(&[0u8; 24]); // compression, size, ppm x/y, colors
            for y in (0..n).rev() {
                for x in 0..n {
                    let i = (y * n + x) * 4;
                    b.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
                }
            }
            b.extend(std::iter::repeat_n(0u8, n.div_ceil(32) * 4 * n)); // AND mask
            b
        })
        .collect();
    let mut out = Vec::new();
    for v in [0u16, 1, sizes.len() as u16] { out.extend_from_slice(&v.to_le_bytes()); }
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (&n, img) in sizes.iter().zip(&images) {
        let d = if n >= 256 { 0 } else { n as u8 };
        out.extend_from_slice(&[d, d, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(img.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += img.len() as u32;
    }
    for img in images { out.extend(img); }
    out
}

fn message(text: &str) {
    unsafe {
        MessageBoxW(None, &HSTRING::from(text), w!("net-pin"), MB_OK | MB_ICONWARNING);
    }
}

fn trim() {
    unsafe {
        let _ = SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX);
    }
}

fn autostart_enabled() -> bool {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(RUN_KEY)
        .and_then(|k| k.get_value::<String, _>(RUN_NAME))
        .is_ok()
}

fn set_autostart(on: bool) -> std::io::Result<()> {
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(RUN_KEY)?;
    if on {
        let exe = std::env::current_exe()?;
        key.set_value(RUN_NAME, &format!("\"{}\"", exe.display()))
    } else {
        match key.delete_value(RUN_NAME) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_owned() } else { s.chars().take(max - 1).collect::<String>() + "\u{2026}" }
}

/// Short local time from the RFC 3339 timestamp ("2026-11-03T21:17:42.83-05:00").
fn short_time(iso: &str) -> &str {
    iso.get(11..16).unwrap_or("")
}

struct Ui {
    tray: TrayIcon,
    status: MenuItem,
    detail: MenuItem,
    internet: Submenu,
    /// "Windows decides" first, then one item per network (`None` = Windows decides).
    choices: Vec<(Option<String>, CheckMenuItem)>,
    enabled: CheckMenuItem,
    apply: MenuItem,
    log: MenuItem,
    autostart: CheckMenuItem,
    quit: MenuItem,
}

/// A request sent to the service, shown (blue) until its reply arrives.
struct Pending {
    text: String,
    reply: Receiver<Result<Reply, String>>,
}

struct State {
    key: Option<(Look, Option<SystemTime>)>,
    pending: Option<Pending>,
}

fn build_ui() -> Ui {
    let status = MenuItem::new("net-pin", false, None);
    let detail = MenuItem::new("", false, None);
    let internet = Submenu::new("Internet", true);
    let enabled = CheckMenuItem::new("Routing on", true, true, None);
    let apply = MenuItem::new("Re-apply now", true, None);
    let log = MenuItem::new("Open log", true, None);
    let autostart = CheckMenuItem::new("Start with Windows", true, autostart_enabled(), None);
    let quit = MenuItem::new("Quit tray", true, None);
    let menu = Menu::new();
    let _ = menu.append_items(&[
        &status,
        &detail,
        &PredefinedMenuItem::separator(),
        &internet,
        &enabled,
        &apply,
        &log,
        &PredefinedMenuItem::separator(),
        &autostart,
        &quit,
    ]);
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(true)
        .with_tooltip("net-pin")
        .with_icon(pin_icon(Look::Missing))
        .build()
        .expect("tray icon");
    let mut ui = Ui { tray, status, detail, internet, choices: Vec::new(), enabled, apply, log, autostart, quit };
    set_choices(&mut ui, &["wifi".into(), "lan".into()]);
    ui
}

/// Rebuilds the Internet submenu for these networks.
fn set_choices(ui: &mut Ui, networks: &[String]) {
    for (_, item) in ui.choices.drain(..) { let _ = ui.internet.remove(&item); }
    let names = std::iter::once(None).chain(networks.iter().cloned().map(Some));
    for n in names {
        let item = CheckMenuItem::new(n.as_deref().unwrap_or("Windows decides"), true, false, None);
        let _ = ui.internet.append(&item);
        ui.choices.push((n, item));
    }
}

fn refresh(ui: &mut Ui, st: &mut State) {
    if let Some(p) = &st.pending {
        match p.reply.try_recv() {
            Ok(Ok(r)) if !r.ok => { st.pending = None; message(&r.message); }
            Ok(Err(e)) => { st.pending = None; message(&e); }
            Ok(Ok(_)) | Err(std::sync::mpsc::TryRecvError::Disconnected) => st.pending = None,
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
    }
    let running = net_pin::svc::running();
    let mtime = status_mtime();
    let status = read_status();
    let look = if st.pending.is_some() { Look::Pending } else { look_of(status.as_ref(), running) };
    if st.key == Some((look, mtime)) { return; }
    st.key = Some((look, mtime));
    let _ = ui.tray.set_icon(Some(pin_icon(look)));
    let (line, extra, tip) = match (&status, look) {
        (_, Look::Pending) => {
            let t = st.pending.as_ref().map_or("", |p| p.text.as_str());
            (t.to_owned(), String::new(), format!("net-pin: {t}"))
        }
        (_, Look::Missing) if !running => (
            "Service not running".to_owned(),
            "Start it: net-pin service start (admin)".to_owned(),
            "net-pin: service not running".to_owned(),
        ),
        (None, _) => ("No status yet".to_owned(), String::new(), "net-pin".to_owned()),
        (Some(s), _) => {
            let extra = match s.problems.len() {
                0 | 1 => format!("Checked {}", short_time(&s.time)),
                n => format!("+{} more problem(s), checked {}", n - 1, short_time(&s.time)),
            };
            (clip(&s.summary, 70), extra, clip(&format!("net-pin: {}", s.summary), 120))
        }
    };
    ui.status.set_text(line);
    ui.detail.set_text(extra);
    let _ = ui.tray.set_tooltip(Some(tip));
    if let Some(s) = &status {
        let have: Vec<String> = ui.choices.iter().filter_map(|(n, _)| n.clone()).collect();
        if !s.networks.is_empty() && have != s.networks { set_choices(ui, &s.networks); }
        ui.enabled.set_checked(s.enabled);
        for (n, item) in &ui.choices {
            let on = match n { None => s.internet.is_none(), Some(n) => s.internet.as_deref().is_some_and(|i| i.eq_ignore_ascii_case(n)) };
            item.set_checked(on);
        }
    }
}

/// Sends `req` on a worker thread (a reconcile can take a few seconds).
fn request(ui: &mut Ui, st: &mut State, req: Request, text: String) {
    if st.pending.is_some() { st.key = None; refresh(ui, st); return; }
    let (tx, rx) = channel();
    std::thread::spawn(move || { let _ = tx.send(service::call(&req).map_err(|e| format!("{e:#}"))); });
    st.pending = Some(Pending { text, reply: rx });
    st.key = None;
    refresh(ui, st);
}

/// Returns false to quit.
fn handle(ui: &mut Ui, st: &mut State, ev: MenuEvent) -> bool {
    let id = ev.id;
    if let Some((n, _)) = ui.choices.iter().find(|(_, item)| item.id() == &id) {
        let n = n.clone();
        let text = format!("Moving internet to {}\u{2026}", n.as_deref().unwrap_or("Windows' choice"));
        st.key = None; // muda toggled the check; the next refresh puts the real state back
        request(ui, st, Request::SetInternet { network: n.unwrap_or_default() }, text);
    } else if id == ui.enabled.id() {
        let on = ui.enabled.is_checked(); // muda already toggled it
        let text = if on { "Turning routing on\u{2026}" } else { "Turning routing off\u{2026}" };
        request(ui, st, Request::SetEnabled { enabled: on }, text.into());
    } else if id == ui.apply.id() {
        request(ui, st, Request::Apply, "Re-applying\u{2026}".into());
    } else if id == ui.log.id() {
        let _ = std::process::Command::new("notepad.exe").arg(net_pin::log_path()).spawn();
    } else if id == ui.autostart.id() {
        let want = ui.autostart.is_checked();
        if let Err(e) = set_autostart(want) {
            message(&format!("Could not change autostart: {e}"));
        }
        ui.autostart.set_checked(autostart_enabled());
    } else if id == ui.quit.id() {
        return false;
    }
    true
}

fn main() {
    unsafe {
        // Held for the life of the process: one tray per session.
        let _mutex = CreateMutexW(None, true, w!("Local\\NetPinTray"));
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return;
        }
    }
    let mut ui = build_ui();
    let mut st = State { key: None, pending: None };
    refresh(&mut ui, &mut st);
    trim();
    let mut ticks = 0u32;
    loop {
        // Pump window messages for the tray; wake every second.
        let r = unsafe { MsgWaitForMultipleObjects(None, false, 1000, QS_ALLINPUT) };
        let mut msg = MSG::default();
        while unsafe { PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE) }.as_bool() {
            if msg.message == WM_QUIT {
                return;
            }
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if !handle(&mut ui, &mut st, ev) {
                return;
            }
        }
        if r == WAIT_TIMEOUT {
            ticks += 1;
            if ticks % 2 == 0 || st.pending.is_some() {
                refresh(&mut ui, &mut st);
            }
            if ticks % 600 == 0 {
                trim();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_status_json() {
        let s: Status = serde_json::from_str(r#"{"level":"ok","summary":"x","internet":"wifi","networks":["wifi","lan"],"problems":["a"],"enabled":true,"extra":1}"#).unwrap();
        assert_eq!((s.internet.as_deref(), s.networks.len(), s.problems.len(), s.enabled), (Some("wifi"), 2, 1, true));
        let d: Status = serde_json::from_str(r#"{"internet":null}"#).unwrap();
        assert_eq!(d.internet, None);
    }

    #[test]
    fn look_from_level() {
        let mk = |l: &str| Status { level: l.into(), ..Default::default() };
        assert_eq!(look_of(Some(&mk("ok")), true), Look::Ok);
        assert_eq!(look_of(Some(&mk("blocked")), true), Look::Blocked);
        assert_eq!(look_of(Some(&mk("off")), true), Look::Off);
        assert_eq!(look_of(Some(&mk("problem")), true), Look::Problem);
        assert_eq!(look_of(Some(&mk("waiting")), true), Look::Problem);
        assert_eq!(look_of(Some(&mk("ok")), false), Look::Missing);
        assert_eq!(look_of(None, true), Look::Missing);
    }

    #[test]
    fn pin_in_a_network() {
        let px = pin_rgba(Look::Ok, 32);
        let alpha = |x: usize, y: usize| px[(y * 32 + x) * 4 + 3];
        assert!(alpha(11, 20) > 200, "hub");
        assert!(alpha(24, 7) > 200, "pin head");
        assert_eq!(alpha(30, 30), 0, "corner is empty");
        assert!(pin_rgba(Look::Missing, 32)[(24 * 32 + 26) * 4] > 200, "red dot when missing");
    }

    /// Regenerates assets/net-pin.ico: `cargo test --release -- --ignored write_app_icon`
    #[test]
    #[ignore]
    fn write_app_icon() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/net-pin.ico");
        std::fs::write(path, ico_bytes(Look::Ok, &[16, 20, 24, 32, 40, 48, 64, 256])).unwrap();
    }

    #[test]
    fn short_time_and_clip() {
        assert_eq!(short_time("2026-11-03T21:17:42.83-05:00"), "21:17");
        assert_eq!(short_time("x"), "");
        assert_eq!(clip("abcdef", 4), "abc\u{2026}");
        assert_eq!(clip("abc", 4), "abc");
    }
}
