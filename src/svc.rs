//! Windows service plumbing for the `net-pin` service (LocalSystem):
//! dispatch, install, uninstall, start / stop. The service only ever runs from
//! `C:\Program Files\net-pin\net-pin.exe` (admin-only folder): `install` refuses any other copy.
use std::ffi::OsString;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use windows_service::service::{
    Service, ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const NAME: &str = "net-pin";
const DESCRIPTION: &str = "net-pin: chooses which network (Wi-Fi, wired LAN, ...) carries general internet, each VPN and chosen destinations; kill switches.";

define_windows_service!(ffi_service_main, service_main);

pub fn dispatch() -> anyhow::Result<()> {
    service_dispatcher::start(NAME, ffi_service_main)?;
    Ok(())
}

fn status(state: ServiceState) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running { ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN } else { ServiceControlAccept::empty() },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(20),
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() { crate::log(format!("service: {e:#}")); }
}

fn run_service() -> anyhow::Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let handle = service_control_handler::register(NAME, move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => { s.store(true, Ordering::SeqCst); ServiceControlHandlerResult::NoError }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(ServiceState::Running))?;
    let r = crate::service::run(&stop);
    handle.set_service_status(status(ServiceState::Stopped))?;
    r
}

fn open(access: ServiceAccess) -> Option<Service> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?.open_service(NAME, access).ok()
}

/// Whether the service is registered (any state).
pub fn exists() -> bool { open(ServiceAccess::QUERY_STATUS).is_some() }

/// Whether the service runs (users may query this).
pub fn running() -> bool {
    open(ServiceAccess::QUERY_STATUS).and_then(|s| s.query_status().ok()).is_some_and(|s| s.current_state == ServiceState::Running)
}

fn wait_for(svc: &Service, want: ServiceState) -> anyhow::Result<()> {
    for _ in 0..150 {
        if svc.query_status()?.current_state == want { return Ok(()); }
        std::thread::sleep(Duration::from_millis(200));
    }
    anyhow::bail!("service did not reach {want:?} within 30 s")
}

/// Registers and starts the service, or restarts it on upgrade (admin; run by the installer).
pub fn install() -> anyhow::Result<()> {
    let me = std::env::current_exe()?;
    let want = crate::paths::install_dir().join("net-pin.exe");
    anyhow::ensure!(me.to_string_lossy().eq_ignore_ascii_case(&want.to_string_lossy()),
        "the service runs only from {} (this is {}); use the installer", want.display(), me.display());
    crate::paths::create_data_dir()?;
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    if let Ok(svc) = mgr.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP) {
        if svc.query_status()?.current_state != ServiceState::Stopped { let _ = svc.stop(); wait_for(&svc, ServiceState::Stopped)?; }
        svc.start::<&str>(&[])?;
        println!("service {NAME} already installed; restarted");
        return Ok(());
    }
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: want,
        launch_arguments: vec!["service".into(), "run".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let svc = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    svc.set_description(DESCRIPTION)?;
    svc.start::<&str>(&[])?;
    println!("service {NAME} installed and started");
    Ok(())
}

/// Stops the service, puts back everything net-pin changed (network and memory), and removes the service (admin; the
/// uninstaller). Also works when the service is already gone.
pub fn uninstall() -> anyhow::Result<()> {
    crate::paths::ensure_may_write_data_dir()?;
    let svc = open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE);
    if let Some(s) = &svc {
        if s.query_status()?.current_state != ServiceState::Stopped { let _ = s.stop(); wait_for(s, ServiceState::Stopped)?; }
    }
    if crate::state_path().exists() || !crate::fw::rules().is_empty() {
        for l in crate::undo()? { println!("{l}"); }
    } else {
        println!("nothing recorded: nothing to put back");
    }
    if crate::ram::daemon::state_path().exists() {
        for l in crate::ram::daemon::restore_all() { println!("{l}"); }
    }
    match svc {
        Some(s) => { s.delete()?; println!("service {NAME} removed"); }
        None => println!("service {NAME} not installed"),
    }
    Ok(())
}

pub fn start() -> anyhow::Result<()> {
    let svc = open(ServiceAccess::QUERY_STATUS | ServiceAccess::START).ok_or_else(|| anyhow::anyhow!("service {NAME} not installed (or not admin)"))?;
    if svc.query_status()?.current_state != ServiceState::Running { svc.start::<&str>(&[])?; wait_for(&svc, ServiceState::Running)?; }
    println!("service {NAME} running");
    Ok(())
}

pub fn stop() -> anyhow::Result<()> {
    let svc = open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP).ok_or_else(|| anyhow::anyhow!("service {NAME} not installed (or not admin)"))?;
    if svc.query_status()?.current_state != ServiceState::Stopped { svc.stop()?; wait_for(&svc, ServiceState::Stopped)?; }
    println!("service {NAME} stopped (the routes, metrics and rules stay as they are)");
    Ok(())
}
