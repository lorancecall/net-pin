//! Kill-switch firewall rules (Windows Firewall COM, INetFwPolicy2). net-pin's rules are in the
//! group "net-pin". Descriptions are informational only; reconciliation reads actual COM scope.
use crate::model::Rule;
use anyhow::{Context, Result, anyhow};
use windows::Win32::NetworkManagement::WindowsFirewall::*;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx};
use windows::Win32::System::Ole::{SafeArrayCreateVector, SafeArrayPutElement, SafeArrayGetDim, SafeArrayGetLBound, SafeArrayGetUBound, SafeArrayGetElement, SafeArrayGetVartype};
use windows::Win32::System::Variant::{VARIANT, VT_ARRAY, VT_VARIANT, VT_BSTR};
use windows::core::{BSTR, Interface};

pub const GROUP: &str = "net-pin";
const ALIASES: &str = "aliases: ";
const PORTS: &str = "ports: ";

fn policy() -> Result<INetFwPolicy2> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER).map_err(|e| anyhow!("firewall: {e}"))
    }
}

/// net-pin's rules (group "net-pin"). Empty when the firewall cannot be read.
pub fn rules() -> Vec<Rule> {
    let Ok(p) = policy() else { return Vec::new() };
    let mut out = Vec::new();
    unsafe {
        let Ok(rules) = p.Rules() else { return out };
        let Ok(e) = rules._NewEnum() else { return out };
        let Ok(e) = e.cast::<windows::Win32::System::Ole::IEnumVARIANT>() else { return out };
        loop {
            let mut v = [VARIANT::default()];
            let mut got = 0u32;
            if e.Next(&mut v, &mut got).is_err() || got == 0 { break; }
            // The enumerator hands out VT_DISPATCH; IUnknown::try_from only takes VT_UNKNOWN.
            let r = match windows::Win32::System::Com::IDispatch::try_from(&v[0]) {
                Ok(d) => d.cast::<INetFwRule>(),
                Err(_) => windows::core::IUnknown::try_from(&v[0]).and_then(|u| u.cast::<INetFwRule>()),
            };
            let Ok(r) = r else { continue };
            if r.Grouping().map(|g| g.to_string()).unwrap_or_default() != GROUP { continue; }
            out.push(read_rule(&r));
        }
    }
    out
}

fn alias_list(aliases: &[String]) -> Result<VARIANT> {
    unsafe {
        let sa = SafeArrayCreateVector(VT_VARIANT, 0, aliases.len() as u32);
        if sa.is_null() { return Err(anyhow!("SafeArrayCreateVector failed")); }
        for (i, a) in aliases.iter().enumerate() {
            let v = VARIANT::from(BSTR::from(a.as_str()));
            SafeArrayPutElement(sa, &(i as i32), &v as *const VARIANT as *const _)?;
        }
        let mut var = VARIANT::default();
        (*var.Anonymous.Anonymous).vt = windows::Win32::System::Variant::VARENUM(VT_ARRAY.0 | VT_VARIANT.0);
        (*var.Anonymous.Anonymous).Anonymous.parray = sa;
        Ok(var)
    }
}

/// Read only actual firewall properties. Any unreadable or unsupported scope is unverified.
fn read_rule(r: &INetFwRule) -> Rule {
    unsafe {
        let aliases = r.Interfaces().ok().and_then(|v| read_aliases(&v).ok());
        let program = r.ApplicationName();
        let direction = r.Direction();
        let protocol = r.Protocol();
        let remote_addresses = r.RemoteAddresses();
        let (ports, protocol_ok) = match protocol {
            Ok(256) => (None, true), // ANY: port filters do not apply.
            Ok(proto @ (6 | 17)) => match (r.RemotePorts(), r.LocalPorts()) {
                (Ok(remote), Ok(local)) if unrestricted(&local.to_string()) && !remote.is_empty() =>
                    (Some((proto as u8, remote.to_string())), true),
                _ => (None, false),
            },
            _ => (None, false),
        };
        let verified = aliases.is_some() && program.is_ok() && remote_addresses.is_ok() && protocol_ok
            && matches!(direction, Ok(NET_FW_RULE_DIR_IN | NET_FW_RULE_DIR_OUT))
            && r.Action().is_ok_and(|a| a == NET_FW_ACTION_BLOCK)
            && r.Profiles().is_ok_and(|p| p == NET_FW_PROFILE2_ALL.0)
            && r.InterfaceTypes().is_ok_and(|t| t.to_string().eq_ignore_ascii_case("All"))
            && r.LocalAddresses().is_ok_and(|a| unrestricted(&a.to_string()))
            && r.ServiceName().is_ok_and(|s| s.is_empty())
            && unrestricted_security_scope(r);
        Rule {
            name: r.Name().map(|n| n.to_string()).unwrap_or_default(),
            enabled: r.Enabled().map(|b| b.as_bool()).unwrap_or(false),
            program: program.map(|n| n.to_string()).unwrap_or_default(),
            aliases: aliases.unwrap_or_default(), ports,
            remote_addresses: remote_addresses.map(|a| a.to_string()).unwrap_or_default(),
            outbound: direction.is_ok_and(|d| d == NET_FW_RULE_DIR_OUT), verified,
        }
    }
}

// INetFwRule3 can narrow a rule to a package/principal or authenticated traffic.
// Do not retire older protection unless these are the unrestricted defaults.
fn unrestricted_security_scope(rule: &INetFwRule) -> bool {
    let Ok(rule) = rule.cast::<INetFwRule3>() else { return false };
    unsafe {
        rule.LocalAppPackageId().is_ok_and(|v| v.is_empty())
            && rule.LocalUserOwner().is_ok_and(|v| v.is_empty())
            && rule.LocalUserAuthorizedList().is_ok_and(|v| v.is_empty())
            && rule.RemoteUserAuthorizedList().is_ok_and(|v| v.is_empty())
            && rule.RemoteMachineAuthorizedList().is_ok_and(|v| v.is_empty())
            && rule.SecureFlags().is_ok_and(|v| v == 0)
    }
}

fn unrestricted(value: &str) -> bool { value.is_empty() || value == "*" }

/// Windows may return SAFEARRAY(VARIANT) or SAFEARRAY(BSTR). Never infer scope from text.
fn read_aliases(value: &VARIANT) -> Result<Vec<String>> {
    unsafe {
        let inner = &*value.Anonymous.Anonymous;
        let kind = inner.vt.0;
        anyhow::ensure!(kind == (VT_ARRAY.0 | VT_VARIANT.0) || kind == (VT_ARRAY.0 | VT_BSTR.0), "unsupported interface variant");
        let sa = inner.Anonymous.parray;
        anyhow::ensure!(!sa.is_null() && SafeArrayGetDim(sa) == 1, "invalid interface array");
        let element = SafeArrayGetVartype(sa)?;
        anyhow::ensure!(element.0 == (kind & !VT_ARRAY.0), "inconsistent interface array type");
        let lower = SafeArrayGetLBound(sa, 1)?;
        let upper = SafeArrayGetUBound(sa, 1)?;
        anyhow::ensure!(upper >= lower && i64::from(upper) - i64::from(lower) < 65536, "invalid interface count");
        let mut result = Vec::new();
        for index in lower..=upper {
            let name = if element == VT_VARIANT {
                let mut item = VARIANT::default();
                SafeArrayGetElement(sa, &index, &mut item as *mut VARIANT as *mut _)?;
                anyhow::ensure!((*item.Anonymous.Anonymous).vt == VT_BSTR, "non-string interface");
                (*item.Anonymous.Anonymous).Anonymous.bstrVal.to_string()
            } else {
                let mut item = BSTR::new();
                SafeArrayGetElement(sa, &index, &mut item as *mut BSTR as *mut _)?;
                item.to_string()
            };
            anyhow::ensure!(!name.is_empty(), "empty interface alias");
            result.push(name);
        }
        result.sort();
        result.dedup();
        Ok(result)
    }
}

/// Replaces rule `name` with an enabled block rule for `program` (empty: every program) on
/// `aliases`; with `ports`, only that protocol (6 / 17) and those remote ports.
pub fn block(name: &str, program: &str, aliases: &[String], outbound: bool, ports: Option<&(u8, String)>, remote_addresses: &str) -> Result<()> {
    anyhow::ensure!(!aliases.is_empty(), "no interfaces: a rule without interfaces would block everywhere");
    let p = policy()?;
    unsafe {
        let rules = p.Rules()?;
        // Add replaces by identifier; never remove existing protection before Add succeeds.
        let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
        r.SetName(&BSTR::from(name)).context("SetName")?;
        let pdesc = ports.map_or(String::new(), |(proto, list)| format!("{PORTS}{proto}/{list} "));
        r.SetDescription(&BSTR::from(format!("net-pin kill switch. {pdesc}{ALIASES}{}", aliases.join(";")))).context("SetDescription")?;
        r.SetGrouping(&BSTR::from(GROUP)).context("SetGrouping")?;
        if !program.is_empty() { r.SetApplicationName(&BSTR::from(program)).context("SetApplicationName")?; }
        if let Some((proto, list)) = ports {
            r.SetProtocol(*proto as i32).context("SetProtocol")?;
            r.SetRemotePorts(&BSTR::from(list.as_str())).context("SetRemotePorts")?;
        }
        r.SetRemoteAddresses(&BSTR::from(remote_addresses)).context("SetRemoteAddresses")?;
        r.SetDirection(if outbound { NET_FW_RULE_DIR_OUT } else { NET_FW_RULE_DIR_IN }).context("SetDirection")?;
        r.SetAction(NET_FW_ACTION_BLOCK).context("SetAction")?;
        r.SetProfiles(NET_FW_PROFILE2_ALL.0).context("SetProfiles")?;
        r.SetInterfaces(&alias_list(aliases)?).context("SetInterfaces")?;
        r.SetEnabled(true.into()).context("SetEnabled")?;
        rules.Add(&r).with_context(|| format!("add (remote addresses: {remote_addresses})"))?;
    }
    Ok(())
}

pub fn disable(name: &str) -> Result<()> {
    let p = policy()?;
    unsafe { p.Rules()?.Item(&BSTR::from(name))?.SetEnabled(false.into())?; }
    Ok(())
}

/// Removes one rule (a stale one; see `model::plan`).
pub fn remove(name: &str) -> Result<()> {
    let p = policy()?;
    unsafe { p.Rules()?.Remove(&BSTR::from(name))?; }
    Ok(())
}

/// Removes every rule in net-pin's group (undo).
pub fn remove_all() -> Result<usize> {
    let names: Vec<String> = rules().into_iter().map(|r| r.name).collect();
    let p = policy()?;
    unsafe { let rules = p.Rules()?; for n in &names { rules.Remove(&BSTR::from(n.as_str()))?; } }
    Ok(names.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_array_roundtrip_and_invalid_value() {
        let aliases = vec!["Ethernet".into(), "Wi-Fi".into()];
        assert_eq!(read_aliases(&alias_list(&aliases).unwrap()).unwrap(), aliases);
        unsafe {
            let sa = SafeArrayCreateVector(VT_BSTR, 3, 2);
            assert!(!sa.is_null());
            for (index, name) in [(3, "Wi-Fi"), (4, "Ethernet")] {
                let item = BSTR::from(name);
                SafeArrayPutElement(sa, &index, item.as_ptr() as *const _).unwrap();
            }
            let mut array = VARIANT::default();
            (*array.Anonymous.Anonymous).vt = windows::Win32::System::Variant::VARENUM(VT_ARRAY.0 | VT_BSTR.0);
            (*array.Anonymous.Anonymous).Anonymous.parray = sa;
            assert_eq!(read_aliases(&array).unwrap(), aliases);
        }
        assert!(read_aliases(&VARIANT::default()).is_err());
        assert!(read_aliases(&VARIANT::from(BSTR::from("aliases: Ethernet"))).is_err());
    }

    // In-memory COM object only: never added to the firewall and no elevation needed.
    #[test]
    fn actual_properties_override_description() {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            let r: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER).unwrap();
            r.SetName(&BSTR::from("test")).unwrap();
            r.SetDescription(&BSTR::from("ports: 17/123 aliases: Fake")).unwrap();
            r.SetApplicationName(&BSTR::from("C:\\Windows\\System32\\notepad.exe")).unwrap();
            r.SetInterfaces(&alias_list(&["Ethernet".into()]).unwrap()).unwrap();
            r.SetProfiles(NET_FW_PROFILE2_ALL.0).unwrap();
            r.SetProtocol(256).unwrap();
            r.SetDirection(NET_FW_RULE_DIR_OUT).unwrap();
            r.SetAction(NET_FW_ACTION_BLOCK).unwrap();
            r.SetEnabled(true.into()).unwrap();
            let actual = read_rule(&r);
            assert!(actual.verified, "{actual:?}");
            assert_eq!(actual.aliases, ["Ethernet"]);
            assert_eq!(actual.ports, None);
            assert!(actual.outbound);
            let r3 = r.cast::<INetFwRule3>().unwrap();
            r3.SetLocalUserOwner(&BSTR::from("S-1-5-18")).unwrap();
            assert!(!read_rule(&r).verified);
            r3.SetLocalUserOwner(&BSTR::new()).unwrap();
            assert!(read_rule(&r).verified);
            r3.SetLocalAppPackageId(&BSTR::from("S-1-15-2-1")).unwrap();
            assert!(!read_rule(&r).verified);
            r3.SetLocalAppPackageId(&BSTR::new()).unwrap();
            assert!(read_rule(&r).verified);
            r.SetAction(NET_FW_ACTION_ALLOW).unwrap();
            assert!(!read_rule(&r).verified);
            r.SetAction(NET_FW_ACTION_BLOCK).unwrap();
            r.SetProfiles(NET_FW_PROFILE2_PRIVATE.0).unwrap();
            assert!(!read_rule(&r).verified);
            r.SetProfiles(NET_FW_PROFILE2_ALL.0).unwrap();
            r.SetLocalAddresses(&BSTR::from("192.0.2.1")).unwrap();
            assert!(!read_rule(&r).verified);
            r.SetLocalAddresses(&BSTR::from("*")).unwrap();
            r.SetProtocol(17).unwrap();
            r.SetRemotePorts(&BSTR::from("51820")).unwrap();
            let actual = read_rule(&r);
            assert!(actual.verified, "{actual:?}");
            assert_eq!(actual.ports, Some((17, "51820".into())));
            r.SetLocalPorts(&BSTR::from("123")).unwrap();
            assert!(!read_rule(&r).verified);
        }
    }
}
