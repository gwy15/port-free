use serde::Serialize;
use std::{
    collections::HashMap,
    ffi::c_void,
    mem::{offset_of, size_of},
    net::{Ipv4Addr, Ipv6Addr},
    ptr,
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    NetworkManagement::IpHelper::*,
    Networking::WinSock::{AF_INET, AF_INET6},
    System::Threading::{
        GetProcessTimes, IsProcessCritical, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
        WaitForSingleObject,
    },
};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub protocol: String,
    pub family: String,
    pub local_address: String,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
    pub executable_path: Option<String>,
    // FILETIME must remain a string: JavaScript numbers cannot represent it exactly.
    pub started_at: Option<String>,
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortSnapshot {
    pub port: u16,
    pub endpoints: Vec<Endpoint>,
    pub scanned_at: u64,
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one successful OpenProcess handle.
        unsafe { CloseHandle(self.0) };
    }
}

#[derive(Clone)]
pub(crate) struct ProcessInfo {
    pub name: String,
    pub path: Option<String>,
    pub started_at: Option<String>,
    pub blocked_reason: Option<String>,
}

fn win_error(action: &str) -> String {
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
        format!("{action}：权限不足，请关闭应用后右键选择「以管理员身份运行」。")
    } else {
        format!("{action}：{error}")
    }
}

fn open_process(pid: u32, access: u32) -> Result<ProcessHandle, String> {
    // SAFETY: only documented flags are passed; ownership is transferred to the wrapper.
    let handle = unsafe { OpenProcess(access, 0, pid) };
    if handle.is_null() {
        return Err(win_error("无法访问进程（它可能已退出）"));
    }
    Ok(ProcessHandle(handle))
}

fn creation_time(handle: &ProcessHandle) -> Result<String, String> {
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all output pointers refer to live FILETIME values.
    if unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) } == 0
    {
        return Err(win_error("无法核验进程启动时间"));
    }
    Ok(((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)).to_string())
}

fn critical_process(handle: &ProcessHandle) -> Result<bool, String> {
    let mut critical = 0;
    // SAFETY: handle has query rights and the output pointer is valid.
    if unsafe { IsProcessCritical(handle.0, &mut critical) } == 0 {
        return Err(win_error("无法核验系统关键进程"));
    }
    Ok(critical != 0)
}

pub(crate) fn process_info(pid: u32) -> ProcessInfo {
    let mut info = ProcessInfo {
        name: match pid {
            0 => "内核连接".into(),
            4 => "System".into(),
            _ => format!("进程 {pid}"),
        },
        path: None,
        started_at: None,
        blocked_reason: None,
    };
    if pid == 0 || pid == 4 {
        info.blocked_reason = Some("系统连接不能通过结束进程释放。".into());
        return info;
    }
    let handle = match open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(handle) => handle,
        Err(error) => {
            info.blocked_reason = Some(error);
            return info;
        }
    };
    let mut path = vec![0u16; 32768];
    let mut length = path.len() as u32;
    // SAFETY: the writable UTF-16 buffer has the advertised capacity.
    if unsafe { QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut length) } != 0 {
        let path = String::from_utf16_lossy(&path[..length as usize]);
        info.name = path.rsplit('\\').next().unwrap_or(&path).to_string();
        info.path = Some(path);
    }
    match creation_time(&handle) {
        Ok(time) => info.started_at = Some(time),
        Err(error) => info.blocked_reason = Some(error),
    }
    match critical_process(&handle) {
        Ok(true) => info.blocked_reason = Some("Windows 关键进程，不能强制结束。".into()),
        Err(error) => info.blocked_reason = Some(error),
        Ok(false) => {}
    }
    if pid == std::process::id() {
        info.blocked_reason = Some("不能结束 port-free 自身。".into());
    }
    info
}

/// Read a variable-length IP Helper table with aligned storage and bounded retries.
/// SAFETY: T and offset must match the API's table. T must be a plain Win32 row
/// with no references or invalid bit patterns.
unsafe fn read_table<T: Copy>(
    offset: usize,
    mut call: impl FnMut(*mut c_void, *mut u32) -> u32,
) -> Result<Vec<T>, String> {
    let mut bytes = 0u32;
    let status = call(ptr::null_mut(), &mut bytes);
    if status != 0 && status != ERROR_INSUFFICIENT_BUFFER {
        return Err(format!("读取端口表失败（Windows 错误 {status}）。"));
    }
    for _ in 0..8 {
        let mut storage = vec![0u64; (bytes as usize).max(8).div_ceil(8)];
        let capacity = storage.len() * size_of::<u64>();
        bytes = capacity as u32;
        let status = call(storage.as_mut_ptr().cast(), &mut bytes);
        if status == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if status != 0 {
            return Err(format!("读取端口表失败（Windows 错误 {status}）。"));
        }
        if bytes as usize > capacity || (bytes as usize) < size_of::<u32>() {
            return Err("Windows 返回的端口表长度无效。".into());
        }
        let base = storage.as_ptr().cast::<u8>();
        // SAFETY: storage contains at least four initialized bytes.
        let count = unsafe { ptr::read_unaligned(base.cast::<u32>()) } as usize;
        let end = count
            .checked_mul(size_of::<T>())
            .and_then(|n| offset.checked_add(n));
        if end.is_none_or(|end| end > bytes as usize) {
            return Err("Windows 返回的端口表条目越界。".into());
        }
        return Ok((0..count)
            .map(|index| {
                // SAFETY: caller guarantees row layout; the range was checked above.
                unsafe {
                    ptr::read_unaligned(base.add(offset + index * size_of::<T>()).cast::<T>())
                }
            })
            .collect());
    }
    Err("端口连接变化过快，请重新检测。".into())
}

fn port_number(value: u32) -> u16 {
    u16::from_be(value as u16)
}

fn tcp_state(state: u32) -> String {
    match state {
        1 => "CLOSED",
        2 => "LISTENING",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT_1",
        7 => "FIN_WAIT_2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
    .into()
}

fn ipv6_endpoint(bytes: [u8; 16], scope: u32, port: u16) -> String {
    let ip = Ipv6Addr::from(bytes);
    if scope == 0 {
        format!("[{ip}]:{port}")
    } else {
        format!("[{ip}%{scope}]:{port}")
    }
}

fn raw_endpoints(port: u16) -> Result<Vec<Endpoint>, String> {
    if port == 0 {
        return Err("端口号必须是 1–65535 之间的整数。".into());
    }
    let mut result = Vec::new();
    let mut add = |protocol: &str, family: &str, address: String, state: String, pid: u32| {
        result.push(Endpoint {
            protocol: protocol.into(),
            family: family.into(),
            local_address: address,
            state,
            pid,
            process_name: String::new(),
            executable_path: None,
            started_at: None,
            blocked_reason: None,
        });
    };
    // SAFETY: each row type and offset match the selected family and table class.
    unsafe {
        for row in read_table::<MIB_TCPROW_OWNER_PID>(
            offset_of!(MIB_TCPTABLE_OWNER_PID, table),
            |p, n| GetExtendedTcpTable(p, n, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0),
        )? {
            if port_number(row.dwLocalPort) == port {
                add(
                    "TCP",
                    "IPv4",
                    format!("{}:{port}", Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                    tcp_state(row.dwState),
                    row.dwOwningPid,
                );
            }
        }
        for row in read_table::<MIB_TCP6ROW_OWNER_PID>(
            offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
            |p, n| GetExtendedTcpTable(p, n, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0),
        )? {
            if port_number(row.dwLocalPort) == port {
                add(
                    "TCP",
                    "IPv6",
                    ipv6_endpoint(row.ucLocalAddr, row.dwLocalScopeId, port),
                    tcp_state(row.dwState),
                    row.dwOwningPid,
                );
            }
        }
        for row in read_table::<MIB_UDPROW_OWNER_PID>(
            offset_of!(MIB_UDPTABLE_OWNER_PID, table),
            |p, n| GetExtendedUdpTable(p, n, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0),
        )? {
            if port_number(row.dwLocalPort) == port {
                add(
                    "UDP",
                    "IPv4",
                    format!("{}:{port}", Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                    "BOUND".into(),
                    row.dwOwningPid,
                );
            }
        }
        for row in read_table::<MIB_UDP6ROW_OWNER_PID>(
            offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
            |p, n| GetExtendedUdpTable(p, n, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0),
        )? {
            if port_number(row.dwLocalPort) == port {
                add(
                    "UDP",
                    "IPv6",
                    ipv6_endpoint(row.ucLocalAddr, row.dwLocalScopeId, port),
                    "BOUND".into(),
                    row.dwOwningPid,
                );
            }
        }
    }
    result.sort_by(|a, b| {
        (a.pid, &a.protocol, &a.family, &a.local_address, &a.state).cmp(&(
            b.pid,
            &b.protocol,
            &b.family,
            &b.local_address,
            &b.state,
        ))
    });
    result.dedup_by(|a, b| {
        a.pid == b.pid
            && a.protocol == b.protocol
            && a.local_address == b.local_address
            && a.state == b.state
    });
    Ok(result)
}

pub fn inspect(port: u16) -> Result<PortSnapshot, String> {
    let mut endpoints = raw_endpoints(port)?;
    let mut cache = HashMap::new();
    for endpoint in &mut endpoints {
        let info = cache
            .entry(endpoint.pid)
            .or_insert_with(|| process_info(endpoint.pid));
        endpoint.process_name = info.name.clone();
        endpoint.executable_path = info.path.clone();
        endpoint.started_at = info.started_at.clone();
        endpoint.blocked_reason = info.blocked_reason.clone();
    }
    Ok(PortSnapshot {
        port,
        endpoints,
        scanned_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    })
}

pub fn terminate(port: u16, pid: u32, expected_started_at: &str) -> Result<(), String> {
    if port == 0 {
        return Err("端口号必须是 1–65535 之间的整数。".into());
    }
    terminate_verified(pid, expected_started_at, || {
        Ok(raw_endpoints(port)?
            .iter()
            .any(|endpoint| endpoint.pid == pid))
    })
}

pub(crate) fn terminate_verified(
    pid: u32,
    expected_started_at: &str,
    still_using_resource: impl FnOnce() -> Result<bool, String>,
) -> Result<(), String> {
    if pid == 0 || pid == 4 || pid == std::process::id() {
        return Err("不能结束系统进程或 port-free 自身。".into());
    }
    // Keep the handle through verification and termination so PID reuse cannot
    // redirect TerminateProcess to a different process object.
    let handle = open_process(
        pid,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
    )?;
    if creation_time(&handle)? != expected_started_at {
        return Err("进程已经变化，请重新检测后再释放。".into());
    }
    if critical_process(&handle)? {
        return Err("Windows 关键进程，不能强制结束。".into());
    }
    if !still_using_resource()? {
        return Err("该进程已不再占用目标，请重新检测。".into());
    }
    // SAFETY: the retained handle has synchronize and terminate rights.
    unsafe {
        if WaitForSingleObject(handle.0, 0) != WAIT_TIMEOUT {
            return Err("进程已退出，请重新检测端口。".into());
        }
        if TerminateProcess(handle.0, 1) == 0 {
            return Err(win_error("结束进程失败"));
        }
        match WaitForSingleObject(handle.0, 3000) {
            WAIT_OBJECT_0 => Ok(()),
            WAIT_TIMEOUT => Err("已发送终止请求，进程仍在退出中，请稍后重新检测。".into()),
            _ => Err(win_error("等待进程退出失败")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        net::{TcpListener, UdpSocket},
        os::windows::process::CommandExt,
        process::{Child, Command, Stdio},
    };

    #[test]
    fn validates_port_and_protects_system_and_self() {
        assert!(inspect(0).is_err());
        for pid in [0, 4, std::process::id()] {
            assert!(terminate(7890, pid, "0").is_err());
        }
        assert_eq!(port_number(7890u16.to_be() as u32), 7890);
        assert_eq!(port_number(65535u16.to_be() as u32), 65535);
    }

    #[test]
    fn detects_ipv4_tcp_and_udp_and_then_release() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let udp = UdpSocket::bind(("127.0.0.1", port)).unwrap();
        let snapshot = inspect(port).unwrap();
        for protocol in ["TCP", "UDP"] {
            let row = snapshot
                .endpoints
                .iter()
                .find(|row| row.protocol == protocol && row.pid == std::process::id())
                .unwrap();
            assert_eq!(row.local_address, format!("127.0.0.1:{port}"));
            assert_eq!(row.family, "IPv4");
            assert!(row.started_at.is_some());
            assert!(row.blocked_reason.is_some());
        }
        drop(tcp);
        drop(udp);
        assert!(
            !inspect(port)
                .unwrap()
                .endpoints
                .iter()
                .any(|row| row.pid == std::process::id())
        );
    }

    #[test]
    fn detects_ipv6_tcp_and_udp() {
        let tcp = TcpListener::bind("[::1]:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let udp = UdpSocket::bind(("::1", port)).unwrap();
        let snapshot = inspect(port).unwrap();
        for protocol in ["TCP", "UDP"] {
            assert!(snapshot.endpoints.iter().any(|row| row.protocol == protocol
                && row.family == "IPv6"
                && row.local_address == format!("[::1]:{port}")
                && row.pid == std::process::id()));
        }
        drop(udp);
    }

    struct Fixture(Child);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn terminates_only_verified_child_and_rechecks_port() {
        // The only process killed in this suite is this disposable child.
        let script = "$ErrorActionPreference='Stop'; $tcp=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0); $tcp.Start(); $port=$tcp.LocalEndpoint.Port; $udp=[Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,$port)); [Console]::WriteLine($port); [Console]::Out.Flush(); Start-Sleep -Seconds 45";
        let mut child = Fixture(
            Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .creation_flags(0x08000000)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut line = String::new();
        BufReader::new(child.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port: u16 = line.trim().parse().unwrap();
        let snapshot = inspect(port).unwrap();
        let row = snapshot
            .endpoints
            .iter()
            .find(|row| row.pid == child.0.id())
            .unwrap();
        let token = row.started_at.as_ref().unwrap();
        assert!(row.blocked_reason.is_none());
        assert!(terminate(port, child.0.id(), "wrong-creation-time").is_err());
        assert!(child.0.try_wait().unwrap().is_none());
        let unrelated = TcpListener::bind("127.0.0.1:0").unwrap();
        let other_port = unrelated.local_addr().unwrap().port();
        assert!(terminate(other_port, child.0.id(), token).is_err());
        assert!(child.0.try_wait().unwrap().is_none());
        terminate(port, child.0.id(), token).unwrap();
        assert!(child.0.try_wait().unwrap().is_some());
        assert!(
            !inspect(port)
                .unwrap()
                .endpoints
                .iter()
                .any(|row| row.pid == child.0.id())
        );
    }
}
