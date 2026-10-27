use crate::ports;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    io::Read,
    mem::size_of,
    os::windows::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr, thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    Storage::FileSystem::GetFinalPathNameByHandleW,
    System::{
        SystemInformation::GetSystemDirectoryW,
        Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE},
    },
    UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeInfo {
    pub elevated: bool,
    pub handle_available: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileProcess {
    pub pid: u32,
    pub process_name: String,
    pub executable_path: Option<String>,
    pub started_at: Option<String>,
    pub blocked_reason: Option<String>,
    pub files: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSnapshot {
    pub path: String,
    pub processes: Vec<FileProcess>,
    pub partial: bool,
    pub scanned_at: u64,
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this type owns a successful token/process/duplicate handle.
        unsafe { CloseHandle(self.0) };
    }
}

pub fn is_elevated() -> Result<bool, String> {
    let mut handle = ptr::null_mut();
    // SAFETY: output handle is valid; current process is a documented pseudo-handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
        return Err("无法读取当前权限。".into());
    }
    let token = OwnedHandle(handle);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0;
    // SAFETY: the buffer has the size and layout requested by TokenElevation.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err("无法读取当前权限。".into());
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn handle_tool() -> Result<PathBuf, String> {
    let mut system = vec![0u16; 32768];
    // SAFETY: the buffer has the advertised capacity.
    let length = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    let mut folders = Vec::new();
    if length > 0 && length < system.len() {
        folders.push(PathBuf::from(String::from_utf16_lossy(&system[..length])));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        folders.push(parent.to_path_buf());
    }
    let native = if cfg!(target_arch = "aarch64") {
        "handle64a.exe"
    } else {
        "handle64.exe"
    };
    for folder in folders {
        for name in [native, "handle.exe"] {
            let candidate = folder.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err("未找到 Microsoft Handle。请将 handle64.exe 放到程序目录，或安装到 System32。".into())
}

pub fn runtime_info() -> Result<RuntimeInfo, String> {
    Ok(RuntimeInfo {
        elevated: is_elevated()?,
        handle_available: handle_tool().is_ok(),
    })
}

pub fn request_elevation() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let file: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();
    // SAFETY: fixed verb, exact current executable, no user-controlled arguments.
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            ptr::null(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;
    if result <= 32 {
        Err("未获得管理员权限，已保留当前窗口。".into())
    } else {
        Ok(())
    }
}

struct Target {
    path: String,
    directory: bool,
}
fn target(input: &str) -> Result<Target, String> {
    let input = input.trim().trim_matches('"');
    if input.is_empty() || input.contains('\0') {
        return Err("请输入文件或文件夹路径。".into());
    }
    let path = Path::new(input);
    if !path.is_absolute() {
        return Err("请输入完整路径。".into());
    }
    let metadata = path
        .metadata()
        .map_err(|error| format!("无法访问路径：{error}"))?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err("请选择文件或文件夹。".into());
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("无法解析路径：{error}"))?;
    Ok(Target {
        path: display_path(&canonical.to_string_lossy()),
        directory: metadata.is_dir(),
    })
}

fn display_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(path).to_string()
    }
}

fn matches_target(candidate: &str, target: &Target) -> bool {
    let candidate = display_path(candidate).replace('/', r"\").to_lowercase();
    let base = target.path.replace('/', r"\").to_lowercase();
    let base = base.trim_end_matches('\\');
    candidate.trim_end_matches('\\') == base
        || (target.directory && candidate.starts_with(&format!("{base}\\")))
}

#[derive(Debug)]
struct HandleRow {
    pid: u32,
    handle: usize,
    _reported_path: String,
}

// Handle's CSV output does not quote commas in filenames. Use -vt and split the
// first four tabs only; this preserves spaces, commas and bracket characters.
fn parse_output(output: &str) -> Result<Vec<HandleRow>, String> {
    let output = output.trim_start_matches('\u{feff}').trim();
    if output == "No matching handles found." {
        return Ok(Vec::new());
    }
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let header = lines.next().ok_or("Handle 未返回结果。")?;
    if header.trim_end() != "Process\tPID\tType\tHandle\tName" {
        return Err(format!(
            "Handle 扫描失败：{}",
            output.chars().take(240).collect::<String>()
        ));
    }
    let mut rows = Vec::new();
    for line in lines {
        let fields: Vec<_> = line.trim_end().splitn(5, '\t').collect();
        if fields.len() != 5 || fields[2] != "File" {
            return Err("Handle 返回了无法识别的记录，未将其视为无占用。".into());
        }
        rows.push(HandleRow {
            pid: fields[1].parse().map_err(|_| "Handle 返回的 PID 无效。")?,
            handle: usize::from_str_radix(fields[3].trim_start_matches("0x"), 16)
                .map_err(|_| "Handle 返回的句柄无效。")?,
            _reported_path: fields[4].to_string(),
        });
    }
    Ok(rows)
}

fn run_handle(target: &Target, pid: Option<u32>) -> Result<Vec<HandleRow>, String> {
    let tool = handle_tool()?;
    let mut command = Command::new(&tool);
    command.args(["-accepteula", "-nobanner", "-vt"]);
    if let Some(pid) = pid {
        command.args(["-p", &pid.to_string()]);
    }
    // Arguments are passed directly to the executable; no shell interpolation.
    command
        .arg(&target.path)
        .current_dir(tool.parent().ok_or("Handle 路径无效。")?)
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("无法运行 Handle：{error}"))?;
    const LIMIT: u64 = 8 * 1024 * 1024;
    let stdout = child.stdout.take().ok_or("无法读取 Handle 输出。")?;
    let stderr = child.stderr.take().ok_or("无法读取 Handle 错误输出。")?;
    let read = |pipe: Box<dyn Read + Send>| -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        pipe.take(LIMIT + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    };
    let out = thread::spawn(move || read(Box::new(stdout)));
    let err = thread::spawn(move || read(Box::new(stderr)));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if start.elapsed() < Duration::from_secs(45) => {
                thread::sleep(Duration::from_millis(80))
            }
            Ok(None) => break Err("Handle 扫描超时，请以管理员身份重试。".to_string()),
            Err(error) => break Err(format!("Handle 扫描失败：{error}")),
        }
    };
    if status.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stdout = out
        .join()
        .map_err(|_| "读取 Handle 输出失败。")?
        .map_err(|error| error.to_string())?;
    let stderr = err
        .join()
        .map_err(|_| "读取 Handle 输出失败。")?
        .map_err(|error| error.to_string())?;
    let status = status?;
    if stdout.len() as u64 > LIMIT || stderr.len() as u64 > LIMIT {
        return Err("结果超过大小限制，请缩小到具体文件或子文件夹。".into());
    }
    let stdout = String::from_utf8_lossy(&stdout);
    if !stderr.is_empty() {
        return Err(format!(
            "Handle 扫描失败：{}",
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    // Handle exits with 1 for a normal no-match result.
    if !status.success() && stdout.trim() != "No matching handles found." {
        return Err(format!(
            "Handle 扫描失败（{}）：{}",
            status,
            stdout.chars().take(240).collect::<String>()
        ));
    }
    parse_output(&stdout)
}

fn unicode_handle_path(pid: u32, value: usize) -> Option<String> {
    // SAFETY: all handles are owned below; DuplicateHandle never closes the
    // source handle (DUPLICATE_CLOSE_SOURCE is deliberately not used).
    unsafe {
        let process = OpenProcess(PROCESS_DUP_HANDLE, 0, pid);
        if process.is_null() {
            return None;
        }
        let process = OwnedHandle(process);
        let mut duplicate = ptr::null_mut();
        if DuplicateHandle(
            process.0,
            value as HANDLE,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            return None;
        }
        let duplicate = OwnedHandle(duplicate);
        let mut buffer = vec![0u16; 32768];
        let count =
            GetFinalPathNameByHandleW(duplicate.0, buffer.as_mut_ptr(), buffer.len() as u32, 0)
                as usize;
        if count == 0 || count >= buffer.len() {
            return None;
        }
        Some(display_path(&String::from_utf16_lossy(&buffer[..count])))
    }
}

fn scan(target: &Target, pid: Option<u32>) -> Result<FileSnapshot, String> {
    let mut grouped: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    let mut partial = !is_elevated()?;
    for row in run_handle(target, pid)? {
        // -p can be interpreted by external tool versions as a prefix. Enforce
        // exact PID before considering a resource for destructive operations.
        if pid.is_some_and(|pid| pid != row.pid) {
            continue;
        }
        let path = match unicode_handle_path(row.pid, row.handle) {
            Some(path) => path,
            None => {
                // A disappeared or inaccessible handle must not become a
                // verified match just because Handle's substring search hit it.
                partial = true;
                continue;
            }
        };
        if matches_target(&path, target) {
            grouped.entry(row.pid).or_default().insert(path);
        }
    }
    let processes = grouped
        .into_iter()
        .map(|(pid, files)| {
            let info = ports::process_info(pid);
            FileProcess {
                pid,
                process_name: info.name,
                executable_path: info.path,
                started_at: info.started_at,
                blocked_reason: info.blocked_reason,
                files: files.into_iter().collect(),
            }
        })
        .collect();
    Ok(FileSnapshot {
        path: target.path.clone(),
        processes,
        partial,
        scanned_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    })
}

pub fn inspect(path: &str) -> Result<FileSnapshot, String> {
    if !is_elevated()? {
        return Err("文件排查需要管理员权限。".into());
    }
    scan(&target(path)?, None)
}

pub fn terminate(path: &str, pid: u32, started_at: &str) -> Result<(), String> {
    let target = target(path)?;
    ports::terminate_verified(pid, started_at, || {
        Ok(scan(&target, Some(pid))?
            .processes
            .iter()
            .any(|process| process.pid == pid))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::process::Child;

    #[test]
    fn parse_handles_and_reject_errors() {
        let output = "Process\tPID\tType\tHandle\tName\r\nnode.exe\t123\tFile\t0xABC\tC:\\data\\a, b [1].txt \r\n";
        let rows = parse_output(output).unwrap();
        assert_eq!(rows[0].pid, 123);
        assert_eq!(rows[0].handle, 0xABC);
        assert_eq!(rows[0]._reported_path, r"C:\data\a, b [1].txt");
        assert!(
            parse_output("No matching handles found.\r\n")
                .unwrap()
                .is_empty()
        );
        assert!(parse_output("Error opening process").is_err());
        assert!(parse_output("").is_err());
        assert!(parse_output("Process\tPID\tType\tHandle\tName\nbad row").is_err());
    }

    #[test]
    fn rejects_unprivileged_global_scans() {
        if !is_elevated().unwrap() {
            assert!(inspect(r"C:\Windows").unwrap_err().contains("管理员"));
        }
    }

    #[test]
    fn exact_file_and_directory_boundaries() {
        let folder = Target {
            path: r"C:\Data".into(),
            directory: true,
        };
        assert!(matches_target(r"\\?\C:\data\中文.txt", &folder));
        assert!(matches_target(r"C:\Data", &folder));
        assert!(!matches_target(r"C:\Database\file.txt", &folder));
        let file = Target {
            path: r"C:\Data\file.txt".into(),
            directory: false,
        };
        assert!(matches_target(r"c:\data\FILE.txt", &file));
        assert!(!matches_target(r"C:\Data\file.txt.bak", &file));
        assert!(target("").is_err());
        assert!(target("relative.txt").is_err());
    }

    struct Fixture {
        child: Child,
        root: PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    #[ignore = "Requires Microsoft Sysinternals Handle installed; uses only a disposable child"]
    fn real_file_folder_and_verified_release() {
        let root = std::env::temp_dir().join(format!(
            "port-free-files-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let folder = root.join("data");
        let sibling = root.join("data-other");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        let file = folder.join("锁定,文件 [1].txt");
        let other = sibling.join("other.txt");
        let unheld = root.join("unheld.txt");
        for path in [&file, &other, &unheld] {
            std::fs::write(path, "fixture").unwrap();
        }
        let script = "$a=[IO.File]::Open($env:PORT_FREE_TEST_FILE,'Open','ReadWrite','None'); $b=[IO.File]::Open($env:PORT_FREE_TEST_OTHER,'Open','ReadWrite','None'); [Console]::WriteLine('ready'); [Console]::Out.Flush(); Start-Sleep -Seconds 90";
        let child = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("PORT_FREE_TEST_FILE", &file)
            .env("PORT_FREE_TEST_OTHER", &other)
            .creation_flags(0x08000000)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut fixture = Fixture { child, root };
        let mut line = String::new();
        BufReader::new(fixture.child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ready");
        let pid = fixture.child.id();
        let snapshot = scan(&target(&file.to_string_lossy()).unwrap(), Some(pid)).unwrap();
        assert_eq!(snapshot.processes.len(), 1);
        assert!(snapshot.processes[0].files[0].ends_with("锁定,文件 [1].txt"));
        let folder_snapshot = scan(&target(&folder.to_string_lossy()).unwrap(), Some(pid)).unwrap();
        assert_eq!(
            folder_snapshot.processes[0].files.len(),
            1,
            "must exclude data-other"
        );
        let token = snapshot.processes[0].started_at.as_ref().unwrap();
        assert!(terminate(&file.to_string_lossy(), pid, "stale").is_err());
        assert!(terminate(&unheld.to_string_lossy(), pid, token).is_err());
        assert!(fixture.child.try_wait().unwrap().is_none());
        terminate(&file.to_string_lossy(), pid, token).unwrap();
        assert!(fixture.child.try_wait().unwrap().is_some());
        // Exclusive reopening verifies that the held file was actually released.
        let _reopened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file)
            .unwrap();
    }
}
