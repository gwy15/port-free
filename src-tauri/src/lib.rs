#[cfg(not(windows))]
compile_error!("port-free only supports Windows.");

mod files;
mod ports;

#[tauri::command]
async fn inspect_port(port: u16) -> Result<ports::PortSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || ports::inspect(port))
        .await
        .map_err(|error| format!("检测任务失败：{error}"))?
}

#[tauri::command]
async fn terminate_process(port: u16, pid: u32, started_at: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || ports::terminate(port, pid, &started_at))
        .await
        .map_err(|error| format!("释放任务失败：{error}"))?
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            inspect_port,
            terminate_process,
            inspect_file,
            terminate_file_process,
            runtime_info,
            restart_as_admin
        ])
        .run(tauri::generate_context!())
        .expect("无法启动 port-free");
}

#[tauri::command]
async fn inspect_file(path: String) -> Result<files::FileSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || files::inspect(&path))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn terminate_file_process(path: String, pid: u32, started_at: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || files::terminate(&path, pid, &started_at))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
fn runtime_info() -> Result<files::RuntimeInfo, String> {
    files::runtime_info()
}

#[tauri::command]
async fn restart_as_admin(app: tauri::AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(files::request_elevation)
        .await
        .map_err(|error| error.to_string())??;
    app.exit(0);
    Ok(())
}
