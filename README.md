# port-free

Windows 端口与文件占用排查工具。Tauri 2 / Rust / TypeScript。

## 功能

- **端口**：默认 7890，检查 TCP / UDP、IPv4 / IPv6，可每 3 秒刷新。
- **文件**：输入路径或选择文件 / 文件夹，按进程汇总占用文件。
- 表格仅显示进程名、PID、协议或文件数量及结束按钮；展开可查看地址 / 文件路径，进程名悬停显示程序路径。
- 支持结束单个或全部已检测进程。结束前复核启动时间和当前占用，保护系统关键进程。
- 文件全局扫描要求管理员权限；点击“以管理员身份重启”，通过 Windows UAC 后检测。

## 文件占用依赖

使用 [Microsoft Sysinternals Handle](https://learn.microsoft.com/en-us/sysinternals/downloads/handle)。

优先使用 Windows System32 中的 handle64.exe / handle64a.exe / handle.exe，也支持将对应工具放在本程序 exe 旁边。本项目不重新分发 Handle，不向 System32 安装文件。首次调用以 -accepteula 接受 Handle 自身许可。

使用 -vt 输出解析 PID 和句柄，再通过 Windows 句柄 API 读取完整 Unicode 路径、核对文件或文件夹边界。仅将成功核验的句柄计入结果；不可访问的句柄会标记扫描可能不完整。外部扫描有 45 秒超时，错误不会显示为“无占用”。文件夹扫描包含其子文件夹；打开句柄不一定意味着文件无法删除。

## 开发 / 构建

环境：Windows、Node.js 22.12+、Rust MSVC、C++ Build Tools、WebView2。

```powershell
npm ci
npm run desktop
npm run desktop:build
```

- 程序：src-tauri/target/release/port-free.exe
- 安装包：src-tauri/target/release/bundle/nsis/port-free_0.2.0_x64-setup.exe

npm run dev 仅预览界面，端口和文件检测需要桌面应用。

## 测试

```powershell
npm run build
npm run test:backend
cargo test --manifest-path src-tauri/Cargo.toml --lib files::tests::real_file_folder_and_verified_release -- --ignored
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
```

文件集成测试需要已安装 Handle，只操作测试创建的临时文件与子进程。覆盖中文文件名、相似目录排除、文件和文件夹检测、过期进程身份拒绝及真实释放。

强制结束会关闭整个进程，未保存的数据可能丢失。程序不直接关闭某个文件句柄，也不会阻止服务自动重启。
