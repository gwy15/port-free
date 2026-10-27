import "./styles.css";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";

type Mode = "port" | "file";
interface ProcessInfo {
  pid: number;
  processName: string;
  executablePath: string | null;
  startedAt: string | null;
  blockedReason: string | null;
}
interface Endpoint extends ProcessInfo {
  protocol: string;
  localAddress: string;
  state: string;
}
interface PortSnapshot {
  port: number;
  endpoints: Endpoint[];
  scannedAt: number;
}
interface FileProcess extends ProcessInfo {
  files: string[];
}
interface FileSnapshot {
  path: string;
  processes: FileProcess[];
  partial: boolean;
  scannedAt: number;
}
interface Owner extends ProcessInfo {
  summary: string;
  details: string[];
}
interface Result {
  mode: Mode;
  query: string;
  owners: Owner[];
  scannedAt: number;
  partial: boolean;
}
interface Runtime {
  elevated: boolean;
  handleAvailable: boolean;
}

const $ = <T extends HTMLElement>(id: string) =>
  document.getElementById(id) as T;
const port = $<HTMLInputElement>("port");
const path = $<HTMLInputElement>("path");
const auto = $<HTMLInputElement>("auto-refresh");
const dialog = $<HTMLDialogElement>("confirm");
let mode: Mode = "port";
let result: Result | null = null;
let runtime: Runtime | null = null;
let busy = false;
let error = "";
let pending: { result: Result; targets: Owner[] } | null = null;

const message = (value: unknown) =>
  value instanceof Error ? value.message : String(value);
function text(parent: HTMLElement, tag: string, value: string, className = "") {
  const element = document.createElement(tag);
  element.textContent = value;
  element.className = className;
  parent.append(element);
  return element;
}
function query(): string {
  return (mode === "port" ? port.value : path.value).trim();
}
function valid(): boolean {
  if (mode === "file")
    return (
      query().length > 0 &&
      runtime?.elevated === true &&
      runtime?.handleAvailable === true
    );
  return (
    /^\d{1,5}$/.test(query()) &&
    Number(query()) >= 1 &&
    Number(query()) <= 65535
  );
}
function canEnd(owner: ProcessInfo) {
  return owner.startedAt !== null && owner.blockedReason === null;
}
function notice(value: string, failed = false) {
  $("notice").textContent = value;
  $("notice").className = failed ? "error" : "";
  $("notice").hidden = !value;
}
function controls() {
  document.querySelectorAll<HTMLButtonElement>("button").forEach((button) => {
    if (!dialog.contains(button)) button.disabled = busy;
  });
  port.disabled = busy;
  path.disabled = busy;
  auto.disabled = busy;
  $<HTMLButtonElement>("scan-port").disabled =
    busy || (mode === "port" && !valid());
  $<HTMLButtonElement>("scan-file").disabled =
    busy || (mode === "file" && !valid());
  $("scan-port").textContent = busy && mode === "port" ? "检测中…" : "检测";
  $("scan-file").textContent = busy && mode === "file" ? "处理中…" : "检测";
  $("elevate").hidden = runtime?.elevated !== false;
  $("admin-label").hidden = runtime?.elevated !== true;
}
function render() {
  $("port-controls").hidden = mode !== "port";
  $("file-controls").hidden = mode !== "file";
  for (const kind of ["port", "file"] as const) {
    $("tab-" + kind).classList.toggle("active", mode === kind);
    $("tab-" + kind).setAttribute("aria-pressed", String(mode === kind));
  }
  $("details-heading").textContent =
    mode === "port" ? "协议 / 地址" : "占用文件";
  const note =
    mode === "file"
      ? runtime?.handleAvailable === false
        ? "需要 Microsoft Handle：将 handle64.exe 放到程序目录。"
        : ""
      : "";
  $("file-note").textContent = note;
  $("file-note").hidden = !note;
  $("status").className = error ? "error" : "";
  $("status").textContent = busy
    ? "检测中…"
    : error ||
      (result
        ? result.owners.length
          ? result.owners.length +
            " 个进程" +
            (result.partial ? " · 结果可能不完整" : "")
          : result.partial
            ? "未发现占用（当前权限 / 扫描范围）"
            : "未发现占用"
        : mode === "file" && runtime?.elevated === false
          ? "需要管理员权限"
          : "待检测");
  $("time").textContent = result
    ? new Date(result.scannedAt).toLocaleTimeString("zh-CN", { hour12: false })
    : "";
  $("release-all").hidden = !result?.owners.some(canEnd);
  $("results").hidden = !result?.owners.length;
  const rows = $("rows");
  rows.replaceChildren();
  for (const owner of result?.owners ?? []) {
    const row = text(rows, "tr", "");
    const name = text(row, "td", owner.processName, "process-name");
    name.title = owner.executablePath ?? owner.processName;
    text(row, "td", String(owner.pid), "pid");
    const detailCell = text(row, "td", "");
    const details = text(detailCell, "details", "");
    text(details, "summary", owner.summary);
    for (const line of owner.details)
      text(details, "code", line, "detail-line");
    const action = text(row, "td", "");
    if (canEnd(owner)) {
      const button = text(
        action,
        "button",
        "结束",
        "danger-text",
      ) as HTMLButtonElement;
      button.type = "button";
      button.setAttribute(
        "aria-label",
        "结束 " + owner.processName + " PID " + owner.pid,
      );
      button.addEventListener("click", () => confirmEnd([owner]));
    } else {
      const label = text(action, "span", "不可结束", "blocked");
      label.title = owner.blockedReason ?? "无法核验进程";
    }
  }
  controls();
}
async function inspect(kind: Mode, value: string): Promise<Result> {
  if (!isTauri()) throw new Error("请在桌面应用中检测。");
  if (kind === "file") {
    const scan = await invoke<FileSnapshot>("inspect_file", { path: value });
    return {
      mode: kind,
      query: scan.path,
      scannedAt: scan.scannedAt,
      partial: scan.partial,
      owners: scan.processes.map((owner) => ({
        ...owner,
        summary: owner.files.length + " 个文件",
        details: owner.files,
      })),
    };
  }
  const scan = await invoke<PortSnapshot>("inspect_port", {
    port: Number(value),
  });
  const grouped = new Map<
    number,
    { info: Endpoint; details: string[]; protocols: Set<string> }
  >();
  for (const endpoint of scan.endpoints) {
    const group = grouped.get(endpoint.pid) ?? {
      info: endpoint,
      details: [],
      protocols: new Set<string>(),
    };
    group.details.push(
      endpoint.protocol + "  " + endpoint.localAddress + "  " + endpoint.state,
    );
    group.protocols.add(endpoint.protocol);
    grouped.set(endpoint.pid, group);
  }
  return {
    mode: kind,
    query: String(scan.port),
    scannedAt: scan.scannedAt,
    partial: false,
    owners: [...grouped.values()]
      .map((group) => ({
        ...group.info,
        summary: [...group.protocols].join(" / "),
        details: group.details,
      }))
      .sort((a, b) => Number(a.pid === 0) - Number(b.pid === 0)),
  };
}
async function scan(automatic = false) {
  if (busy || dialog.open || !valid()) return;
  busy = true;
  error = "";
  if (!automatic) notice("");
  render();
  try {
    result = await inspect(mode, query());
  } catch (failure) {
    result = null;
    error = message(failure);
    auto.checked = false;
  } finally {
    busy = false;
    render();
  }
}
function invalidate() {
  result = null;
  error = "";
  notice("");
  const invalid = mode === "port" && !valid();
  port.setAttribute("aria-invalid", String(invalid));
  $("validation").hidden = !invalid;
  $("validation").textContent = invalid ? "端口范围：1–65535" : "";
  render();
}
function switchMode(next: Mode) {
  if (busy || dialog.open) return;
  mode = next;
  invalidate();
}
function confirmEnd(owners: Owner[]) {
  if (busy || !result || dialog.open) return;
  pending = { result, targets: owners.filter(canEnd) };
  if (!pending.targets.length) return;
  const list = $("confirm-processes");
  list.replaceChildren();
  for (const owner of pending.targets) {
    const item = text(list, "li", "");
    text(item, "span", owner.processName);
    text(item, "code", "PID " + owner.pid);
  }
  dialog.returnValue = "";
  dialog.showModal();
}
async function terminate(selection: { result: Result; targets: Owner[] }) {
  busy = true;
  controls();
  $("status").textContent = "结束进程中…";
  let ended = 0;
  const failures: string[] = [];
  for (const owner of selection.targets) {
    try {
      if (selection.result.mode === "port") {
        await invoke("terminate_process", {
          port: Number(selection.result.query),
          pid: owner.pid,
          startedAt: owner.startedAt,
        });
      } else {
        await invoke("terminate_file_process", {
          path: selection.result.query,
          pid: owner.pid,
          startedAt: owner.startedAt,
        });
      }
      ended++;
    } catch (failure) {
      failures.push("PID " + owner.pid + "：" + message(failure));
    }
  }
  try {
    result = await inspect(selection.result.mode, selection.result.query);
    error = "";
  } catch (failure) {
    result = null;
    error = message(failure);
    auto.checked = false;
  } finally {
    busy = false;
    render();
  }
  notice(
    "已结束 " +
      ended +
      " 个进程。" +
      (failures.length ? "\n" + failures.join("\n") : ""),
    failures.length > 0,
  );
}
async function choose(directory: boolean) {
  if (busy) return;
  busy = true;
  controls();
  try {
    const selected = await open({
      directory,
      multiple: false,
      title: directory ? "选择文件夹" : "选择文件",
    });
    if (selected) {
      path.value = selected;
      invalidate();
    }
  } catch (failure) {
    notice(message(failure), true);
  } finally {
    busy = false;
    render();
  }
  if (path.value && !error) path.focus();
}
$("query-form").addEventListener("submit", (event) => {
  event.preventDefault();
  void scan();
});
$("tab-port").addEventListener("click", () => switchMode("port"));
$("tab-file").addEventListener("click", () => switchMode("file"));
port.addEventListener("input", invalidate);
path.addEventListener("input", invalidate);
$("pick-file").addEventListener("click", () => void choose(false));
$("pick-folder").addEventListener("click", () => void choose(true));
$("release-all").addEventListener("click", () => {
  if (result) confirmEnd(result.owners);
});
dialog.addEventListener("close", () => {
  const selection = pending;
  pending = null;
  if (selection && dialog.returnValue === "confirm") void terminate(selection);
});
auto.addEventListener("change", () => {
  if (auto.checked) void scan(true);
});
window.setInterval(() => {
  if (mode === "port" && auto.checked && !document.hidden) void scan(true);
}, 3000);
$("elevate").addEventListener("click", async () => {
  if (busy) return;
  busy = true;
  controls();
  try {
    localStorage.setItem(
      "port-free-resume",
      JSON.stringify({ mode, port: port.value, path: path.value }),
    );
    await invoke("restart_as_admin");
  } catch (failure) {
    localStorage.removeItem("port-free-resume");
    notice(message(failure), true);
    busy = false;
    controls();
  }
});
async function start() {
  try {
    const saved = localStorage.getItem("port-free-resume");
    localStorage.removeItem("port-free-resume");
    if (saved) {
      const value = JSON.parse(saved);
      if (value.mode === "file" || value.mode === "port") mode = value.mode;
      if (typeof value.port === "string") port.value = value.port;
      if (typeof value.path === "string") path.value = value.path;
    }
  } catch {
    /* A stale local preference must not prevent startup. */
  }
  render();
  if (isTauri()) {
    try {
      runtime = await invoke<Runtime>("runtime_info");
    } catch (failure) {
      notice(message(failure), true);
    }
  }
  render();
  if (mode === "port") void scan();
}
void start();
