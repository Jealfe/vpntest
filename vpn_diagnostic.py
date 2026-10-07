from __future__ import annotations

import ctypes
import datetime as dt
import difflib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import traceback
import zipfile
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

APP_NAME = "VPN Diagnostic"
APP_VERSION = "0.1.0"
VPN_WORDS = (
    "vpn", "wireguard", "wintun", "tap", "tun", "openvpn", "amnezia",
    "outline", "clash", "sing-box", "singbox", "v2ray", "xray", "warp",
    "proton", "nord", "mullvad", "tailscale", "zerotier", "forti",
)


def base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


REPORTS = base_dir() / "reports"


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run(cmd: list[str], timeout: int = 35) -> tuple[int, str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            creationflags=flags,
        )
        text = p.stdout or ""
        if p.stderr:
            text += "\n[stderr]\n" + p.stderr
        return p.returncode, text.strip()
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout} seconds"
    except FileNotFoundError as exc:
        return 127, f"NOT FOUND: {exc}"
    except Exception:
        return 1, traceback.format_exc()


def ps(script: str, timeout: int = 45) -> tuple[int, str]:
    return run([
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command", script,
    ], timeout)


def redact(text: str) -> str:
    if not text:
        return text
    text = re.sub(r"(?i)([A-Z]:\\Users\\)[^\\\r\n]+", r"\1<USER>", text)
    text = re.sub(r"(?i)\b(?:[0-9A-F]{2}[-:]){5}[0-9A-F]{2}\b", "<MAC>", text)
    return text


def save(path: Path, text: str) -> None:
    path.write_text(redact(text), encoding="utf-8", errors="replace")


def command_to_file(folder: Path, filename: str, cmd: list[str], timeout: int = 35) -> None:
    code, out = run(cmd, timeout)
    save(folder / filename, f"Exit code: {code}\n\n{out}\n")


def ps_to_file(folder: Path, filename: str, script: str, timeout: int = 45) -> None:
    code, out = ps(script, timeout)
    save(folder / filename, f"Exit code: {code}\n\n{out}\n")


def ps_json(folder: Path, filename: str, expression: str) -> None:
    code, out = ps(
        "$ErrorActionPreference='Continue'; "
        + expression
        + " | ConvertTo-Json -Depth 6"
    )
    if code == 0 and out.strip():
        save(folder / filename, out)
    else:
        save(
            folder / filename,
            json.dumps({"exit_code": code, "error": out}, ensure_ascii=False, indent=2),
        )


def collect_snapshot(folder: Path, deep: bool, log) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    save(folder / "meta.txt", "\n".join([
        f"VPN Diagnostic: {APP_VERSION}",
        f"Captured: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"Platform: {platform.platform()}",
        f"Python: {platform.python_version()}",
        f"Administrator: {is_admin()}",
    ]) + "\n")

    commands = {
        "ipconfig_all.txt": ["ipconfig", "/all"],
        "route_print.txt": ["route", "print"],
        "arp.txt": ["arp", "-a"],
        "netstat.txt": ["netstat", "-ano"],
        "winhttp_proxy.txt": ["netsh", "winhttp", "show", "proxy"],
        "ipv4_interfaces.txt": ["netsh", "interface", "ipv4", "show", "interfaces"],
        "ipv6_interfaces.txt": ["netsh", "interface", "ipv6", "show", "interfaces"],
        "firewall_profiles.txt": ["netsh", "advfirewall", "show", "allprofiles"],
    }
    for name, cmd in commands.items():
        log("  • " + name)
        command_to_file(folder, name, cmd)

    structured = {
        "adapters.json":
            "Get-NetAdapter -IncludeHidden | "
            "Select-Object Name,InterfaceDescription,Status,LinkSpeed,MacAddress,"
            "ifIndex,DriverDescription,DriverVersion",
        "ipconfig.json":
            "Get-NetIPConfiguration -All | "
            "Select-Object InterfaceAlias,InterfaceIndex,NetProfile,IPv4Address,"
            "IPv6Address,IPv4DefaultGateway,IPv6DefaultGateway,DNSServer",
        "routes.json":
            "Get-NetRoute | "
            "Select-Object AddressFamily,DestinationPrefix,NextHop,RouteMetric,"
            "InterfaceMetric,ifIndex,InterfaceAlias,State,PolicyStore | "
            "Sort-Object AddressFamily,DestinationPrefix,RouteMetric",
        "dns.json":
            "Get-DnsClientServerAddress | "
            "Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses",
        "ip_interfaces.json":
            "Get-NetIPInterface | "
            "Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ConnectionState,"
            "Dhcp,NlMtu,InterfaceMetric,WeakHostSend,WeakHostReceive | "
            "Sort-Object InterfaceIndex,AddressFamily",
        "vpn_connections.json":
            "Get-VpnConnection -ErrorAction SilentlyContinue | "
            "Select-Object Name,ServerAddress,TunnelType,ConnectionStatus,"
            "SplitTunneling,AuthenticationMethod,EncryptionLevel",
        "connection_profiles.json":
            "Get-NetConnectionProfile | "
            "Select-Object Name,InterfaceAlias,InterfaceIndex,NetworkCategory,"
            "IPv4Connectivity,IPv6Connectivity",
        "firewall_profiles.json":
            "Get-NetFirewallProfile | "
            "Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,"
            "AllowInboundRules,AllowLocalFirewallRules,LogAllowed,LogBlocked,LogFileName",
    }
    for name, expression in structured.items():
        log("  • " + name)
        ps_json(folder, name, expression)

    log("  • services.txt")
    ps_to_file(
        folder,
        "services.txt",
        "Get-Service | Where-Object { "
        "$_.Name -match 'RasMan|IKEEXT|PolicyAgent|BFE|MpsSvc|Dnscache|NlaSvc|"
        "WinHttpAutoProxySvc|WlanSvc' -or "
        "$_.DisplayName -match 'VPN|WireGuard|OpenVPN|Tunnel|Wintun' } | "
        "Sort-Object Name | Format-Table -AutoSize Name,Status,StartType,DisplayName"
    )

    log("  • vpn_processes.txt")
    ps_to_file(
        folder,
        "vpn_processes.txt",
        "$k='vpn|wireguard|openvpn|amnezia|outline|clash|sing-box|singbox|"
        "v2ray|xray|warp|proton|nord|mullvad|tailscale|zerotier|forti'; "
        "Get-Process -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ProcessName -match $k -or $_.Path -match $k } | "
        "Select-Object ProcessName,Id,Path,StartTime | Format-Table -AutoSize"
    )

    log("  • user_proxy.txt")
    ps_to_file(
        folder,
        "user_proxy.txt",
        "Get-ItemProperty "
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' "
        "-ErrorAction SilentlyContinue | "
        "Select-Object ProxyEnable,ProxyServer,AutoConfigURL,AutoDetect | Format-List"
    )

    if deep:
        log("  • глубокая диагностика драйверов/Winsock")
        command_to_file(
            folder, "pnputil_net_devices.txt",
            ["pnputil", "/enum-devices", "/class", "Net"], 60
        )
        command_to_file(
            folder, "winsock_catalog.txt",
            ["netsh", "winsock", "show", "catalog"], 60
        )
        ps_to_file(
            folder,
            "net_adapter_bindings.txt",
            "Get-NetAdapterBinding -AllBindings -ErrorAction SilentlyContinue | "
            "Select-Object Name,DisplayName,ComponentID,Enabled | "
            "Sort-Object Name,DisplayName | Format-Table -AutoSize",
            60,
        )
        ps_to_file(
            folder,
            "net_adapter_advanced.txt",
            "Get-NetAdapterAdvancedProperty -AllProperties -ErrorAction SilentlyContinue | "
            "Select-Object Name,DisplayName,DisplayValue,RegistryKeyword,RegistryValue | "
            "Format-Table -AutoSize",
            60,
        )


def test_server(folder: Path, host: str, port_text: str, log) -> None:
    host = host.strip()
    port_text = port_text.strip()
    if not host:
        save(folder / "target_test.txt", "VPN server not specified.\n")
        return

    log(f"  • проверка сервера {host}{':' + port_text if port_text else ''}")
    lines = [f"Target: {host}", f"Port: {port_text or '(not specified)'}", ""]

    try:
        info = socket.getaddrinfo(host, None)
        ips = sorted({entry[4][0] for entry in info})
        lines.append("DNS resolved: " + ", ".join(ips))
    except Exception as exc:
        lines.append(f"DNS resolution FAILED: {type(exc).__name__}: {exc}")

    code, out = run(["ping", "-n", "2", "-w", "1500", host], 8)
    lines.append(f"\nPING exit={code}\n{out}")

    if port_text:
        try:
            port = int(port_text)
            with socket.create_connection((host, port), timeout=5):
                lines.append(f"\nTCP {host}:{port}: CONNECTED")
        except Exception as exc:
            lines.append(
                f"\nTCP {host}:{port_text}: FAILED: {type(exc).__name__}: {exc}"
            )

        if port_text.isdigit():
            safe_host = host.replace("'", "''")
            code, out = ps(
                f"Test-NetConnection -ComputerName '{safe_host}' -Port {port_text} "
                "-InformationLevel Detailed | Format-List *",
                15,
            )
            lines.append(f"\nTest-NetConnection exit={code}\n{out}")

    save(folder / "target_test.txt", "\n".join(lines) + "\n")


def collect_events(folder: Path, minutes: int, log) -> None:
    channels = {
        "System": "events_system.txt",
        "Application": "events_application.txt",
        "Microsoft-Windows-RasClient/Operational": "events_rasclient.txt",
        "Microsoft-Windows-NetworkProfile/Operational": "events_networkprofile.txt",
        "Microsoft-Windows-WLAN-AutoConfig/Operational": "events_wlan.txt",
    }
    ms = max(1, minutes) * 60 * 1000
    query = f"*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    for channel, filename in channels.items():
        log("  • Event Log: " + channel)
        command_to_file(
            folder,
            filename,
            [
                "wevtutil", "qe", channel,
                f"/q:{query}", "/f:text", "/rd:true", "/c:250"
            ],
            60,
        )


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def adapter_map(value) -> dict[str, dict]:
    result = {}
    for item in as_list(value):
        if isinstance(item, dict):
            name = str(
                item.get("Name")
                or item.get("InterfaceDescription")
                or item.get("ifIndex")
                or "?"
            )
            result[name] = item
    return result


def route_set(value) -> set[tuple[str, str, str, str, str]]:
    result = set()
    for item in as_list(value):
        if isinstance(item, dict) and "DestinationPrefix" in item:
            result.add((
                str(item.get("AddressFamily", "")),
                str(item.get("DestinationPrefix", "")),
                str(item.get("NextHop", "")),
                str(item.get("InterfaceAlias", "")),
                str(item.get("RouteMetric", "")),
            ))
    return result


def vpn_like(text: str) -> bool:
    value = text.lower()
    return any(word in value for word in VPN_WORDS)


def create_diffs(session: Path, before: Path, after: Path) -> None:
    names = [
        "ipconfig_all.txt", "route_print.txt", "adapters.json", "routes.json",
        "dns.json", "ip_interfaces.json", "vpn_connections.json",
        "connection_profiles.json", "services.txt", "vpn_processes.txt",
        "winhttp_proxy.txt", "user_proxy.txt",
    ]
    out_dir = session / "diff"
    out_dir.mkdir(exist_ok=True)

    for name in names:
        old = before / name
        new = after / name
        if not old.exists() or not new.exists():
            continue
        a = old.read_text(encoding="utf-8", errors="replace").splitlines()
        b = new.read_text(encoding="utf-8", errors="replace").splitlines()
        diff = "\n".join(difflib.unified_diff(
            a, b,
            fromfile=f"before/{name}",
            tofile=f"after/{name}",
            lineterm="",
        ))
        save(
            out_dir / f"{name}.diff.txt",
            diff + ("\n" if diff else "No differences.\n")
        )


def build_summary(
    before: Path,
    after: Path,
    started: dt.datetime,
    host: str,
    port: str,
) -> str:
    observations: list[str] = []

    b_adapters = adapter_map(load_json(before / "adapters.json"))
    a_adapters = adapter_map(load_json(after / "adapters.json"))

    for name in sorted(set(a_adapters) - set(b_adapters)):
        item = a_adapters[name]
        observations.append(
            f"[+] New adapter: {name} | status={item.get('Status')} | "
            f"{item.get('InterfaceDescription', '')}"
        )

    for name in sorted(set(a_adapters) & set(b_adapters)):
        old = str(b_adapters[name].get("Status"))
        new = str(a_adapters[name].get("Status"))
        if old != new:
            observations.append(f"[*] Adapter state changed: {name}: {old} -> {new}")

    vpn_adapters = []
    for name, item in a_adapters.items():
        search = (
            name + " "
            + str(item.get("InterfaceDescription", "")) + " "
            + str(item.get("DriverDescription", ""))
        )
        if vpn_like(search):
            vpn_adapters.append(
                f"{name} [{item.get('Status')}] "
                f"{item.get('InterfaceDescription', '')}"
            )

    if vpn_adapters:
        observations.append(
            "[*] VPN/TUN/TAP/Wintun-like adapters: " + "; ".join(vpn_adapters)
        )
    else:
        observations.append(
            "[!] No obvious VPN/TUN/TAP/Wintun adapter found after the attempt."
        )

    old_routes = route_set(load_json(before / "routes.json"))
    new_routes = route_set(load_json(after / "routes.json"))
    added = sorted(new_routes - old_routes)
    removed = sorted(old_routes - new_routes)
    observations.append(f"[*] Routes changed: +{len(added)} / -{len(removed)}")

    new_defaults = [r for r in added if r[1] in ("0.0.0.0/0", "::/0")]
    old_defaults = [r for r in removed if r[1] in ("0.0.0.0/0", "::/0")]
    if new_defaults:
        observations.append("[+] New default route(s): " + "; ".join(map(str, new_defaults)))
    if old_defaults:
        observations.append("[-] Default route(s) removed: " + "; ".join(map(str, old_defaults)))

    target = ""
    target_path = after / "target_test.txt"
    if target_path.exists():
        target = target_path.read_text(encoding="utf-8", errors="replace")
    if "DNS resolution FAILED" in target:
        observations.append("[!] DNS resolution of the VPN server failed.")
    if re.search(r"TCP .*: FAILED", target):
        observations.append("[!] TCP connection to the specified server/port failed.")
    if re.search(r"TCP .*: CONNECTED", target):
        observations.append("[+] TCP connection to the specified server/port succeeded.")

    ras_path = after / "events_rasclient.txt"
    if ras_path.exists():
        ras = ras_path.read_text(encoding="utf-8", errors="replace")
        if "Event ID:" in ras:
            observations.append(
                "[*] RasClient events were found. Check events_rasclient.txt."
            )

    lines = [
        f"{APP_NAME} {APP_VERSION}",
        f"Session started: {started.isoformat(timespec='seconds')}",
        f"Report created: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"Administrator: {is_admin()}",
        f"Target: {host.strip() or '(not specified)'}"
        + (":" + port.strip() if port.strip() else ""),
        "",
        "=== Automatic observations ===",
        *observations,
        "",
        "=== Added routes (max 80) ===",
        *[str(x) for x in added[:80]],
        "",
        "=== Removed routes (max 80) ===",
        *[str(x) for x in removed[:80]],
        "",
        "=== Privacy ===",
        "No packet contents, passwords, VPN keys or tokens are captured.",
        "MAC addresses and Windows account names in C:\\Users\\... are redacted.",
        "IP addresses, routes, interface names and the entered VPN target are kept.",
    ]
    return "\n".join(lines) + "\n"


def make_zip(session: Path) -> Path:
    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / f"VPN_Diagnostic_{session.name}.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in session.rglob("*"):
            if item.is_file():
                zf.write(item, item.relative_to(session))
    return path


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("860x630")
        self.minsize(760, 560)

        self.session: Path | None = None
        self.started: dt.datetime | None = None
        self.busy = False

        self.host_var = tk.StringVar()
        self.port_var = tk.StringVar()
        self.deep_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(
            value="Готово. Перед первым снимком VPN должен быть отключён."
        )

        self.build_ui()
        REPORTS.mkdir(parents=True, exist_ok=True)

        self.log(f"{APP_NAME} {APP_VERSION}")
        self.log("Администратор: " + ("ДА" if is_admin() else "НЕТ"))
        if not is_admin():
            self.log(
                "Лучше запустить от имени администратора: иначе часть данных "
                "драйверов и Event Log может быть недоступна."
            )

    def build_ui(self) -> None:
        frame = ttk.Frame(self, padding=14)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text="Диагностика подключения VPN",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            frame,
            text=(
                "Ничего в Windows не исправляет и не меняет. "
                "Снимает состояние сети ДО и ПОСЛЕ попытки VPN."
            ),
            wraplength=810,
        ).pack(anchor="w", pady=(4, 12))

        target = ttk.LabelFrame(frame, text="VPN-сервер — необязательно", padding=10)
        target.pack(fill="x")
        ttk.Label(target, text="Домен/IP:").grid(row=0, column=0, sticky="w")
        ttk.Entry(target, textvariable=self.host_var, width=42).grid(
            row=0, column=1, padx=(8, 18), sticky="ew"
        )
        ttk.Label(target, text="Порт:").grid(row=0, column=2, sticky="w")
        ttk.Entry(target, textvariable=self.port_var, width=10).grid(
            row=0, column=3, padx=(8, 0), sticky="w"
        )
        target.columnconfigure(1, weight=1)
        ttk.Checkbutton(
            target,
            text="Глубокая диагностика драйверов и Winsock",
            variable=self.deep_var,
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 0))

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=12)

        self.before_btn = ttk.Button(
            buttons, text="1. Снять состояние ДО", command=self.before_click
        )
        self.before_btn.pack(side="left", padx=(0, 8))

        self.after_btn = ttk.Button(
            buttons,
            text="2. VPN не подключился — собрать ПОСЛЕ",
            command=self.after_click,
        )
        self.after_btn.pack(side="left", padx=(0, 8))

        ttk.Button(
            buttons, text="Открыть отчёты", command=self.open_reports
        ).pack(side="right")

        ttk.Label(
            frame,
            textvariable=self.status_var,
            font=("Segoe UI", 10, "bold"),
            wraplength=810,
        ).pack(anchor="w", pady=(0, 8))

        box = ttk.LabelFrame(frame, text="Ход диагностики", padding=6)
        box.pack(fill="both", expand=True)
        self.text = tk.Text(
            box, wrap="word", state="disabled", font=("Consolas", 9)
        )
        scroll = ttk.Scrollbar(box, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def log(self, message: str) -> None:
        def append():
            self.text.configure(state="normal")
            self.text.insert(
                "end",
                f"[{dt.datetime.now().strftime('%H:%M:%S')}] {message}\n"
            )
            self.text.see("end")
            self.text.configure(state="disabled")
        self.after(0, append)

    def set_busy(self, value: bool, status: str) -> None:
        self.busy = value

        def apply():
            state = "disabled" if value else "normal"
            self.before_btn.configure(state=state)
            self.after_btn.configure(state=state)
            self.status_var.set(status)
        self.after(0, apply)

    def before_click(self) -> None:
        if self.busy:
            return
        deep = bool(self.deep_var.get())
        host = self.host_var.get()
        port = self.port_var.get()
        threading.Thread(
            target=self.before_worker,
            args=(deep, host, port),
            daemon=True,
        ).start()

    def before_worker(self, deep: bool, host: str, port: str) -> None:
        try:
            self.set_busy(True, "Собираю состояние ДО...")
            self.started = dt.datetime.now()
            self.session = REPORTS / self.started.strftime("%Y%m%d_%H%M%S")
            before = self.session / "before"

            self.log("Снимок ДО: начало.")
            collect_snapshot(before, deep, self.log)
            test_server(before, host, port, self.log)

            self.log(
                "Снимок ДО готов. Теперь подключайте VPN и дождитесь ошибки."
            )
            self.set_busy(
                False,
                "ДО готово. Попробуйте подключить VPN, дождитесь ошибки "
                "и нажмите кнопку №2.",
            )
        except Exception:
            self.log(traceback.format_exc())
            self.set_busy(False, "Ошибка при сборе состояния ДО.")
            self.after(
                0,
                lambda: messagebox.showerror(
                    APP_NAME,
                    "Ошибка при сборе состояния ДО. Подробности в окне программы.",
                ),
            )

    def after_click(self) -> None:
        if self.busy:
            return
        if not self.session or not self.started or not (self.session / "before").exists():
            messagebox.showwarning(
                APP_NAME, "Сначала нажмите «1. Снять состояние ДО»."
            )
            return

        deep = bool(self.deep_var.get())
        host = self.host_var.get()
        port = self.port_var.get()

        threading.Thread(
            target=self.after_worker,
            args=(deep, host, port),
            daemon=True,
        ).start()

    def after_worker(self, deep: bool, host: str, port: str) -> None:
        try:
            assert self.session is not None
            assert self.started is not None

            self.set_busy(True, "Собираю состояние ПОСЛЕ и события Windows...")
            before = self.session / "before"
            after = self.session / "after"

            self.log("Снимок ПОСЛЕ: начало.")
            collect_snapshot(after, deep, self.log)
            test_server(after, host, port, self.log)

            elapsed_minutes = max(
                1,
                int((dt.datetime.now() - self.started).total_seconds() / 60) + 2,
            )
            collect_events(after, elapsed_minutes, self.log)

            self.log("Сравниваю состояние ДО/ПОСЛЕ...")
            create_diffs(self.session, before, after)
            save(
                self.session / "summary.txt",
                build_summary(before, after, self.started, host, port),
            )

            self.log("Создаю ZIP...")
            archive = make_zip(self.session)
            self.log("ГОТОВО: " + str(archive))
            self.set_busy(False, "Готово: " + archive.name)

            self.after(
                0,
                lambda: messagebox.showinfo(
                    APP_NAME,
                    "Диагностика завершена.\n\n"
                    f"Архив:\n{archive}\n\n"
                    "Пришлите этот ZIP в чат для анализа.",
                ),
            )
        except Exception:
            self.log(traceback.format_exc())
            self.set_busy(False, "Ошибка при сборе состояния ПОСЛЕ.")
            self.after(
                0,
                lambda: messagebox.showerror(
                    APP_NAME,
                    "Ошибка при завершении диагностики. Подробности в окне программы.",
                ),
            )

    def open_reports(self) -> None:
        REPORTS.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(REPORTS)  # type: ignore[attr-defined]


if __name__ == "__main__":
    if os.name != "nt":
        raise SystemExit("VPN Diagnostic is intended for Windows 10/11.")
    App().mainloop()
