# RAT Guard Ultimate (v2.0 XWorm & RAT Enhanced Edition)
# Advanced Behavioral Analysis & TCP/Process Intelligence for Windows

import csv
import ctypes
import hashlib
import ipaddress
import json
import os
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime


def ensure_admin():
    """Relaunch this script with Windows UAC elevation when needed."""
    if os.name != "nt":
        return

    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
    except Exception as exc:
        ctypes.windll.user32.MessageBoxW(
            None,
            f"تعذّر التحقق من صلاحيات المسؤول: {exc}",
            "RAT Guard Ultimate",
            0x10,
        )
        raise SystemExit(1)

    try:
        if getattr(sys, "frozen", False):
            executable = sys.executable
            parameters = subprocess.list2cmdline(sys.argv[1:])
            working_dir = os.path.dirname(executable)
        else:
            script_path = os.path.abspath(sys.argv[0])
            executable = sys.executable
            parameters = subprocess.list2cmdline([script_path, *sys.argv[1:]])
            working_dir = os.path.dirname(script_path)

        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        shell_execute = shell32.ShellExecuteW
        shell_execute.argtypes = (
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int,
        )
        shell_execute.restype = ctypes.c_void_p
        result = shell_execute(None, "runas", executable, parameters, working_dir, 1)

        if result and int(result) > 32:
            raise SystemExit(0)

        shell_error = int(result or 0)
        error_text = "تم رفض طلب صلاحيات المسؤول أو إلغاء نافذة UAC." if shell_error == 5 else f"تعذّر طلب صلاحيات المسؤول. رمز الكود: {shell_error}"

        ctypes.windll.user32.MessageBoxW(
            None,
            error_text,
            "RAT Guard Ultimate",
            0x10,
        )
        raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as exc:
        ctypes.windll.user32.MessageBoxW(
            None,
            f"فشل طلب صلاحيات المسؤول: {exc}",
            "RAT Guard Ultimate",
            0x10,
        )
        raise SystemExit(1)


ensure_admin()

APP_NAME = "RAT Guard Ultimate v3"
RULE_PREFIX = "RATGuardUlt-"

# These ports are clues only; no port is proof of malware by itself.
RAT_KNOWN_PORTS = {
    7000, 8000, 8888, 7777, 6666, 5552, 1604, 200, 2001, 2002,
    4899, 4444, 1337, 31337, 1234, 1235, 4321, 54321, 27015, 2710,
    5050, 8282, 3060, 3070, 4040
}
COMMON_PORTS = {53, 80, 123, 443, 853, 3389}
SUSPICIOUS_PATHS = (
    "\\appdata\\roaming\\", "\\appdata\\local\\temp\\", "\\appdata\\local\\",
    "\\downloads\\", "\\desktop\\", "\\public\\", "\\programdata\\"
)
KNOWN_BROWSERS = ("chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe", "discord.exe", "steam.exe")
SPECIFIC_RAT_MARKERS = ("xworm", "wormexploit", "asyncrat", "njrat", "remcos", "darkcomet", "nanocore", "quasar", "warzone")
GENERIC_SUSPICIOUS_MARKERS = ("worm", "payload", "stub")


def run_cmd(args, timeout=15):
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="mbcs" if os.name == "nt" else "utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=creationflags,
        check=False,
    )


def run_powershell(script, timeout=25):
    return run_cmd(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout=timeout,
    )


def parse_endpoint(value):
    value = value.strip()
    if value in ("*:*", "-*", "*"):
        return "*", "*"
    if value.startswith("[") and "]:" in value:
        addr, port = value[1:].rsplit("]:", 1)
    elif ":" in value:
        addr, port = value.rsplit(":", 1)
    else:
        return value, "?"
    return addr, port


def load_tasklist_names():
    names = {}
    result = run_cmd(["tasklist.exe", "/FO", "CSV", "/NH"], timeout=15)
    if result.returncode == 0:
        for row in csv.reader(result.stdout.splitlines()):
            if len(row) >= 2:
                try:
                    names[int(row[1])] = row[0]
                except ValueError:
                    pass
    return names


def load_process_details(pids):
    if not pids:
        return {}
    pid_list = ",".join(str(int(pid)) for pid in sorted(set(pids)))
    ps = (
        f"$ids = @({pid_list}); "
        "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
        "Where-Object { $ids -contains [int]$_.ProcessId } | "
        "Select-Object ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
    )
    result = run_powershell(ps, timeout=18)
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    try:
        data = json.loads(result.stdout.strip())
        if isinstance(data, dict):
            data = [data]
        return {int(item.get("ProcessId")): item for item in data if item.get("ProcessId") is not None}
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}


def is_public_ip(address):
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        return ip.is_global
    except ValueError:
        return False


def suspicious_outbound_candidates(rows):
    candidates = {}
    for row in rows:
        if row.get("level") != "danger" or row.get("score", 0) < 70:
            continue
        protocol = str(row.get("protocol", "")).upper()
        state = str(row.get("state", "")).upper()
        if protocol not in ("TCP", "UDP"):
            continue
        if state not in ("SYN_SENT", "ESTABLISHED", "UDP"):
            continue
        try:
            remote_ip = str(ipaddress.ip_address(row.get("remote_ip", "").split("%", 1)[0]))
            remote_port = int(row.get("remote_port"))
        except (AttributeError, TypeError, ValueError):
            continue
        if not is_public_ip(remote_ip) or not 1 <= remote_port <= 65535:
            continue
        key = (protocol, remote_ip, remote_port)
        candidates[key] = row
    return list(candidates.items())


def analyze_rat_behavior(remote_ip, remote_port, state, path, name, local_port="?", protocol="TCP", command=""):
    """Heuristic triage only. It must never label an unscanned process as safe."""
    lower_path = (path or "").lower().replace("/", "\\")
    lower_name = (name or "").lower()
    lower_command = (command or "").lower()
    evidence_text = " ".join((lower_name, lower_path, lower_command))
    state_upper = (state or "").upper()
    protocol_upper = (protocol or "TCP").upper()

    def as_port(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return -1

    rport, lport = as_port(remote_port), as_port(local_port)
    score = 0
    reasons = []

    # Process identity and path are checked even for localhost/private IPs.
    specific_hits = [marker for marker in SPECIFIC_RAT_MARKERS if marker in evidence_text]
    if specific_hits:
        score += 65
        reasons.append("اسم/مسار/سطر أوامر يحتوي مؤشراً معروفاً لعائلة RAT: " + ", ".join(specific_hits))
    elif any(marker in evidence_text for marker in GENERIC_SUSPICIOUS_MARKERS):
        score += 30
        reasons.append("اسم أو مسار يحتوي كلمة تستحق الفحص (مثل worm/payload/stub)")

    if any(marker in lower_path for marker in SUSPICIOUS_PATHS):
        score += 25
        reasons.append("الملف يعمل من مجلد قابل للكتابة مثل AppData أو Temp أو Downloads")

    # Check both remote and local ports: netstat reports a listener's port locally.
    ports_to_check = {p for p in (rport, lport) if 1 <= p <= 65535}
    known_hits = sorted(ports_to_check.intersection(RAT_KNOWN_PORTS))
    if known_hits:
        score += 45
        reasons.append("منفذ شائع في بعض أدوات RAT/C2 (ليس دليلاً منفرداً): " + ", ".join(map(str, known_hits)))

    # Classify address without treating localhost/private ranges as evidence of safety.
    address_note = ""
    try:
        ip_obj = ipaddress.ip_address((remote_ip or "").split("%", 1)[0])
        if ip_obj.is_loopback:
            address_note = "الاتصال محلي (Loopback)؛ هذا لا يثبت أمان العملية"
        elif ip_obj.is_private or ip_obj.is_link_local:
            address_note = "الاتصال بعنوان خاص/محلي؛ هذا لا يثبت أمان العملية"
        elif ip_obj.is_global and state_upper == "SYN_SENT":
            score += 20
            reasons.append("محاولة اتصال صادرة إلى IP عام لم تكتمل بعد (SYN_SENT)")
        elif ip_obj.is_global and state_upper == "ESTABLISHED":
            if rport not in COMMON_PORTS and lower_name not in KNOWN_BROWSERS and not lower_path.startswith("c:\\windows\\"):
                score += 15
                reasons.append("اتصال خارجي مستمر بمنفذ غير شائع لعملية ليست متصفحاً معروفاً")
        elif not ip_obj.is_global:
            address_note = "عنوان غير عام؛ لا يمكن استنتاج الأمان منه"
    except ValueError:
        address_note = "عنوان الوجهة غير محدد أو محلي؛ لا يمكن استنتاج الأمان منه"

    if state_upper == "LISTENING" and lport not in COMMON_PORTS:
        reasons.append(f"البرنامج يستمع على منفذ محلي {lport}; تحقق من سبب فتحه")
        score += 10

    score = min(score, 100)
    if score >= 70:
        verdict = "🚨 مشتبه بقوة — اعزل العملية وافحص الملف"
        level = "danger"
    elif score >= 35:
        verdict = "⚠️ مريب — يحتاج تحققاً إضافياً"
        level = "warning"
    else:
        verdict = "🟡 غير محسوم — لا توجد أدلة كافية للحكم بالأمان"
        level = "uncertain"

    if address_note:
        reasons.append(address_note)
    if not reasons:
        reasons.append("لم تظهر مؤشرات ضمن القواعد الحالية؛ هذه ليست شهادة بأن الملف آمن")
    return verdict, score, " | ".join(reasons), level


def collect_connections():
    result = run_cmd(["netstat.exe", "-ano"], timeout=15)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "تعذّر تشغيل netstat")

    parsed = []
    pids = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].upper() not in ("TCP", "UDP"):
            continue
        protocol = parts[0].upper()
        local, remote = parts[1], parts[2]
        if protocol == "TCP":
            if len(parts) < 5:
                continue
            state, pid_text = parts[3], parts[4]
        else:
            state, pid_text = "UDP", parts[3]
        try:
            pid = int(pid_text)
        except ValueError:
            continue
        local_ip, local_port = parse_endpoint(local)
        remote_ip, remote_port = parse_endpoint(remote)
        pids.add(pid)
        parsed.append((protocol, local_ip, local_port, remote_ip, remote_port, state, pid))

    names = load_tasklist_names()
    details = load_process_details(pids)
    rows = []
    for protocol, local_ip, local_port, remote_ip, remote_port, state, pid in parsed:
        info = details.get(pid, {})
        name = names.get(pid, "غير معروف")
        path = info.get("ExecutablePath") or ""
        command = info.get("CommandLine") or ""
        verdict, score, reasons, level = analyze_rat_behavior(
            remote_ip, remote_port, state, path, name, local_port, protocol, command
        )
        rows.append({
            "protocol": protocol,
            "local": f"{local_ip}:{local_port}",
            "remote": f"{remote_ip}:{remote_port}",
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "local_port": local_port,
            "state": state,
            "pid": pid,
            "name": name,
            "path": path,
            "command": command,
            "verdict": verdict,
            "score": score,
            "reasons": reasons,
            "level": level,
        })
    rows.sort(key=lambda x: (x["score"], x["name"].lower()), reverse=True)
    return rows


class RATGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} — تحليل الـ RAT ومراقبة السلوك")
        self.root.geometry("1480x900")
        self.root.minsize(1120, 700)
        self.root.configure(bg="#0d1117")
        
        self.rows_by_id = {}
        self.all_rows = []
        self.worker_busy = False
        self.events = queue.Queue()
        self.auto_refresh = tk.BooleanVar(value=True)
        self.auto_block_suspicious = tk.BooleanVar(value=False)
        self.auto_blocked_endpoints = set()
        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="الكل")
        self.status_var = tk.StringVar(value="جاهز — المراقبة السلوكية تعمل")
        self.summary_vars = {
            "total": tk.StringVar(value="0"),
            "danger": tk.StringVar(value="0"),
            "warning": tk.StringVar(value="0"),
            "unknown": tk.StringVar(value="0"),
        }
        
        self._build_ui()
        self.root.after(250, self._process_events)
        self.refresh()
        self.root.after(8000, self._auto_tick)

    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=30, font=("Segoe UI", 9), background="#111827", fieldbackground="#111827", foreground="#e5e7eb", borderwidth=0)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), background="#1f2937", foreground="#93c5fd", padding=(8, 8))
        style.map("Treeview", background=[("selected", "#1d4ed8")], foreground=[("selected", "#ffffff")])
        style.configure("TCombobox", fieldbackground="#111827", background="#1f2937", foreground="#e5e7eb")

        header = tk.Frame(self.root, bg="#0b1220", padx=20, pady=16)
        header.pack(fill="x")
        tk.Label(header, text="🛡️ RAT GUARD ULTIMATE", fg="#e5e7eb", bg="#0b1220", font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(header, text="مراقبة TCP / UDP • ربط الاتصالات بالعمليات • تقييم أولي لمؤشرات RAT", fg="#93c5fd", bg="#0b1220", font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))
        tk.Label(header, text="تنبيه: (غير محسوم) لا تعني آمن. هذه أداة فرز سلوكي وليست مضاد فيروسات ولا تكشف كل RAT.", fg="#fbbf24", bg="#0b1220", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(7, 0))

        cards = tk.Frame(self.root, bg="#0d1117", padx=14, pady=10)
        cards.pack(fill="x")
        self._summary_card(cards, "كل الاتصالات", self.summary_vars["total"], "#93c5fd").pack(side="left", fill="x", expand=True, padx=4)
        self._summary_card(cards, "اشتباه مرتفع", self.summary_vars["danger"], "#f87171").pack(side="left", fill="x", expand=True, padx=4)
        self._summary_card(cards, "يحتاج تحقق", self.summary_vars["warning"], "#fbbf24").pack(side="left", fill="x", expand=True, padx=4)
        self._summary_card(cards, "غير محسوم", self.summary_vars["unknown"], "#a5b4fc").pack(side="left", fill="x", expand=True, padx=4)

        toolbar = tk.Frame(self.root, bg="#161b22", padx=10, pady=8, highlightbackground="#30363d", highlightthickness=1)
        toolbar.pack(fill="x", padx=14, pady=(0, 5))
        self._button(toolbar, "↻ تحديث", self.refresh, color="#1d4ed8").pack(side="left", padx=3)
        self._button(toolbar, "إنهاء العملية", self.kill_selected_process, color="#7f1d1d").pack(side="left", padx=3)
        self._button(toolbar, "حظر IP والمنفذ", self.block_selected, color="#991b1b").pack(side="left", padx=3)
        self._button(toolbar, "حظر ملف البرنامج", self.block_selected_program, color="#7f1d1d").pack(side="left", padx=3)
        self._button(toolbar, "حظر IP يدوي", self.block_custom_ip, color="#374151").pack(side="left", padx=3)

        toolbar2 = tk.Frame(self.root, bg="#161b22", padx=10, pady=7, highlightbackground="#30363d", highlightthickness=1)
        toolbar2.pack(fill="x", padx=14, pady=(0, 5))
        self._button(toolbar2, "فحص Defender", self.scan_file, color="#374151").pack(side="left", padx=3)
        self._button(toolbar2, "حالة Defender", self.check_defender_status, color="#374151").pack(side="left", padx=3)
        self._button(toolbar2, "فحص توقيع/هاش الملف", self.check_selected_file, color="#374151").pack(side="left", padx=3)
        self._button(toolbar2, "تصدير CSV", self.export_csv, color="#374151").pack(side="left", padx=3)
        self._button(toolbar2, "إزالة قواعد RAT Guard", self.unblock_rule, color="#374151").pack(side="left", padx=3)
        tk.Checkbutton(
            toolbar2,
            text="حظر تلقائي للمشبوه (IP:منفذ)",
            variable=self.auto_block_suspicious,
            command=self._toggle_auto_block,
            fg="#fca5a5",
            bg="#161b22",
            selectcolor="#1f2937",
            activebackground="#161b22",
            activeforeground="#fca5a5",
            font=("Segoe UI", 9, "bold"),
        ).pack(side="right", padx=6)
        tk.Checkbutton(toolbar2, text="تحديث تلقائي كل 8 ثوانٍ", variable=self.auto_refresh, fg="#cbd5e1", bg="#161b22", selectcolor="#1f2937", activebackground="#161b22", activeforeground="#93c5fd", font=("Segoe UI", 9)).pack(side="right", padx=6)

        filter_frame = tk.Frame(self.root, bg="#0d1117", padx=14, pady=6)
        filter_frame.pack(fill="x")
        tk.Label(filter_frame, text="بحث:", bg="#0d1117", fg="#cbd5e1", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 6))
        search_entry = tk.Entry(filter_frame, textvariable=self.search_var, bg="#111827", fg="#e5e7eb", insertbackground="#ffffff", relief="flat", font=("Segoe UI", 10), width=34)
        search_entry.pack(side="left", ipady=6, padx=(0, 12))
        search_entry.insert(0, "")
        tk.Label(filter_frame, text="عرض:", bg="#0d1117", fg="#cbd5e1", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 6))
        filter_box = ttk.Combobox(filter_frame, textvariable=self.filter_var, state="readonly", width=20, values=("الكل", "اشتباه مرتفع", "يحتاج تحقق", "غير محسوم"))
        filter_box.pack(side="left")
        filter_box.bind("<<ComboboxSelected>>", lambda _e: self._apply_filters())
        self.search_var.trace_add("write", lambda *_: self._apply_filters())

        table_frame = tk.Frame(self.root, bg="#0d1117")
        table_frame.pack(fill="both", expand=True, padx=14, pady=5)
        columns = ("verdict", "protocol", "name", "pid", "state", "remote", "local", "path")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "verdict": "نتيجة الفحص الأولي",
            "protocol": "البروتوكول",
            "name": "العملية",
            "pid": "PID",
            "state": "الحالة",
            "remote": "عنوان الوجهة",
            "local": "العنوان المحلي",
            "path": "مسار الملف",
        }
        widths = {"verdict": 300, "protocol": 78, "name": 130, "pid": 65, "state": 95, "remote": 175, "local": 175, "path": 360}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], minwidth=65, anchor="w", stretch=(col == "path"))
        self.tree.tag_configure("danger", background="#451a1a", foreground="#fecaca")
        self.tree.tag_configure("warning", background="#3f2e12", foreground="#fde68a")
        self.tree.tag_configure("uncertain", background="#172554", foreground="#bfdbfe")
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", self.show_selection)

        details_frame = tk.Frame(self.root, bg="#0d1117", padx=14, pady=5)
        details_frame.pack(fill="x")
        tk.Label(details_frame, text="تفاصيل الاتصال المحدد", bg="#0d1117", fg="#93c5fd", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.details = tk.Text(details_frame, height=5, wrap="word", bg="#111827", fg="#e5e7eb", insertbackground="#93c5fd", relief="flat", font=("Consolas", 9))
        self.details.pack(fill="x", pady=(5, 6))
        self.details.insert("1.0", "اختر اتصالاً من الجدول لعرض اسم العملية ومسارها ومؤشرات الاشتباه.")
        self.details.configure(state="disabled")

        footer = tk.Frame(self.root, bg="#0b1220", padx=14, pady=8)
        footer.pack(fill="x")
        tk.Label(footer, textvariable=self.status_var, bg="#0b1220", fg="#93c5fd", font=("Segoe UI", 9), anchor="w").pack(side="left", fill="x", expand=True)
        tk.Label(footer, text="Behavioral triage only • not a clean-file certificate", bg="#0b1220", fg="#94a3b8", font=("Segoe UI", 8)).pack(side="right")

    def _summary_card(self, parent, title, value_var, accent):
        card = tk.Frame(parent, bg="#161b22", padx=14, pady=9, highlightbackground="#30363d", highlightthickness=1)
        tk.Label(card, text=title, bg="#161b22", fg="#9ca3af", font=("Segoe UI", 9)).pack(anchor="w")
        tk.Label(card, textvariable=value_var, bg="#161b22", fg=accent, font=("Segoe UI", 21, "bold")).pack(anchor="w")
        return card

    def _button(self, parent, text, command, color="#21262d", fg="white"):
        return tk.Button(
            parent, text=text, command=command, bg=color, fg=fg, 
            activebackground="#30363d", activeforeground="#FFD700", 
            relief="flat", padx=10, pady=6, font=("Segoe UI", 9, "bold"), cursor="hand2"
        )

    def refresh(self):
        if self.worker_busy:
            return
        self.worker_busy = True
        auto_block_enabled = self.auto_block_suspicious.get()
        self.status_var.set("⏳ جاري تحليل شبكة النظام وسلوك العمليات...")

        def work():
            try:
                data = collect_connections()
            except Exception as exc:
                self.events.put(("error", str(exc)))
                return

            blocked_count = 0
            auto_block_error = ""
            if auto_block_enabled:
                try:
                    blocked_count = self._auto_block_suspicious(data)
                except Exception as exc:
                    auto_block_error = str(exc)
            for key, row in suspicious_outbound_candidates(data):
                if key in self.auto_blocked_endpoints:
                    row["auto_blocked"] = True
            self.events.put(("refresh_ok", (data, blocked_count, auto_block_error)))
        threading.Thread(target=work, daemon=True).start()

    def _toggle_auto_block(self):
        if not self.auto_block_suspicious.get():
            self.status_var.set("الحظر التلقائي متوقف.")
            return
        confirmed = messagebox.askyesno(
            APP_NAME,
            "سيُنشئ البرنامج قواعد Windows Firewall للاتصالات الصادرة عالية الاشتباه "
            "(درجة 70 فأكثر) إلى عناوين IP عامة، ويقيّدها بالبروتوكول والمنفذ المرصود.\n\n"
            "الفحص كل 8 ثوانٍ عند تفعيل التحديث التلقائي، أو عند التحديث اليدوي؛ "
            "لذلك قد لا يمنع أول محاولة. "
            "لا يقرأ البرنامج اسم النطاق؛ الحظر يكون على IP وقد يؤثر في نطاقات أخرى "
            "تشاركه. هل تريد تفعيل ذلك؟",
        )
        if not confirmed:
            self.auto_block_suspicious.set(False)
            return
        self.status_var.set("الحظر التلقائي للاتصالات عالية الاشتباه مفعّل.")
        self.refresh()

    def _auto_block_suspicious(self, rows):
        candidates = [
            (key, row)
            for key, row in suspicious_outbound_candidates(rows)
            if key not in self.auto_blocked_endpoints
        ]
        if not candidates:
            return 0

        entries = []
        for (protocol, remote_ip, remote_port), _row in candidates:
            digest = hashlib.sha256(
                f"{protocol}:{remote_ip}:{remote_port}".encode()
            ).hexdigest()[:12]
            name = self._ps_quote(f"{RULE_PREFIX}AutoEndpoint-{digest}")
            address = self._ps_quote(remote_ip)
            entries.append(
                f"@{{Name={name}; Address={address}; Port={remote_port}; Protocol='{protocol}'}}"
            )
        script = (
            f"$items = @({';'.join(entries)}); "
            "foreach ($item in $items) { "
            "$n=$item.Name; "
            "Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -ErrorAction Stop; "
            "New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block "
            "-Protocol $item.Protocol -RemoteAddress $item.Address -RemotePort $item.Port "
            "-Profile Any -Enabled True -ErrorAction Stop | Out-Null "
            "}; Write-Output 'RATGUARD_OK'"
        )
        result = run_powershell(script, timeout=35)
        if result.returncode != 0 or "RATGUARD_OK" not in result.stdout:
            detail = (result.stderr or result.stdout or "فشل تنفيذ قواعد الحظر.").strip()
            raise RuntimeError(detail)

        for key, row in candidates:
            self.auto_blocked_endpoints.add(key)
            row["auto_blocked"] = True
        return len(candidates)

    def _auto_tick(self):
        if self.auto_refresh.get():
            self.refresh()
        self.root.after(8000, self._auto_tick)

    def _process_events(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "refresh_ok":
                    self.worker_busy = False
                    rows, blocked_count, auto_block_error = payload
                    self._fill_table(rows)
                    status = f"✅ آخر تحليل: {datetime.now().strftime('%H:%M:%S')} — تم فحص {len(rows)} اتصال."
                    if blocked_count:
                        status += f" — أُنشئت قواعد حظر تلقائية لـ {blocked_count} وجهة عالية الاشتباه."
                    self.status_var.set(status)
                    if auto_block_error:
                        self.events.put(("warning", f"تعذّر الحظر التلقائي: {auto_block_error}"))
                elif kind == "error":
                    self.worker_busy = False
                    self.status_var.set("❌ حدث خطأ أثناء التحليل")
                    messagebox.showerror(APP_NAME, payload)
                elif kind == "message":
                    messagebox.showinfo(APP_NAME, payload)
                elif kind == "warning":
                    messagebox.showwarning(APP_NAME, payload)
                elif kind == "defender_status":
                    messagebox.showinfo(APP_NAME, payload)
        except queue.Empty:
            pass
        self.root.after(250, self._process_events)

    def _fill_table(self, rows):
        self.all_rows = list(rows)
        danger = sum(1 for row in rows if row.get("level") == "danger")
        warning = sum(1 for row in rows if row.get("level") == "warning")
        unknown = len(rows) - danger - warning
        self.summary_vars["total"].set(str(len(rows)))
        self.summary_vars["danger"].set(str(danger))
        self.summary_vars["warning"].set(str(warning))
        self.summary_vars["unknown"].set(str(unknown))
        self._apply_filters()

    def _apply_filters(self):
        if not hasattr(self, "tree"):
            return
        query = self.search_var.get().strip().lower()
        selected_filter = self.filter_var.get()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.rows_by_id.clear()

        for row in self.all_rows:
            level = row.get("level", "uncertain")
            if selected_filter == "اشتباه مرتفع" and level != "danger":
                continue
            if selected_filter == "يحتاج تحقق" and level != "warning":
                continue
            if selected_filter == "غير محسوم" and level != "uncertain":
                continue
            searchable = " ".join(str(row.get(k, "")) for k in ("name", "pid", "remote", "local", "path", "command", "reasons", "protocol")).lower()
            if query and query not in searchable:
                continue
            iid = self.tree.insert(
                "", "end",
                values=(row["verdict"], row.get("protocol", "TCP"), row["name"], row["pid"], row["state"], row["remote"], row["local"], row["path"]),
                tags=(level,)
            )
            self.rows_by_id[iid] = row

    def export_csv(self):
        if not self.all_rows:
            messagebox.showinfo(APP_NAME, "لا توجد اتصالات لتصديرها.")
            return
        path = filedialog.asksaveasfilename(
            title="حفظ تقرير الاتصالات", defaultextension=".csv",
            filetypes=[("CSV", "*.csv")], initialfile="RATGuard_connections.csv"
        )
        if not path:
            return
        fields = ("protocol", "name", "pid", "state", "local", "remote", "score", "level", "verdict", "reasons", "path", "command", "auto_blocked")
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(self.all_rows)
            messagebox.showinfo(APP_NAME, f"تم حفظ التقرير:\n{path}")
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"تعذّر حفظ التقرير:\n{exc}")

    def show_selection(self, _event=None):
        row = self._selected_silent()
        if not row:
            return
        text = (
            f"النتيجة: {row['verdict']}    |    المؤشر: {row['score']}/100    |    المستوى: {row.get('level', 'uncertain')}\n"
            f"البرنامج: {row['name']}    |    PID: {row['pid']}    |    البروتوكول: {row.get('protocol', 'TCP')} / {row['state']}\n"
            f"مؤشرات الشبهة: {row['reasons']}\n"
            f"الوجهة: {row['remote']}    |    المحلي: {row['local']}\n"
            f"الحظر التلقائي: {'نعم' if row.get('auto_blocked') else 'لا'}\n"
            f"المسار: {row['path'] or '(غير متاح)'}\n"
            f"سطر الأوامر: {row['command'] or '(غير متاح)'}\n"
            "مهم: النتيجة غير المحسومة لا تعني أن الملف آمن؛ استخدم Defender وفحص الملف."
        )
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _selected(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning(APP_NAME, "⚠️ يجب تحديد اتصال من الجدول أولاً.")
            return None
        return self.rows_by_id.get(selection[0])

    def _selected_silent(self):
        selection = self.tree.selection()
        return self.rows_by_id.get(selection[0]) if selection else None

    @staticmethod
    def _ps_quote(value):
        return "'" + str(value).replace("'", "''") + "'"

    @staticmethod
    def _safe_remote_ip(value):
        ip = ipaddress.ip_address(value.split("%", 1)[0])
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            raise ValueError("لا يمكن تطبيق الإجراء على عناوين Loopback أو غير صالحة.")
        return str(ip)

    def kill_selected_process(self):
        row = self._selected()
        if not row:
            return
        pid = row["pid"]
        name = row["name"]
        if pid in (0, 4) or name.lower() in ("system", "idle", "csrss.exe", "services.exe"):
            messagebox.showwarning(APP_NAME, "🛑 حماية النظام تمنع إنهاء العمليات الأساسية.")
            return
        if not messagebox.askyesno(APP_NAME, f"إنهاء العملية '{name}' (PID: {pid}) فوراً؟"):
            return
        
        result = run_cmd(["taskkill.exe", "/F", "/PID", str(pid)], timeout=10)
        if result.returncode == 0:
            messagebox.showinfo(APP_NAME, f"✅ تم إنهاء العملية {name} بنجاح.")
            self.refresh()
        else:
            messagebox.showerror(APP_NAME, f"❌ تعذّر إنهاء العملية:\n{result.stderr.strip()}")

    def block_selected(self):
        row = self._selected()
        if not row:
            return
        try:
            ip_text = self._safe_remote_ip(row["remote_ip"])
            port = int(row["remote_port"])
            protocol = row.get("protocol", "TCP").upper()
            if not 1 <= port <= 65535:
                raise ValueError("المنفذ البعيد غير صالح أو غير محدد؛ استخدم حظر IP اليدوي إذا لزم الأمر.")
        except ValueError as exc:
            messagebox.showerror(APP_NAME, str(exc) or "عنوان IP أو المنفذ غير صالح.")
            return
        rule = f"{RULE_PREFIX}Endpoint-{hashlib.sha256(f'{protocol}:{ip_text}:{port}'.encode()).hexdigest()[:12]}"
        if not messagebox.askyesno(APP_NAME, f"حظر الاتصالات الصادرة إلى {ip_text}:{port} ({protocol})؟"):
            return
        qrule, qip = self._ps_quote(rule), self._ps_quote(ip_text)
        script = (
            f"$n={qrule}; Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
            f"New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block -Protocol {protocol} -RemoteAddress {qip} -RemotePort {port} -Profile Any -Enabled True -ErrorAction Stop | Out-Null; "
            "Write-Output 'RATGUARD_OK'"
        )
        self._firewall_job(script, f"تم إنشاء قاعدة حظر للاتصال إلى {ip_text}:{port} ({protocol}).")

    def block_selected_program(self):
        row = self._selected()
        if not row:
            return
        path = row.get("path") or ""
        if not path or not os.path.isfile(path):
            messagebox.showwarning(APP_NAME, "مسار البرنامج غير متاح أو غير موجود.")
            return
        if row.get("pid") in (0, 4):
            return
        digest = hashlib.sha256(os.path.normcase(path).encode("utf-8", "replace")).hexdigest()[:12]
        base = f"{RULE_PREFIX}Prog-{digest}"
        if not messagebox.askyesno(APP_NAME, f"حظر جميع الاتصالات للبرنامج:\n\n{path}"):
            return
        qp, qout, qin = self._ps_quote(path), self._ps_quote(base + "-OUT"), self._ps_quote(base + "-IN")
        script = (
            f"$p={qp}; $o={qout}; $i={qin}; "
            "Get-NetFirewallRule -DisplayName $o -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
            "Get-NetFirewallRule -DisplayName $i -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
            "New-NetFirewallRule -DisplayName $o -Program $p -Direction Outbound -Action Block -Profile Any -Enabled True -ErrorAction Stop | Out-Null; "
            "New-NetFirewallRule -DisplayName $i -Program $p -Direction Inbound -Action Block -Profile Any -Enabled True -ErrorAction Stop | Out-Null; "
            "Write-Output 'RATGUARD_OK'"
        )
        self._firewall_job(script, f"✅ تم حظر البرنامج بنجاح:\n{path}")

    def block_custom_ip(self):
        win = tk.Toplevel(self.root)
        win.title("حظر IP أو CIDR يدوياً")
        win.configure(bg="#0d1117")
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()
        frame = tk.Frame(win, bg="#0d1117", padx=16, pady=14)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="عنوان IP أو النطاق:", bg="#0d1117", fg="#c9d1d9").grid(row=0, column=0, sticky="w", pady=(0, 4))
        ip_var = tk.StringVar()
        ip_entry = tk.Entry(frame, textvariable=ip_var, width=38, bg="#161b22", fg="#c9d1d9", insertbackground="#FFD700")
        ip_entry.grid(row=1, column=0, sticky="ew", pady=(0, 9))

        def submit():
            try:
                raw = ip_var.get().strip()
                network = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                messagebox.showerror(APP_NAME, f"عنوان غير صالح: {exc}", parent=win)
                return
            remote = str(network)
            rule = f"{RULE_PREFIX}Custom-{hashlib.sha256(remote.encode()).hexdigest()[:12]}"
            if not messagebox.askyesno(APP_NAME, f"تأكيد حظر العنوان: {remote}؟", parent=win):
                return
            win.destroy()
            script = (
                f"$n={self._ps_quote(rule)}; Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
                f"New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block -Protocol Any -RemoteAddress {self._ps_quote(remote)} -Profile Any -Enabled True -ErrorAction Stop | Out-Null; "
                "Write-Output 'RATGUARD_OK'"
            )
            self._firewall_job(script, f"✅ تم حظر العنوان {remote} بنجاح.")

        buttons = tk.Frame(frame, bg="#0d1117")
        buttons.grid(row=2, column=0, sticky="e", pady=(6, 0))
        tk.Button(buttons, text="حظر", command=submit, bg="#741212", fg="white", relief="flat", padx=16, pady=6).pack(side="left", padx=4)
        tk.Button(buttons, text="إلغاء", command=win.destroy, bg="#21262d", fg="white", relief="flat", padx=16, pady=6).pack(side="left", padx=4)
        ip_entry.focus_set()

    def unblock_rule(self):
        if not messagebox.askyesno(APP_NAME, "هل تريد إزالة كافة قواعد الحظر؟"):
            return
        script = (
            "Get-NetFirewallRule -ErrorAction SilentlyContinue | "
            "Where-Object { $_.DisplayName -like 'RATGuardUlt-*' -or $_.DisplayName -like 'RATGuard-*' } | "
            "Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
            "Write-Output 'RATGUARD_OK'"
        )
        self.auto_blocked_endpoints.clear()
        self._firewall_job(script, "🧹 تم مسح جميع القواعد المخصصة بنجاح.")

    def scan_file(self):
        path = filedialog.askopenfilename(title="اختَر ملفاً لفحصه بـ Microsoft Defender", filetypes=[("Executable files", "*.exe;*.dll;*.scr;*.com"), ("All files", "*.*")])
        if not path:
            return
        self._defender_scan(path)

    def _defender_scan(self, path):
        if not os.path.isfile(path):
            return
        safe_path = path.replace("'", "''")
        self.status_var.set("⏳ جاري الطلب من Microsoft Defender...")

        def work():
            result = run_powershell(f"Start-MpScan -ScanType CustomScan -ScanPath '{safe_path}' -ErrorAction Stop; Write-Output 'DEFENDER_OK'", timeout=90)
            if result.returncode == 0:
                self.events.put(("message", "تم تنفيذ طلب الفحص بواسطة Defender. راجع سجل الحماية في Windows Security لمعرفة نتيجة الكشف؛ بدء الفحص لا يعني أن الملف نظيف."))
            else:
                self.events.put(("warning", "تعذّر تشغيل الفحص بـ Defender. تحقق من أن الحماية مفعّلة وأن خدمة Defender تعمل."))
        threading.Thread(target=work, daemon=True).start()

    def check_defender_status(self):
        self.status_var.set("جاري التحقق من Microsoft Defender...")
        def work():
            ps = (
                "try { $s=Get-MpComputerStatus -ErrorAction Stop; "
                "[PSCustomObject]@{AMServiceEnabled=$s.AMServiceEnabled; AntivirusEnabled=$s.AntivirusEnabled; "
                "RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled; SignatureAge=$s.AntivirusSignatureAge; "
                "LastUpdated=$s.AntivirusSignatureLastUpdated} | ConvertTo-Json -Compress } "
                "catch { Write-Error $_; exit 1 }"
            )
            result = run_powershell(ps, timeout=25)
            if result.returncode != 0 or not result.stdout.strip():
                self.events.put(("warning", "تعذّر قراءة حالة Defender. تأكد أن Microsoft Defender متاح وغير معطّل بواسطة سياسة النظام."))
                return
            try:
                data = json.loads(result.stdout.strip())
                realtime = bool(data.get("RealTimeProtectionEnabled"))
                antivirus = bool(data.get("AntivirusEnabled"))
                service = bool(data.get("AMServiceEnabled"))
                verdict = "مفعّل" if realtime and antivirus and service else "معطّل أو غير مكتمل"
                report = (
                    f"حالة Microsoft Defender: {verdict}\\n\\n"
                    f"خدمة الحماية: {service}\\nمضاد الفيروسات: {antivirus}\\n"
                    f"الحماية الفورية: {realtime}\\nعمر التواقيع بالأيام: {data.get('SignatureAge', 'غير معروف')}\\n"
                    f"آخر تحديث: {data.get('LastUpdated', 'غير معروف')}\\n\\n"
                    "تنبيه: تعطيل الحماية يجعل نتائج Defender غير مفيدة كدليل على سلامة الملف."
                )
                self.events.put(("defender_status", report))
            except Exception as exc:
                self.events.put(("warning", f"تعذّر تحليل نتيجة Defender: {exc}"))
        threading.Thread(target=work, daemon=True).start()

    def check_selected_file(self):
        row = self._selected()
        if not row:
            return
        path = row["path"]
        if not path or not os.path.isfile(path):
            messagebox.showwarning(APP_NAME, "مسار الملف غير متاح.")
            return

        self.status_var.set("⏳ جاري حساب التوقيع الرقمي والهاش SHA256...")

        def work():
            try:
                digest = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        digest.update(chunk)
                safe_path = path.replace("'", "''")
                ps = f"$s=Get-AuthenticodeSignature -LiteralPath '{safe_path}'; $signer=''; if($s.SignerCertificate){{$signer=$s.SignerCertificate.Subject}}; [PSCustomObject]@{{Status=$s.Status; Signer=$signer}} | ConvertTo-Json -Compress"
                result = run_powershell(ps, timeout=30)
                status = "غير متاح"
                signer = ""
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        info = json.loads(result.stdout.strip())
                        status = str(info.get("Status", "غير معروف"))
                        signer = str(info.get("Signer", ""))
                    except json.JSONDecodeError:
                        pass
                report = f"الملف: {path}\n\nSHA256:\n{digest.hexdigest()}\n\nحالة التوقيع الرقمي: {status}\nالموقّع: {signer or 'غير موقّع (Unsigned Payload)'}"
                self.events.put(("message", report))
            except Exception as exc:
                self.events.put(("warning", f"فشل الفحص: {exc}"))
        threading.Thread(target=work, daemon=True).start()

    def _firewall_job(self, script, success_text):
        def work():
            result = run_powershell(script, timeout=35)
            if result.returncode == 0 and "RATGUARD_OK" in result.stdout:
                self.events.put(("message", success_text))
                self.refresh()
            else:
                detail = (result.stderr or result.stdout or "فشل التنفيذ.").strip()
                self.events.put(("warning", detail))
        threading.Thread(target=work, daemon=True).start()


def main():
    if os.name != "nt":
        print("RAT Guard Ultimate requires Windows 10/11.")
        return
    root = tk.Tk()
    RATGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
