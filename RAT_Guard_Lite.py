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

APP_NAME = "RAT Guard Ultimate (XWorm Edition)"
RULE_PREFIX = "RATGuardUlt-"

# Common RAT & C2 Ports (XWorm, AsyncRAT, njRAT, DarkComet, Remcos, Venom)
RAT_KNOWN_PORTS = {
    7000, 8000, 8888, 7777, 6666, 5552, 1604, 200, 2001, 2002, 
    4899, 4444, 1337, 31337, 1234, 1235, 4321, 54321, 27015, 2710, 
    5050, 8282, 3060, 3070, 4040
}
COMMON_PORTS = {53, 80, 123, 443, 853, 3389}

# Typical execution paths for auto-dropped payloads like XWorm & njRAT
SUSPICIOUS_PATHS = (
    "\\appdata\\roaming\\", "\\appdata\\local\\temp\\", "\\appdata\\local\\",
    "\\downloads\\", "\\desktop\\", "\\public\\", "\\programdata\\"
)

KNOWN_BROWSERS = ("chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe", "discord.exe", "steam.exe")


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


def analyze_rat_behavior(remote_ip, remote_port, state, path, name):
    """Behavioral Analysis Engine specifically tailored for RATs like XWorm."""
    if remote_ip in ("127.0.0.1", "::1", "*", "0.0.0.0", "::"):
        return "🟢 اتصال محلي آمن", 0, "عادي"
    if not is_public_ip(remote_ip):
        return "🟢 شبكة محددة / خاصة", 0, "عادي"

    lower_path = (path or "").lower().replace("/", "\\")
    lower_name = (name or "").lower()
    
    try:
        port = int(remote_port)
    except (TypeError, ValueError):
        port = -1

    score = 0
    reasons = []

    # Check 1: Suspicious execution directories (XWorm default dropping locations)
    if any(marker in lower_path for marker in SUSPICIOUS_PATHS):
        score += 40
        reasons.append("عملية تعمل من مسار مؤقت/قابلة للكتابة (AppData/Temp)")

    # Check 2: Known C2 / RAT ports
    if port in RAT_KNOWN_PORTS:
        score += 45
        reasons.append(f"منفذ اتصال شائع لبرمجيات C2/RAT ({port})")

    # Check 3: Non-standard ports with established connection by non-browser apps
    if port not in COMMON_PORTS and state == "ESTABLISHED":
        if lower_name not in KNOWN_BROWSERS and not lower_path.startswith("c:\\windows\\"):
            score += 30
            reasons.append("اتصال خارجي مستمر بمنفذ غير عادي بدون متصفح")

    # Check 4: Suspicious process naming patterns (e.g. random chars or spoofed names)
    if lower_name.endswith(".exe") and lower_name not in KNOWN_BROWSERS:
        if any(w in lower_name for w in ("stub", "worm", "rat", "client", "payload", "build")):
            score += 50
            reasons.append("اسم العملية يحتوي على دلالات برمجيات ضارة")

    # Verdict Matrix
    if score >= 60:
        verdict = "🚨 خطر مرتفع جداً: مرجّح (XWorm / RAT) — افحصه فوراً!"
        level = "danger"
    elif score >= 30:
        verdict = "⚠️ يستحق الفحص الدقيق (سلوك مريب)"
        level = "warning"
    else:
        verdict = "🟢 اتصال خارجي عادي"
        level = "normal"

    details_str = " | ".join(reasons) if reasons else "لا توجد مؤشرات خطورة مجدية"
    return verdict, score, details_str


def collect_connections():
    result = run_cmd(["netstat.exe", "-ano", "-p", "tcp"], timeout=12)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "تعذّر تشغيل netstat")

    parsed = []
    pids = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        local, remote, state = parts[1], parts[2], parts[3]
        try:
            pid = int(parts[4])
        except ValueError:
            continue
        local_ip, local_port = parse_endpoint(local)
        remote_ip, remote_port = parse_endpoint(remote)
        pids.add(pid)
        parsed.append((local_ip, local_port, remote_ip, remote_port, state, pid))

    names = load_tasklist_names()
    details = load_process_details(pids)
    rows = []
    for local_ip, local_port, remote_ip, remote_port, state, pid in parsed:
        info = details.get(pid, {})
        name = names.get(pid, "غير معروف")
        path = info.get("ExecutablePath") or ""
        verdict, score, reasons = analyze_rat_behavior(remote_ip, remote_port, state, path, name)
        
        rows.append({
            "local": f"{local_ip}:{local_port}",
            "remote": f"{remote_ip}:{remote_port}",
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
            "pid": pid,
            "name": name,
            "path": path,
            "command": info.get("CommandLine") or "",
            "verdict": verdict,
            "score": score,
            "reasons": reasons
        })
    # Sort highest risk scores to the top
    rows.sort(key=lambda x: (x["score"], x["name"].lower()), reverse=True)
    return rows


class RATGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} — تحليل الـ RAT ومراقبة السلوك")
        self.root.geometry("1320\\760".replace("\\", "x"))
        self.root.minsize(1024, 600)
        self.root.configure(bg="#0d1117")
        
        self.rows_by_id = {}
        self.worker_busy = False
        self.events = queue.Queue()
        self.auto_refresh = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="جاهز — نظام التحليل السلوكي في الخدمة")
        
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
        
        style.configure("Treeview", rowheight=27, font=("Segoe UI", 9), background="#161b22", fieldbackground="#161b22", foreground="#c9d1d9")
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), background="#21262d", foreground="#FFD700")
        style.map("Treeview", background=[("selected", "#30363d")], foreground=[("selected", "#FFD700")])

        header = tk.Frame(self.root, bg="#0d1117", padx=16, pady=10)
        header.pack(fill="x")
        tk.Label(header, text="🛡️ RAT Guard Ultimate — خوارزمية كشف XWorm و برمجيات RAT", fg="#FFD700", bg="#0d1117", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(
            header,
            text="تحليل سلوك الاتصالات والمنافذ ومسارات التشغيل للتمييز بين الاتصالات الآمنة والتي تستحق التدخل والقتل الفوري.",
            fg="#8b949e", bg="#0d1117", font=("Segoe UI", 9)
        ).pack(anchor="w", pady=(2, 0))

        toolbar = tk.Frame(self.root, bg="#161b22", padx=10, pady=7, highlightbackground="#30363d", highlightthickness=1)
        toolbar.pack(fill="x", padx=14)
        self._button(toolbar, "🔄 تحديث الاتصالات", self.refresh, color="#21262d", fg="#FFD700").pack(side="left", padx=3)
        self._button(toolbar, "🛑 إنهاء العملية (Kill PID)", self.kill_selected_process, color="#5a0000").pack(side="left", padx=3)
        self._button(toolbar, "🚫 حظر IP + Port", self.block_selected, color="#741212").pack(side="left", padx=3)
        self._button(toolbar, "🔒 حظر البرنامج نهائياً", self.block_selected_program, color="#8b0000").pack(side="left", padx=3)

        toolbar2 = tk.Frame(self.root, bg="#161b22", padx=10, pady=7, highlightbackground="#30363d", highlightthickness=1)
        toolbar2.pack(fill="x", padx=14, pady=(4, 0))
        self._button(toolbar2, "🎯 حظر IP يدوي...", self.block_custom_ip, color="#21262d").pack(side="left", padx=3)
        self._button(toolbar2, "🧹 تنظيف الحظر السلس", self.unblock_rule, color="#21262d").pack(side="left", padx=3)
        self._button(toolbar2, "🔍 فحص Defender", self.scan_file, color="#21262d").pack(side="left", padx=3)
        self._button(toolbar2, "🛡️ فحص التوقيع الرقمي", self.check_selected_file, color="#21262d").pack(side="left", padx=3)
        
        tk.Checkbutton(
            toolbar2, text="تحديث تلقائي (8 ثوانٍ)", variable=self.auto_refresh, 
            fg="#c9d1d9", bg="#161b22", selectcolor="#21262d", 
            activebackground="#161b22", activeforeground="#FFD700", font=("Segoe UI", 9)
        ).pack(side="right", padx=6)

        columns = ("verdict", "name", "pid", "state", "remote", "local", "path")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="browse")
        headings = {
            "verdict": "التقييم السلوكي (القرار الصريح)",
            "name": "اسم البرنامج",
            "pid": "PID",
            "state": "الحالة",
            "remote": "Remote IP:Port",
            "local": "Local IP:Port",
            "path": "مسار الملف التنفيذي",
        }
        widths = {"verdict": 310, "name": 130, "pid": 65, "state": 95, "remote": 170, "local": 170, "path": 320}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")
            
        self.tree.tag_configure("danger", background="#4a0404", foreground="#fca5a5")
        self.tree.tag_configure("warning", background="#3d2b00", foreground="#fde68a")
        self.tree.tag_configure("local", background="#0b253a", foreground="#93c5fd")
        self.tree.pack(fill="both", expand=True, padx=14, pady=6)
        self.tree.bind("<<TreeviewSelect>>", self.show_selection)

        details_frame = tk.Frame(self.root, bg="#0d1117", padx=14, pady=4)
        details_frame.pack(fill="x")
        tk.Label(details_frame, text="📋 تحليل ومؤشرات الخطر للعملية المحددة:", bg="#0d1117", fg="#FFD700", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.details = tk.Text(details_frame, height=4, wrap="word", bg="#161b22", fg="#c9d1d9", insertbackground="#FFD700", relief="flat", font=("Consolas", 9))
        self.details.pack(fill="x", pady=(4, 5))
        self.details.insert("1.0", "اختر اتصالاً لعرض دوافع التقييم السلوكي وسطر الأوامر ومسار التشغيل الكامل.")
        self.details.configure(state="disabled")

        footer = tk.Frame(self.root, bg="#0d1117", padx=14, pady=6)
        footer.pack(fill="x")
        tk.Label(footer, textvariable=self.status_var, bg="#0d1117", fg="#58a6ff", font=("Segoe UI", 9), anchor="w").pack(side="left", fill="x", expand=True)
        tk.Label(footer, text="Behavioral Analysis Matrix Ready", bg="#0d1117", fg="#8b949e", font=("Segoe UI", 9)).pack(side="right")

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
        self.status_var.set("⏳ جاري تحليل شبكة النظام وسلوك العمليات...")

        def work():
            try:
                data = collect_connections()
                self.events.put(("refresh_ok", data))
            except Exception as exc:
                self.events.put(("error", str(exc)))
        threading.Thread(target=work, daemon=True).start()

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
                    self._fill_table(payload)
                    self.status_var.set(f"✅ آخر تحليل: {datetime.now().strftime('%H:%M:%S')} — تم فحص {len(payload)} اتصال تكتيكي.")
                elif kind == "error":
                    self.worker_busy = False
                    self.status_var.set("❌ حدث خطأ أثناء التحليل")
                    messagebox.showerror(APP_NAME, payload)
                elif kind == "message":
                    messagebox.showinfo(APP_NAME, payload)
                elif kind == "warning":
                    messagebox.showwarning(APP_NAME, payload)
        except queue.Empty:
            pass
        self.root.after(250, self._process_events)

    def _fill_table(self, rows):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.rows_by_id.clear()
        for row in rows:
            tags = ()
            v = row["verdict"]
            if "🚨" in v:
                tags = ("danger",)
            elif "⚠️" in v:
                tags = ("warning",)
            elif "🟢" in v:
                tags = ("local",)
            iid = self.tree.insert("", "end", values=(row["verdict"], row["name"], row["pid"], row["state"], row["remote"], row["local"], row["path"]), tags=tags)
            self.rows_by_id[iid] = row

    def show_selection(self, _event=None):
        row = self._selected_silent()
        if not row:
            return
        text = (
            f"البرنامج: {row['name']}    |    PID: {row['pid']}    |    درجة الخطر: {row['score']}/100\n"
            f"مؤشرات الشبهة: {row['reasons']}\n"
            f"الاتصال البعيد: {row['remote']}    |    المحلي: {row['local']}\n"
            f"المسار: {row['path'] or '(غير متاح - ارفع الصلاحيات)'}\n"
            f"الأمر التنفيذي: {row['command'] or '(غير متاح)'}"
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
        except ValueError as exc:
            messagebox.showerror(APP_NAME, str(exc) or "عنوان IP أو المنفذ غير صالح.")
            return
        rule = f"{RULE_PREFIX}Endpoint-{hashlib.sha256(f'{ip_text}:{port}'.encode()).hexdigest()[:12]}"
        if not messagebox.askyesno(APP_NAME, f"حظر الاتصالات الصادرة إلى {ip_text}:{port}؟"):
            return
        qrule, qip = self._ps_quote(rule), self._ps_quote(ip_text)
        script = (
            f"$n={qrule}; Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue; "
            f"New-NetFirewallRule -DisplayName $n -Direction Outbound -Action Block -Protocol TCP -RemoteAddress {qip} -RemotePort {port} -Profile Any -Enabled True -ErrorAction Stop | Out-Null; "
            "Write-Output 'RATGUARD_OK'"
        )
        self._firewall_job(script, f"✅ تم حظر الاتصال إلى {ip_text}:{port} بنجاح.")

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
                self.events.put(("message", "✅ تم إرسال الطلب بنجاح إلى Defender."))
            else:
                self.events.put(("warning", "⚠️ تعذّر تشغيل الفحص بـ Defender."))
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