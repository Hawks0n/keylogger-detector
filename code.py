#!/usr/bin/env python3
"""
Mini Anti-Keylogger Demo (educational)

Single-file Tkinter GUI that scans processes for suspicious keywords and
allows viewing, refreshing, and terminating detected processes.

Requirements satisfied:
 - Python 3.10+
 - Tkinter UI
 - psutil for process enumeration
 - threading for background scanning
 - queue + after for safe UI updates

Safety: This tool is defensive only. Do not use to build or improve keyloggers.
"""
from _future_ import annotations

import json
import os
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

try:
    import psutil
except Exception as e:
    raise SystemExit("Missing dependency 'psutil'. Install with: pip install psutil")

# Default configuration
DEFAULT_KEYWORDS = ["pynput", "keylogger.py"]
CONFIG_FILE = "antikey_config.json"
LOG_FILE_DEFAULT = "antikey_log.txt"


class AntiKeyGUI:
    def _init_(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Mini Anti-Keylogger Demo")
        self.root.geometry("900x600")

        # State
        self.scan_interval = tk.DoubleVar(value=2.0)
        self.is_scanning = False
        self.auto_kill = tk.BooleanVar(value=False)
        self.keywords = list(DEFAULT_KEYWORDS)
        self.log_lines: list[str] = []

        # Threading
        self._scan_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._q: "queue.Queue[dict]" = queue.Queue()

        self._build_ui()
        self._load_config_if_exists()

        # Poll UI queue
        self.root.after(300, self._process_queue)

    # ----------------------- UI -----------------------
    def _build_ui(self) -> None:
        # Top: Title + description
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=8, pady=6)

        title = ttk.Label(top_frame, text="Mini Anti-Keylogger Demo", font=(None, 16, "bold"))
        title.pack(anchor=tk.W)

        desc = ttk.Label(top_frame, text=(
            "Scans running processes for suspicious keywords (educational). "
            "Detected processes can be viewed and terminated. Some actions may require root/admin privileges."))
        desc.pack(anchor=tk.W)

        main_pane = ttk.Frame(self.root)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # Left: Controls
        left = ttk.Frame(main_pane, width=220)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))

        ttk.Label(left, text="Controls", font=(None, 12, "bold")).pack(anchor=tk.W, pady=(0, 6))

        ttk.Button(left, text="Start Scan", command=self.start_scan).pack(fill=tk.X)
        ttk.Button(left, text="Stop Scan", command=self.stop_scan).pack(fill=tk.X, pady=(6, 0))

        ttk.Label(left, text="Scan interval (sec):").pack(anchor=tk.W, pady=(8, 0))
        ttk.Entry(left, textvariable=self.scan_interval).pack(fill=tk.X)

        ttk.Button(left, text="Refresh Now", command=self.manual_refresh).pack(fill=tk.X, pady=(6, 0))

        ttk.Separator(left, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=8)

        ttk.Label(left, text="Keywords (detect):").pack(anchor=tk.W)
        self.keywords_listbox = tk.Listbox(left, height=6)
        self.keywords_listbox.pack(fill=tk.X)
        self._refresh_keywords_listbox()

        kw_entry_frame = ttk.Frame(left)
        kw_entry_frame.pack(fill=tk.X, pady=(6, 0))
        self.kw_entry = ttk.Entry(kw_entry_frame)
        self.kw_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(kw_entry_frame, text="Add", command=self.add_keyword).pack(side=tk.LEFT, padx=(6, 0))

        ttk.Button(left, text="Remove Selected", command=self.remove_selected_keyword).pack(fill=tk.X, pady=(6, 0))

        ttk.Button(left, text="Save Config", command=self.save_config).pack(fill=tk.X, pady=(8, 0))
        ttk.Button(left, text="Load Config", command=self.load_config).pack(fill=tk.X, pady=(6, 0))

        ttk.Checkbutton(left, text="Auto-kill on detection", variable=self.auto_kill).pack(anchor=tk.W, pady=(8, 0))
        ttk.Label(left, text="(Disabled by default; use with caution)").pack(anchor=tk.W)

        ttk.Separator(main_pane, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)

        # Center: Detected processes table
        center = ttk.Frame(main_pane)
        center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        cols = ("pid", "name", "cmdline", "keywords")
        self.tree = ttk.Treeview(center, columns=cols, show="headings")
        self.tree.heading("pid", text="PID")
        self.tree.heading("name", text="Name")
        self.tree.heading("cmdline", text="Cmdline")
        self.tree.heading("keywords", text="Detected Keywords")

        self.tree.column("pid", width=60, anchor=tk.CENTER)
        self.tree.column("name", width=150)
        self.tree.column("cmdline", width=400)
        self.tree.column("keywords", width=150)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Add kill button below table
        btn_frame = ttk.Frame(center)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Kill Selected", command=self.kill_selected).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Export Log", command=self.export_log).pack(side=tk.LEFT, padx=(6, 0))

        # Bottom: Log
        bottom = ttk.Frame(self.root)
        bottom.pack(fill=tk.BOTH, expand=False, padx=8, pady=(0, 8))

        ttk.Label(bottom, text="Activity Log:").pack(anchor=tk.W)
        self.log_text = tk.Text(bottom, height=8, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.configure(state=tk.DISABLED)

    # ----------------------- Config -----------------------
    def _refresh_keywords_listbox(self) -> None:
        self.keywords_listbox.delete(0, tk.END)
        for kw in self.keywords:
            self.keywords_listbox.insert(tk.END, kw)

    def add_keyword(self) -> None:
        kw = self.kw_entry.get().strip()
        if kw and kw not in self.keywords:
            self.keywords.append(kw)
            self._refresh_keywords_listbox()
            self._log(f"Keyword added: {kw}")
            self.kw_entry.delete(0, tk.END)

    def remove_selected_keyword(self) -> None:
        sel = self.keywords_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        kw = self.keywords.pop(idx)
        self._refresh_keywords_listbox()
        self._log(f"Keyword removed: {kw}")

    def save_config(self) -> None:
        data = {"scan_interval": float(self.scan_interval.get()), "keywords": self.keywords}
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self._log(f"Config saved to {CONFIG_FILE}")
        except Exception as e:
            self._log(f"Failed to save config: {e}")

    def load_config(self) -> None:
        path = filedialog.askopenfilename(title="Load config JSON", filetypes=[("JSON files", ".json"), ("All files", "")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.scan_interval.set(data.get("scan_interval", self.scan_interval.get()))
            self.keywords = list(data.get("keywords", self.keywords))
            self._refresh_keywords_listbox()
            self._log(f"Config loaded from {path}")
        except Exception as e:
            self._log(f"Failed to load config: {e}")

    def _load_config_if_exists(self) -> None:
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.scan_interval.set(data.get("scan_interval", self.scan_interval.get()))
                self.keywords = list(data.get("keywords", self.keywords))
                self._refresh_keywords_listbox()
                self._log(f"Loaded config from {CONFIG_FILE}")
            except Exception:
                # Non-fatal
                pass

    # ----------------------- Logging -----------------------
    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}"
        self.log_lines.append(line)
        # Keep UI append lightweight via queue
        self._q.put({"type": "log", "text": line})

    def export_log(self) -> None:
        path = filedialog.asksaveasfilename(title="Export log to...", defaultextension=".txt", filetypes=[("Text files", ".txt"), ("All files", "")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(self.log_lines))
            self._log(f"Exported log to {path}")
            messagebox.showinfo("Export", f"Log exported to: {path}")
        except Exception as e:
            self._log(f"Failed to export log: {e}")

    # ----------------------- Scanning -----------------------
    def start_scan(self) -> None:
        if self.is_scanning:
            self._log("Scan already running")
            return
        self._stop_event.clear()
        self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._scan_thread.start()
        self.is_scanning = True
        self._log("Background scan started")

    def stop_scan(self) -> None:
        if not self.is_scanning:
            self._log("Scan is not running")
            return
        self._stop_event.set()
        if self._scan_thread:
            self._scan_thread.join(timeout=2.0)
        self.is_scanning = False
        self._log("Background scan stopped")

    def manual_refresh(self) -> None:
        # Run one scan iteration in a short-lived thread to avoid blocking UI
        threading.Thread(target=self._scan_once, daemon=True).start()

    def _scan_loop(self) -> None:
        # Loop until stop_event is set, sleeping between intervals
        while not self._stop_event.is_set():
            self._scan_once()
            interval = max(0.1, float(self.scan_interval.get()))
            # Sleep in small chunks to be responsive to stop_event
            end = time.time() + interval
            while time.time() < end and not self._stop_event.is_set():
                time.sleep(0.1)

    def _scan_once(self) -> None:
        detected = []
        keywords_lower = [k.lower() for k in self.keywords]
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid = proc.info.get("pid")
                name = proc.info.get("name") or ""
                cmdline_list = proc.info.get("cmdline") or []
                cmdline = " ".join(cmdline_list)
                hay = (name + " " + cmdline).lower()
                matched = [k for k in keywords_lower if k in hay]
                if matched:
                    detected.append({"pid": pid, "name": name, "cmdline": cmdline, "matched": matched})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process disappeared or no permission; skip
                continue

        # Send detected list to main thread for UI update
        self._q.put({"type": "detected", "data": detected})

        # Auto-kill if enabled
        if self.auto_kill.get():
            for item in detected:
                try:
                    p = psutil.Process(item["pid"])
                    p.kill()
                    self._log(f"Auto-killed PID {item['pid']} ({item['name']})")
                except psutil.NoSuchProcess:
                    self._log(f"Auto-kill: process {item['pid']} already gone")
                except psutil.AccessDenied:
                    self._log(f"Auto-kill: access denied to kill {item['pid']}")
                except Exception as e:
                    self._log(f"Auto-kill: failed to kill {item['pid']}: {e}")

    # ----------------------- UI Queue Processing -----------------------
    def _process_queue(self) -> None:
        try:
            while True:
                item = self._q.get_nowait()
                if item["type"] == "log":
                    self._append_log_to_text(item["text"])
                elif item["type"] == "detected":
                    self._update_detected_table(item["data"])
        except queue.Empty:
            pass
        finally:
            # Schedule next poll
            self.root.after(300, self._process_queue)

    def _append_log_to_text(self, text: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _update_detected_table(self, detected: list[dict]) -> None:
        # Clear table and repopulate
        for item in self.tree.get_children():
            self.tree.delete(item)
        for d in detected:
            pid = d.get("pid")
            name = d.get("name")
            cmdline = d.get("cmdline")
            matched = ", ".join(d.get("matched", []))
            self.tree.insert("", tk.END, iid=str(pid), values=(pid, name, cmdline, matched))
            self._log(f"Detected PID {pid}: {name} | matched: {matched}")

    # ----------------------- Actions -----------------------
    def kill_selected(self) -> None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Kill", "No process selected")
            return
        for iid in sel:
            try:
                pid = int(iid)
            except Exception:
                continue
            try:
                p = psutil.Process(pid)
                p.kill()
                self._log(f"Killed PID {pid} ({p.name()})")
            except psutil.NoSuchProcess:
                self._log(f"Failed to kill {pid}: process does not exist")
                messagebox.showwarning("Kill", f"Process {pid} does not exist")
            except psutil.AccessDenied:
                self._log(f"Failed to kill {pid}: access denied")
                messagebox.showerror("Kill", f"Access denied when attempting to kill {pid}. Try running as root/administrator.")
            except Exception as e:
                self._log(f"Failed to kill {pid}: {e}")
                messagebox.showerror("Kill", f"Failed to kill {pid}: {e}")


def main() -> None:
    root = tk.Tk()
    app = AntiKeyGUI(root)

    # Intercept close to ensure thread stops
    def on_close() -> None:
        if app.is_scanning:
            if not messagebox.askyesno("Exit", "Scan is running. Stop and exit?"):
                return
            app.stop_scan()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if _name_ == "_main_":
    main()
