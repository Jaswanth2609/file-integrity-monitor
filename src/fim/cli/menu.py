"""
Interactive ANSI Terminal Menu for FIM v2.0.
Provides rich interactive console UI with colors, status badges, and direct actions.
"""

import os
import sys
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

from ..config import ConfigManager
from ..core.baseline import BaselineManager
from ..core.comparator import IntegrityComparator
from ..core.hasher import HashEngine
from ..intel.virustotal import VirusTotalClient
from ..reports.generator import ReportGenerator
from ..storage.db import DatabaseManager

class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

class InteractiveMenu:
    """Terminal UI for File Integrity Monitor v2.0."""

    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.db = DatabaseManager(self.config.db_path)
        self.hasher = HashEngine(chunk_size=self.config.chunk_size_bytes)
        self.baseline_mgr = BaselineManager(self.config, self.db)
        self.comparator = IntegrityComparator(self.config, self.db)
        self.vt = VirusTotalClient(config=self.config, db=self.db)

    def _clear(self):
        os.system("cls" if os.name == "nt" else "clear")

    def _header(self):
        print(f"{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║     FILE INTEGRITY MONITOR (FIM) v2.0                    ║")
        print(f"║     Cryptographic Integrity & Threat Intelligence        ║")
        print(f"╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n")

    def _select_profile(self) -> Optional[str]:
        """Helper to list registered baselines and let user choose one easily."""
        baselines = self.db.list_baselines()
        if not baselines:
            print(f"{Colors.WARNING}[!] No baselines found in database.{Colors.RESET}")
            print("You must create a baseline before you can check integrity or generate reports.")
            create_now = input("\nWould you like to create a baseline now? [Y/n]: ").strip().lower()
            if create_now in ("", "y", "yes"):
                self._menu_create_baseline()
                baselines = self.db.list_baselines()
                if not baselines:
                    return None
            else:
                return None

        if len(baselines) == 1:
            # Single baseline available
            b = baselines[0]
            print(f"Selected baseline: {Colors.CYAN}{b['name']}{Colors.RESET} ({b['file_count']} files)")
            return b["name"]

        print(f"{Colors.BOLD}Available Baseline Profiles:{Colors.RESET}")
        for idx, b in enumerate(baselines, 1):
            print(f"  [{idx}] {Colors.CYAN}{b['name']}{Colors.RESET} ({b['file_count']} files, algo: {b['algo']})")

        sel = input(f"\nSelect a baseline [1-{len(baselines)}] (default: 1): ").strip()
        if not sel:
            return baselines[0]["name"]
        if sel.isdigit() and 1 <= int(sel) <= len(baselines):
            return baselines[int(sel) - 1]["name"]
        # Check if user typed the name directly
        for b in baselines:
            if b["name"] == sel:
                return b["name"]
        return baselines[0]["name"]

    def run(self):
        while True:
            self._clear()
            self._header()
            print(f"  {Colors.BOLD}[1]{Colors.RESET} Create / Update Baseline")
            print(f"      Snapshot file metadata and cryptographically sign HMAC")
            print()
            print(f"  {Colors.BOLD}[2]{Colors.RESET} Check File Integrity")
            print(f"      Compare live filesystem against signed baseline")
            print()
            print(f"  {Colors.BOLD}[3]{Colors.RESET} Calculate File Hash")
            print(f"      Compute SHA-256, SHA-512, BLAKE2b, and MD5")
            print()
            print(f"  {Colors.BOLD}[4]{Colors.RESET} Query VirusTotal / MalwareBazaar")
            print(f"      Check reputation for file hash via Threat Intel")
            print()
            print(f"  {Colors.BOLD}[5]{Colors.RESET} View Audit Chain Ledger")
            print(f"      Inspect tamper-evident append-only history")
            print()
            print(f"  {Colors.BOLD}[6]{Colors.RESET} Generate Audit Report")
            print(f"      Export findings to HTML, JSON, or CSV")
            print()
            print(f"  {Colors.BOLD}[7]{Colors.RESET} Settings & Configuration")
            print(f"      Configure API keys, algorithms, and alert rules")
            print()
            print(f"  {Colors.BOLD}[0]{Colors.RESET} Exit")
            print("-" * 60)

            choice = input(f"{Colors.BOLD}Select an option [0-7]: {Colors.RESET}").strip()

            if choice == "1":
                self._menu_create_baseline()
            elif choice == "2":
                self._menu_check_integrity()
            elif choice == "3":
                self._menu_hash_file()
            elif choice == "4":
                self._menu_query_intel()
            elif choice == "5":
                self._menu_view_audit()
            elif choice == "6":
                self._menu_generate_report()
            elif choice == "7":
                self._menu_settings()
            elif choice == "0":
                print("\nExiting FIM. Stay safe!\n")
                break
            else:
                input("\nInvalid option. Press Enter to continue...")

    def _menu_create_baseline(self):
        self._clear()
        self._header()
        print(f"{Colors.BOLD}--- CREATE / UPDATE BASELINE ---{Colors.RESET}\n")
        name = input("Enter baseline profile name [default]: ").strip() or "default"
        path_input = input("Enter directory or file paths (e.g. ./config or /etc): ").strip()
        if not path_input:
            input("\nNo path provided. Press Enter to return...")
            return

        paths = [p.strip() for p in path_input.split(",") if p.strip()]
        algo = input("Choose hash algorithm [sha256/sha512/blake2b] (default: sha256): ").strip().lower() or "sha256"
        if algo not in ("sha256", "sha512", "blake2b"):
            algo = "sha256"

        print(f"\nCreating baseline '{name}' for paths: {paths} using {algo}...")
        try:
            manifest = self.baseline_mgr.create_baseline(
                name=name,
                paths=paths,
                algo=algo,
                progress_callback=lambda idx, total, f: print(f"\rIndexed [{idx}/{total}] files...", end="", flush=True)
            )
            print(f"\n\n{Colors.GREEN}[✓] Baseline '{name}' created successfully!{Colors.RESET}")
            print(f"Files Indexed   : {len(manifest.files)}")
            print(f"Algorithm       : {manifest.algo}")
            print(f"HMAC Signature  : {manifest.signature[:16]}... (tamper-protected)")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error creating baseline: {e}{Colors.RESET}")
        
        input("\nPress Enter to return...")

    def _menu_check_integrity(self):
        self._clear()
        self._header()
        print(f"{Colors.BOLD}--- CHECK INTEGRITY ---{Colors.RESET}\n")
        profile = self._select_profile()
        if not profile:
            input("\nPress Enter to return...")
            return

        print(f"\nVerifying profile '{profile}'...")
        try:
            summary = self.comparator.check_baseline(profile_name=profile)
            print(f"\nChecked {summary.current_files_scanned} live files against {summary.total_baseline_files} baseline files in {summary.finished_at - summary.started_at:.2f}s.")
            
            if not summary.has_changes:
                print(f"{Colors.GREEN}[✓] Clean! No unauthorized changes detected.{Colors.RESET}")
            else:
                print(f"{Colors.RED}[!] ALERT: {len(summary.findings)} changes detected!{Colors.RESET}\n")
                for f in summary.findings:
                    sev_color = Colors.RED if f.severity in ("CRITICAL", "HIGH") else Colors.WARNING
                    print(f"  {sev_color}[{f.severity}] {f.change_type}: {f.path}{Colors.RESET}")
                    print(f"      {f.description}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Verification failed: {e}{Colors.RESET}")

        input("\nPress Enter to return...")

    def _menu_hash_file(self):
        self._clear()
        self._header()
        print(f"{Colors.BOLD}--- CALCULATE FILE HASHES ---{Colors.RESET}\n")
        path_str = input("Enter file path: ").strip()
        if not path_str:
            return
        res = self.hasher.hash_single_file(path_str)
        if res.error:
            print(f"\n{Colors.RED}[!] Error: {res.error}{Colors.RESET}")
        else:
            print(f"\nFile     : {res.path}")
            print(f"Size     : {res.size:,} bytes")
            print(f"SHA-256  : {Colors.CYAN}{res.sha256}{Colors.RESET}")
            print(f"SHA-512  : {res.sha512}")
            print(f"BLAKE2b  : {res.blake2b}")
            print(f"MD5      : {res.md5}")
        input("\nPress Enter to return...")

    def _menu_query_intel(self):
        self._clear()
        self._header()
        print(f"{Colors.BOLD}--- THREAT INTELLIGENCE LOOKUP ---{Colors.RESET}\n")
        h = input("Enter hash (SHA-256 / MD5): ").strip()
        if not h:
            return
        print(f"\nQuerying threat intel feeds for: {h}...")
        report = self.vt.query_hash(h)
        col = Colors.RED if report.verdict == "MALICIOUS" else (Colors.WARNING if report.verdict == "SUSPICIOUS" else Colors.GREEN)
        print(f"\nProvider   : {report.provider}")
        print(f"Verdict    : {col}{report.verdict}{Colors.RESET}")
        print(f"Detections : {report.detection_ratio}")
        if report.threat_names:
            print(f"Threats    : {', '.join(report.threat_names)}")
        input("\nPress Enter to return...")

    def _menu_view_audit(self):
        self._clear()
        self._header()
        print(f"{Colors.BOLD}--- IMMUTABLE AUDIT CHAIN ---{Colors.RESET}\n")
        valid, err, count = self.db.audit.verify_integrity()
        if valid:
            print(f"{Colors.GREEN}[✓] Cryptographic Audit Chain Valid ({count} records verified).{Colors.RESET}\n")
        else:
            print(f"{Colors.RED}[!] AUDIT CHAIN BROKEN: {err}{Colors.RESET}\n")

        records = self.db.audit.get_recent_records(limit=10)
        for r in records:
            print(f"  #{r['id']} [{r['event']}] at {time.ctime(r['timestamp'])}")
            print(f"     Hash: {r['entry_hash'][:24]}...")
        input("\nPress Enter to return...")

    def _menu_generate_report(self):
        self._clear()
        self._header()
        print(f"{Colors.BOLD}--- GENERATE AUDIT REPORT ---{Colors.RESET}\n")
        profile = self._select_profile()
        if not profile:
            input("\nPress Enter to return...")
            return

        fmt = input("\nSelect format [html/json/csv/txt] (default: html): ").strip().lower() or "html"
        out_path = input(f"Enter output file path (default: reports/audit_report.{fmt}): ").strip()
        if not out_path:
            out_path = f"reports/audit_report.{fmt}"

        try:
            summary = self.comparator.check_baseline(profile_name=profile)
            if fmt == "html":
                saved = ReportGenerator.export_to_html(summary, out_path)
            elif fmt == "json":
                saved = ReportGenerator.export_to_json(summary, out_path)
            elif fmt == "csv":
                saved = ReportGenerator.export_to_csv(summary, out_path)
            else:
                saved = ReportGenerator.export_to_txt(summary, out_path)
            print(f"\n{Colors.GREEN}[✓] Report successfully saved to:{Colors.RESET}")
            print(f"    {saved}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error generating report: {e}{Colors.RESET}")
        input("\nPress Enter to return...")

    def _menu_settings(self):
        self._clear()
        self._header()
        print(f"{Colors.BOLD}--- SETTINGS & CONFIGURATION ---{Colors.RESET}\n")
        print(f"  [1] Set VirusTotal API Key")
        print(f"  [2] Set Master Secret Key")
        print(f"  [3] View Current Configuration")
        print(f"  [0] Back")
        c = input("\nSelect: ").strip()
        if c == "1":
            k = input("Enter VirusTotal API Key: ").strip()
            self.config.set("virustotal.api_key", k)
            self.config.save()
            print(f"{Colors.GREEN}API key saved.{Colors.RESET}")
        elif c == "2":
            sk = input("Enter Secret Key: ").strip()
            self.config.set("app.secret_key", sk)
            self.config.save()
            print(f"{Colors.GREEN}Secret key saved.{Colors.RESET}")
        elif c == "3":
            print(f"\nDatabase : {self.config.db_path}")
            print(f"VT Key   : {'configured' if self.config.vt_api_key else 'none'}")
        input("\nPress Enter to return...")
