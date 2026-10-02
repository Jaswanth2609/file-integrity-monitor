"""
Interactive Command Line Interface for File Integrity Monitor.
Implements the rich menu system, screen layouts, colored terminals, and user workflows.
"""

import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fim.config import ConfigManager
from fim.database import DatabaseManager
from fim.hasher import HashEngine
from fim.reporter import ReportGenerator
from fim.scanner import DirectoryScanSummary, FileScanner, ScanResult
from fim.virustotal import VirusTotalClient

class Colors:
    """Terminal ANSI Color Codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

class FIMCLI:
    """Interactive CLI Controller for FIM."""

    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.db = DatabaseManager(self.config.database_path)
        self.hasher = HashEngine(chunk_size=self.config.chunk_size)
        self.vt = VirusTotalClient(
            api_key=self.config.vt_api_key,
            db_manager=self.db,
            rate_limit_rpm=self.config.rate_limit_rpm,
            cache_ttl_hours=self.config.cache_ttl_hours,
        )
        self.scanner = FileScanner(
            config=self.config,
            db_manager=self.db,
            vt_client=self.vt,
            hasher=self.hasher,
        )
        self.last_scan_result: Optional[Any] = None

    def _c(self, text: str, color_code: str) -> str:
        """Applies color if enabled in config."""
        if self.config.colored_output:
            return f"{color_code}{text}{Colors.RESET}"
        return text

    def _clear_screen(self) -> None:
        """Clears the console screen."""
        os.system("cls" if os.name == "nt" else "clear")

    def _banner(self) -> None:
        """Prints application header banner."""
        b = f"""
{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗
║     FILE INTEGRITY MONITOR v1.0                          ║
║     Secure File Analysis with VirusTotal                 ║
╚══════════════════════════════════════════════════════════╝{Colors.RESET}"""
        print(b)

    def _press_enter(self) -> None:
        """Prompts user to press enter to continue."""
        print(f"\n{self._c('[Press Enter to continue]', Colors.DIM)}")
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            print()

    def run(self) -> None:
        """Main application loop."""
        # Cleanup expired cache on launch
        try:
            self.db.cleanup_expired_cache()
        except Exception:
            pass

        while True:
            self._clear_screen()
            self._banner()
            
            # Show quick status line
            api_status = self._c("Configured", Colors.GREEN) if self.config.vt_api_key else self._c("Not Set (Local checks only)", Colors.YELLOW)
            db_count = self.db.get_hash_db_count()
            print(f"  {self._c('•', Colors.BLUE)} VirusTotal API: {api_status} | {self._c('•', Colors.BLUE)} Known Hashes: {self._c(str(db_count), Colors.BOLD)}\n")
            
            print("Please select an option:\n")
            print(f"  {self._c('[1]', Colors.CYAN)} Check File Hash")
            print(f"      {self._c('Calculate MD5 and SHA256 hashes of a file', Colors.DIM)}\n")
            print(f"  {self._c('[2]', Colors.CYAN)} Check if File is Malicious")
            print(f"      {self._c('Query VirusTotal for malware detection', Colors.DIM)}\n")
            print(f"  {self._c('[3]', Colors.CYAN)} Overall Scan")
            print(f"      {self._c('Complete analysis (Hash + VirusTotal + Database)', Colors.DIM)}\n")
            print(f"  {self._c('[4]', Colors.CYAN)} Manage Hash Database")
            print(f"      {self._c('Load, view, or create hash databases', Colors.DIM)}\n")
            print(f"  {self._c('[5]', Colors.CYAN)} View Scan History")
            print(f"      {self._c('Search and inspect past scan events', Colors.DIM)}\n")
            print(f"  {self._c('[6]', Colors.CYAN)} Export Results")
            print(f"      {self._c('Export scan reports to JSON, CSV, or TXT', Colors.DIM)}\n")
            print(f"  {self._c('[7]', Colors.CYAN)} Settings")
            print(f"      {self._c('Configure API key, cache, and preferences', Colors.DIM)}\n")
            print(f"  {self._c('[0]', Colors.RED)} Exit\n")

            try:
                choice = input(f"{Colors.BOLD}Enter choice (0-7): {Colors.RESET}").strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{self._c('Exiting File Integrity Monitor. Goodbye!', Colors.YELLOW)}")
                sys.exit(0)

            if choice == "1":
                self.menu_check_hash()
            elif choice == "2":
                self.menu_check_malicious()
            elif choice == "3":
                self.menu_overall_scan()
            elif choice == "4":
                self.menu_manage_hash_database()
            elif choice == "5":
                self.menu_view_history()
            elif choice == "6":
                self.menu_export_results()
            elif choice == "7":
                self.menu_settings()
            elif choice == "0":
                print(f"\n{self._c('Exiting File Integrity Monitor. Goodbye!', Colors.GREEN)}")
                sys.exit(0)
            else:
                print(f"{self._c('Invalid option. Please enter a number between 0 and 7.', Colors.RED)}")
                time.sleep(1.2)

    # -------------------------------------------------------------
    # Option 1: Check File Hash
    # -------------------------------------------------------------
    def menu_check_hash(self) -> None:
        self._clear_screen()
        print(f"{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║  FILE HASH CALCULATION                                   ║")
        print(f"╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n")

        try:
            file_path = input("Enter file path (or 'q' to cancel): ").strip()
            if not file_path or file_path.lower() == "q":
                return
        except (KeyboardInterrupt, EOFError):
            return

        print(f"\n{self._c('Calculating hashes...', Colors.CYAN)}")
        res = self.scanner.scan_file(file_path, check_vt=False, check_db=True, record_history=True, scan_type="hash_only")
        self.last_scan_result = res

        if res.error:
            print(f"\n{self._c('✗ ' + res.error, Colors.RED)}")
            self._press_enter()
            return

        print(f"\n{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║  HASH RESULTS                                            ║")
        print(f"╠══════════════════════════════════════════════════════════╣{Colors.RESET}")
        print(f"  File Name : {self._c(res.file_name, Colors.BOLD)}")
        print(f"  File Path : {res.file_path}")
        print(f"  File Size : {res.file_size:,} bytes")
        print(f"  MD5       : {self._c(res.md5 or '', Colors.CYAN)}")
        print(f"  SHA256    : {self._c(res.sha256 or '', Colors.CYAN)}")
        
        if res.known_db_match:
            print(f"  {self._c('Local DB Match: ' + str(res.known_db_match.get('description')), Colors.YELLOW)}")
            
        print(f"{Colors.GREEN}{Colors.BOLD}╚══════════════════════════════════════════════════════════╝{Colors.RESET}")
        self._press_enter()

    # -------------------------------------------------------------
    # Option 2: Check if File is Malicious (VirusTotal)
    # -------------------------------------------------------------
    def menu_check_malicious(self) -> None:
        self._clear_screen()
        print(f"{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║  VIRUSTOTAL MALWARE CHECK                                ║")
        print(f"╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n")

        try:
            target = input("Enter file path or hash (or 'q' to cancel): ").strip()
            if not target or target.lower() == "q":
                return
        except (KeyboardInterrupt, EOFError):
            return

        # Check if target is a direct hash or file path
        is_hash, htype = HashEngine.validate_hash(target)
        
        if is_hash:
            print(f"\n{self._c('Querying VirusTotal cloud database by ' + htype.upper() + ' hash...', Colors.CYAN)}")
            vt_res = self.vt.query_hash(target, progress_callback=lambda msg: print(f"  {self._c(msg, Colors.DIM)}"))
            self.last_scan_result = vt_res
            self._display_vt_result(vt_res, filename=target)
        else:
            print(f"\n{self._c('Step 1: Calculating file hash locally (0% file data uploaded, privacy-safe)...', Colors.CYAN)}")
            res = self.scanner.scan_file(target, check_vt=True, check_db=True, record_history=True, scan_type="virustotal")
            self.last_scan_result = res
            
            if res.error:
                print(f"\n{self._c('✗ ' + res.error, Colors.RED)}")
                self._press_enter()
                return

            print(f"✓ MD5    : {res.md5}")
            print(f"✓ SHA256 : {res.sha256}")
            print(f"\n{self._c('Step 2: Looking up SHA256 hash in VirusTotal reputation database...', Colors.CYAN)}")
            if res.vt_result:
                self._display_vt_result(res.vt_result, filename=res.file_name, scan_res=res)

        self._press_enter()

    def _display_vt_result(self, vt_res: VTResult, filename: str, scan_res: Optional[ScanResult] = None) -> None:
        """Displays standard layout for VirusTotal scan result."""
        if vt_res.threat_level == "MALICIOUS":
            status_badge = self._c("🔴 MALICIOUS", Colors.RED + Colors.BOLD)
            border_color = Colors.RED
        elif vt_res.threat_level == "SUSPICIOUS":
            status_badge = self._c("🟡 SUSPICIOUS", Colors.YELLOW + Colors.BOLD)
            border_color = Colors.YELLOW
        elif vt_res.threat_level == "SAFE":
            status_badge = self._c("🟢 SAFE", Colors.GREEN + Colors.BOLD)
            border_color = Colors.GREEN
        else:
            status_badge = self._c("⚪ UNKNOWN / NOT IN VT", Colors.WHITE + Colors.BOLD)
            border_color = Colors.CYAN

        cache_tag = f" {self._c('(cached)', Colors.DIM)}" if vt_res.from_cache else ""

        print(f"\n{border_color}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║  ANALYSIS RESULTS                                        ║")
        print(f"╠══════════════════════════════════════════════════════════╣{Colors.RESET}")
        print(f"  Target       : {self._c(filename, Colors.BOLD)}")
        print(f"  Status       : {status_badge}{cache_tag}")
        
        if vt_res.total_engines > 0:
            print(f"  Detections   : {self._c(f'{vt_res.malicious}/{vt_res.total_engines}', Colors.BOLD)} security engines")
            print(f"  Stats        : {vt_res.malicious} malicious, {vt_res.suspicious} suspicious, {vt_res.undetected} undetected")
        
        if vt_res.detections:
            print(f"\n  {self._c('Top Detections:', Colors.BOLD)}")
            for d in vt_res.detections[:5]:
                eng = d.get("engine", "Engine")
                sig = d.get("result") or "Generic detection"
                print(f"   • {self._c(sig, Colors.RED)} ({eng})")

        if vt_res.error_message and vt_res.status != "SUCCESS":
            print(f"\n  {self._c('Note:', Colors.YELLOW)} {vt_res.error_message}")

        if vt_res.recommendation:
            print(f"\n  {self._c('Recommendation:', Colors.BOLD)} {vt_res.recommendation}")

        print(f"{border_color}{Colors.BOLD}╚══════════════════════════════════════════════════════════╝{Colors.RESET}")

    # -------------------------------------------------------------
    # Option 3: Overall Scan
    # -------------------------------------------------------------
    def menu_overall_scan(self) -> None:
        self._clear_screen()
        print(f"{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║  OVERALL SCAN (Hash + VirusTotal + Database)             ║")
        print(f"╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n")

        print("Scan Mode:")
        print(f"  {self._c('[1]', Colors.CYAN)} Single File Scan")
        print(f"  {self._c('[2]', Colors.CYAN)} Entire Directory Scan")
        print(f"  {self._c('[0]', Colors.RED)} Back to Main Menu\n")

        try:
            mode = input(f"{Colors.BOLD}Enter mode (1-2, 0): {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            return

        if mode == "1":
            self.menu_check_malicious()
        elif mode == "2":
            self._scan_directory_flow()

    def _scan_directory_flow(self) -> None:
        try:
            dir_path = input("\nEnter directory path to scan (or 'q' to cancel): ").strip()
            if not dir_path or dir_path.lower() == "q":
                return
        except (KeyboardInterrupt, EOFError):
            return

        p = Path(dir_path).expanduser().resolve()
        if not p.exists() or not p.is_dir():
            print(f"\n{self._c('E001: Directory not found: ' + str(p), Colors.RED)}")
            self._press_enter()
            return

        print(f"\n{self._c('Starting directory scan on: ' + str(p), Colors.CYAN)}")
        print(f"{self._c('Computing hashes locally and querying hash signatures against local cache & VirusTotal database...', Colors.DIM)}")

        def progress(idx: int, total: int, current_file: str, res: ScanResult):
            badge = "🟢" if res.threat_level == "SAFE" else ("🔴" if res.threat_level == "MALICIOUS" else ("🟡" if res.threat_level == "SUSPICIOUS" else "⚪"))
            fname = Path(current_file).name
            print(f"  [{idx}/{total}] {badge} {fname:<30} ({res.threat_level})")

        summary = self.scanner.scan_directory(str(p), check_vt=bool(self.config.vt_api_key), check_db=True, progress_callback=progress)
        self.last_scan_result = summary

        print(f"\n{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║  OVERALL SCAN RESULTS                                    ║")
        print(f"╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n")

        print("Scan Summary:")
        print(f"┌──────────────────────────────────────────────────────────┐")
        print(f"│ Total Files Scanned: {str(summary.total_files):<36}│")
        print(f"│ Safe Files:          {self._c(str(summary.safe_files), Colors.GREEN):<45}│")
        print(f"│ Suspicious Files:    {self._c(str(summary.suspicious_files), Colors.YELLOW):<45}│")
        print(f"│ Malicious Files:     {self._c(str(summary.malicious_files), Colors.RED):<45}│")
        print(f"│ Unknown Files:       {str(summary.unknown_files):<36}│")
        print(f"│ Errors:              {str(summary.error_files):<36}│")
        print(f"│ Duration:            {f'{summary.duration_seconds:.2f}s':<36}│")
        print(f"└──────────────────────────────────────────────────────────┘\n")

        # Display Malicious Files
        malicious = [r for r in summary.results if r.threat_level == "MALICIOUS"]
        if malicious:
            print(f"{self._c('Malicious Files Detected:', Colors.RED + Colors.BOLD)}")
            print("┌──────────────────────────────────────────────────────────┐")
            for idx, r in enumerate(malicious, 1):
                det = f"{r.vt_result.malicious}/{r.vt_result.total_engines}" if r.vt_result else "Local DB Match"
                print(f"│ {idx}. {r.file_name:<54}│")
                print(f"│    Detections: {det:<42}│")
                print(f"│    Path: {r.file_path:<47}│")
                if idx < len(malicious):
                    print("├──────────────────────────────────────────────────────────┤")
            print("└──────────────────────────────────────────────────────────┘\n")

        # Display Suspicious Files
        suspicious = [r for r in summary.results if r.threat_level == "SUSPICIOUS"]
        if suspicious:
            print(f"{self._c('Suspicious Files Detected:', Colors.YELLOW + Colors.BOLD)}")
            print("┌──────────────────────────────────────────────────────────┐")
            for idx, r in enumerate(suspicious, 1):
                det = f"{r.vt_result.suspicious}/{r.vt_result.total_engines}" if r.vt_result else "Heuristics"
                print(f"│ {idx}. {r.file_name:<54}│")
                print(f"│    Detections: {det:<42}│")
                print(f"│    Path: {r.file_path:<47}│")
                if idx < len(suspicious):
                    print("├──────────────────────────────────────────────────────────┤")
            print("└──────────────────────────────────────────────────────────┘\n")

        print("Options:")
        print(f"  {self._c('[1]', Colors.CYAN)} Export full report (JSON/CSV/TXT)")
        print(f"  {self._c('[2]', Colors.CYAN)} Return to main menu\n")

        try:
            c = input(f"{Colors.BOLD}Enter choice (1-2): {Colors.RESET}").strip()
            if c == "1":
                self.menu_export_results()
        except (KeyboardInterrupt, EOFError):
            pass

    # -------------------------------------------------------------
    # Option 4: Manage Hash Database
    # -------------------------------------------------------------
    def menu_manage_hash_database(self) -> None:
        self._clear_screen()
        print(f"{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║  MANAGE HASH DATABASE                                    ║")
        print(f"╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n")

        count = self.db.get_hash_db_count()
        print(f"Current Known Hashes in Database: {self._c(str(count), Colors.BOLD + Colors.GREEN)}\n")
        print(f"  {self._c('[1]', Colors.CYAN)} Import Hashes from Text File")
        print(f"  {self._c('[2]', Colors.CYAN)} Add Single Hash manually")
        print(f"  {self._c('[3]', Colors.CYAN)} Search Hash in Database")
        print(f"  {self._c('[4]', Colors.CYAN)} View Sample Hashes in Database")
        print(f"  {self._c('[5]', Colors.RED)} Clear Entire Hash Database")
        print(f"  {self._c('[0]', Colors.WHITE)} Back to Main Menu\n")

        try:
            choice = input(f"{Colors.BOLD}Enter choice (0-5): {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            return

        if choice == "1":
            try:
                fpath = input("Enter path to hash file: ").strip()
                if fpath:
                    imported, skipped = self.db.import_hash_file(fpath)
                    print(f"\n{self._c(f'✓ Successfully imported {imported} hashes ({skipped} skipped/duplicate).', Colors.GREEN)}")
            except Exception as e:
                print(f"\n{self._c('✗ Error importing hash file: ' + str(e), Colors.RED)}")
            self._press_enter()

        elif choice == "2":
            try:
                hval = input("Enter hash value (MD5 / SHA256): ").strip()
                is_valid, htype = HashEngine.validate_hash(hval)
                if not is_valid:
                    print(f"{self._c('E006: Invalid hash format.', Colors.RED)}")
                else:
                    desc = input("Enter description (e.g. Known Malware XYZ): ").strip() or "Custom Entry"
                    src = input("Enter source name (default: manual): ").strip() or "manual"
                    self.db.add_hash(hval, hash_type=htype, source=src, description=desc)
                    print(f"\n{self._c('✓ Hash successfully added to database.', Colors.GREEN)}")
            except Exception as e:
                print(f"\n{self._c('✗ Error: ' + str(e), Colors.RED)}")
            self._press_enter()

        elif choice == "3":
            try:
                hval = input("Enter hash to search: ").strip()
                found = self.db.check_hash_in_db(hval)
                if found:
                    print(f"\n{self._c('✓ Hash Found in Database:', Colors.GREEN)}")
                    print(f"  Hash        : {found['hash_value']}")
                    print(f"  Type        : {found['hash_type'].upper()}")
                    print(f"  Source      : {found['source']}")
                    print(f"  Description : {found['description']}")
                    print(f"  Added Date  : {found['added_timestamp']}")
                else:
                    print(f"\n{self._c('✗ Hash not found in local database.', Colors.YELLOW)}")
            except Exception as e:
                print(f"\n{self._c('✗ Error: ' + str(e), Colors.RED)}")
            self._press_enter()

        elif choice == "4":
            hashes = self.db.get_all_hashes(limit=15)
            if not hashes:
                print(f"\n{self._c('Database is currently empty.', Colors.YELLOW)}")
            else:
                print(f"\n{'Hash Value':<40} {'Type':<8} {'Source':<15} {'Description'}")
                print("-" * 75)
                for h in hashes:
                    disp_hash = h['hash_value'][:36] + "..." if len(h['hash_value']) > 36 else h['hash_value']
                    print(f"{disp_hash:<40} {h['hash_type'].upper():<8} {h['source'][:14]:<15} {h['description']}")
            self._press_enter()

        elif choice == "5":
            confirm = input(f"{self._c('Are you sure you want to clear ALL known hashes? (y/N): ', Colors.RED)}").strip()
            if confirm.lower() == "y":
                del_count = self.db.clear_hash_db()
                print(f"\n{self._c(f'✓ Deleted {del_count} entries from database.', Colors.GREEN)}")
            self._press_enter()

    # -------------------------------------------------------------
    # Option 5: View Scan History
    # -------------------------------------------------------------
    def menu_view_history(self) -> None:
        self._clear_screen()
        print(f"{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║  SCAN HISTORY                                            ║")
        print(f"╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n")

        print(f"  {self._c('[1]', Colors.CYAN)} View 20 Most Recent Scans")
        print(f"  {self._c('[2]', Colors.CYAN)} Search Scan History by Name or Hash")
        print(f"  {self._c('[3]', Colors.RED)} Clear Entire Scan History")
        print(f"  {self._c('[0]', Colors.WHITE)} Back to Main Menu\n")

        try:
            choice = input(f"{Colors.BOLD}Enter choice (0-3): {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            return

        if choice == "1":
            scans = self.db.get_recent_scans(limit=20)
            self._display_history_list(scans)
        elif choice == "2":
            q = input("\nEnter search query (file name, path, or hash): ").strip()
            if q:
                scans = self.db.search_history(q)
                self._display_history_list(scans)
        elif choice == "3":
            confirm = input(f"{self._c('Are you sure you want to clear all history? (y/N): ', Colors.RED)}").strip()
            if confirm.lower() == "y":
                deleted = self.db.clear_history()
                print(f"\n{self._c(f'✓ Deleted {deleted} history entries.', Colors.GREEN)}")
            self._press_enter()

    def _display_history_list(self, scans: List[Dict[str, Any]]) -> None:
        if not scans:
            print(f"\n{self._c('No scan records found.', Colors.YELLOW)}")
        else:
            print(f"\n{'ID':<5} {'Threat':<12} {'File Name':<25} {'MD5':<33} {'Timestamp'}")
            print("-" * 95)
            for s in scans:
                threat = s.get("threat_level", "UNKNOWN")
                color = Colors.RED if threat == "MALICIOUS" else (Colors.YELLOW if threat == "SUSPICIOUS" else Colors.GREEN)
                fname = s.get("file_name", "")[:23]
                md5_val = (s.get("md5_hash") or "N/A")[:32]
                ts = str(s.get("scan_timestamp", ""))[:19]
                print(f"{s['id']:<5} {self._c(threat, color):<21} {fname:<25} {md5_val:<33} {ts}")
        self._press_enter()

    # -------------------------------------------------------------
    # Option 6: Export Results
    # -------------------------------------------------------------
    def menu_export_results(self) -> None:
        self._clear_screen()
        print(f"{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║  EXPORT SCAN REPORTS                                     ║")
        print(f"╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n")

        data_to_export = self.last_scan_result
        if not data_to_export:
            # Fallback to recent history
            data_to_export = self.db.get_recent_scans(limit=100)
            if not data_to_export:
                print(f"{self._c('No recent scan results or history to export.', Colors.YELLOW)}")
                self._press_enter()
                return
            print(f"{self._c('Exporting all recent scan history records...', Colors.CYAN)}")
        else:
            print(f"{self._c('Exporting most recent scan execution results...', Colors.CYAN)}")

        print("\nSelect export format:")
        print(f"  {self._c('[1]', Colors.CYAN)} JSON format (.json)")
        print(f"  {self._c('[2]', Colors.CYAN)} CSV format (.csv)")
        print(f"  {self._c('[3]', Colors.CYAN)} Formatted Text Report (.txt)")
        print(f"  {self._c('[0]', Colors.WHITE)} Cancel\n")

        try:
            fmt = input(f"{Colors.BOLD}Enter choice (0-3): {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            return

        reports_dir = Path(__file__).resolve().parent.parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts_str = time.strftime("%Y%m%d_%H%M%S")

        try:
            if fmt == "1":
                out = reports_dir / f"scan_report_{ts_str}.json"
                p = ReportGenerator.export_to_json(data_to_export, str(out))
                print(f"\n{self._c('✓ Successfully exported to JSON: ' + p, Colors.GREEN)}")
            elif fmt == "2":
                out = reports_dir / f"scan_report_{ts_str}.csv"
                p = ReportGenerator.export_to_csv(data_to_export, str(out))
                print(f"\n{self._c('✓ Successfully exported to CSV: ' + p, Colors.GREEN)}")
            elif fmt == "3":
                out = reports_dir / f"scan_report_{ts_str}.txt"
                p = ReportGenerator.export_to_txt(data_to_export, str(out))
                print(f"\n{self._c('✓ Successfully exported to Text Report: ' + p, Colors.GREEN)}")
        except Exception as e:
            print(f"\n{self._c('✗ Export error: ' + str(e), Colors.RED)}")

        self._press_enter()

    # -------------------------------------------------------------
    # Option 7: Settings
    # -------------------------------------------------------------
    def menu_settings(self) -> None:
        self._clear_screen()
        print(f"{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════════════╗")
        print(f"║  SETTINGS & CONFIGURATION                                ║")
        print(f"╚══════════════════════════════════════════════════════════╝{Colors.RESET}\n")

        current_key = self.config.vt_api_key
        masked_key = (current_key[:6] + "..." + current_key[-4:]) if len(current_key) > 10 else (current_key or "(not set)")

        print(f"  VirusTotal API Key   : {self._c(masked_key, Colors.CYAN)}")
        print(f"  Rate Limit (RPM)     : {self.config.rate_limit_rpm} req/min")
        print(f"  Database Path        : {self.config.database_path}")
        print(f"  Cache TTL (Hours)    : {self.config.cache_ttl_hours}h")
        print(f"  Config File Location : {self.config.config_path}\n")

        print("Actions:")
        print(f"  {self._c('[1]', Colors.CYAN)} Update VirusTotal API Key")
        print(f"  {self._c('[2]', Colors.CYAN)} Toggle Terminal Colors (Current: {self.config.colored_output})")
        print(f"  {self._c('[3]', Colors.CYAN)} Set Cache Expiration (Hours)")
        print(f"  {self._c('[0]', Colors.WHITE)} Back to Main Menu\n")

        try:
            choice = input(f"{Colors.BOLD}Enter choice (0-3): {Colors.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            return

        if choice == "1":
            new_key = input("\nEnter your VirusTotal API key (or leave empty to clear): ").strip()
            self.config.vt_api_key = new_key
            self.config.save()
            self.vt.api_key = new_key
            print(f"{self._c('✓ API Key updated successfully.', Colors.GREEN)}")
            self._press_enter()

        elif choice == "2":
            curr = self.config.colored_output
            self.config.set("ui.colored_output", not curr)
            self.config.save()
            print(f"{self._c('✓ Colored terminal output updated.', Colors.GREEN)}")
            self._press_enter()

        elif choice == "3":
            try:
                hrs = int(input("\nEnter cache TTL in hours (e.g. 24): ").strip())
                self.config.set("database.cache_ttl_hours", hrs)
                self.config.save()
                self.vt.cache_ttl_hours = hrs
                print(f"{self._c('✓ Cache TTL updated.', Colors.GREEN)}")
            except ValueError:
                print(f"{self._c('Invalid number.', Colors.RED)}")
            self._press_enter()
