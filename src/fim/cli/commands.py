"""
Command-Line Interface (CLI) Engine for FIM v2.0.
Implements subcommands: baseline, check, watch, scan, hash, report, config, serve, menu.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from .menu import InteractiveMenu, Colors
from ..api.server import run_server
from ..config import ConfigManager
from ..core.baseline import BaselineManager
from ..core.comparator import IntegrityComparator
from ..core.hasher import HashEngine
from ..core.monitor import LiveMonitor
from ..errors import FIMError, BaselineTamperedError
from ..intel.virustotal import VirusTotalClient
from ..reports.generator import ReportGenerator
from ..storage.db import DatabaseManager

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fim",
        description="File Integrity Monitor (FIM) v2.1 - Enterprise File Integrity & Threat Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", "-c", help="Path to custom configuration file (YAML/JSON)")
    parser.add_argument("--version", "-v", action="version", version="FIM v2.1.0 (by Jaswanth)")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Subcommand: baseline
    baseline_parser = subparsers.add_parser("baseline", help="Manage cryptographic file baselines")
    base_sub = baseline_parser.add_subparsers(dest="baseline_action")
    
    # baseline create
    p_base_create = base_sub.add_parser("create", help="Create a new baseline")
    p_base_create.add_argument("paths", nargs="+", help="Directory or file paths to baseline")
    p_base_create.add_argument("--name", "-n", default="default", help="Profile name (default: default)")
    p_base_create.add_argument("--algo", "-a", default="sha256", choices=["sha256", "sha512", "blake2b"], help="Hash algorithm")

    # baseline list
    base_sub.add_parser("list", help="List all recorded baselines")

    # baseline diff
    p_base_diff = base_sub.add_parser("diff", help="Diff two baseline versions")
    p_base_diff.add_argument("base_a", help="First baseline profile name")
    p_base_diff.add_argument("base_b", help="Second baseline profile name")

    # baseline migrate
    p_base_migrate = base_sub.add_parser("migrate", help="Explicitly migrate and re-sign baseline with current master key")
    p_base_migrate.add_argument("name", nargs="?", default="default", help="Baseline profile name (default: default)")

    # Subcommand: check
    check_parser = subparsers.add_parser("check", help="Verify filesystem integrity against baseline")
    check_parser.add_argument("--profile", "-p", default="default", help="Baseline profile name (default: default)")
    check_parser.add_argument("--format", "-f", choices=["table", "json"], default="table", help="Output format")
    check_parser.add_argument("--accept-migration", action="store_true", help="Explicitly accept legacy key migration and re-sign baseline")
    check_parser.add_argument("--export-html", help="Export HTML report to file")
    check_parser.add_argument("--export-json", help="Export JSON report to file")
    check_parser.add_argument("--export-csv", help="Export CSV report to file")

    # Subcommand: watch
    watch_parser = subparsers.add_parser("watch", help="Start real-time monitoring daemon")
    watch_parser.add_argument("--profile", "-p", default="default", help="Baseline profile name")

    # Subcommand: scan
    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory for threats (reputation + local)")
    scan_parser.add_argument("target", help="Path to file or directory")
    scan_parser.add_argument("--no-vt", action="store_true", help="Skip VirusTotal lookup")

    # Subcommand: hash
    hash_parser = subparsers.add_parser("hash", help="Calculate cryptographic hashes for a file")
    hash_parser.add_argument("file", help="Path to file")
    hash_parser.add_argument("--algo", "-a", choices=["sha256", "sha512", "blake2b", "md5", "sha1"], default="sha256")

    # Subcommand: report
    rep_parser = subparsers.add_parser("report", help="Generate audit report")
    rep_parser.add_argument("--profile", "-p", default="default")
    rep_parser.add_argument("--format", "-f", choices=["html", "json", "csv", "txt"], default="html")
    rep_parser.add_argument("--output", "-o", default="reports/fim_audit_report.html")

    # Subcommand: config
    cfg_parser = subparsers.add_parser("config", help="Get or set configuration options")
    cfg_sub = cfg_parser.add_subparsers(dest="config_action")
    p_cfg_get = cfg_sub.add_parser("get", help="Get config value")
    p_cfg_get.add_argument("key", help="Key path (e.g. virustotal.api_key)")
    p_cfg_set = cfg_sub.add_parser("set", help="Set config value")
    p_cfg_set.add_argument("key", help="Key path")
    p_cfg_set.add_argument("value", help="Value to set")

    # Subcommand: serve
    serve_parser = subparsers.add_parser("serve", help="Launch REST API and Web Dashboard")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port number (default: 8000)")

    # Subcommand: menu
    subparsers.add_parser("menu", help="Launch interactive terminal menu UI")

    # Backward compatibility flags (v1)
    parser.add_argument("--file", "-f", help="[Legacy v1] Scan a single file")
    parser.add_argument("--dir", "-d", help="[Legacy v1] Scan a directory")
    parser.add_argument("--hash", help="[Legacy v1] Query a hash directly on VirusTotal")
    parser.add_argument("--no-vt", action="store_true", help="[Legacy v1] Disable VirusTotal checks")
    parser.add_argument("--import-hashes", help="[Legacy v1] Import known hash signatures into DB")

    return parser

def main_cli(args_list: Optional[List[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(args_list)
    config = ConfigManager(args.config)
    db = DatabaseManager(config.db_path)

    # 1. Check legacy v1 flags first
    if args.hash:
        vt = VirusTotalClient(config=config, db=db)
        print(f"Checking VirusTotal for hash: {args.hash}...")
        res = vt.query_hash(args.hash)
        print(f"Verdict: {res.verdict} | Detection Ratio: {res.detection_ratio}")
        return 0

    if args.import_hashes:
        imported, skipped = db.import_hash_file(args.import_hashes)
        print(f"Imported {imported} hashes ({skipped} duplicates skipped).")
        return 0

    if args.file:
        hasher = HashEngine(chunk_size=config.chunk_size_bytes)
        h_res = hasher.hash_single_file(args.file)
        if h_res.error:
            print(f"{Colors.RED}Error: {h_res.error}{Colors.RESET}")
            return 1
        print(f"File     : {h_res.path}")
        print(f"SHA-256  : {h_res.sha256}")
        print(f"MD5      : {h_res.md5}")
        if not args.no_vt and config.vt_api_key:
            vt = VirusTotalClient(config=config, db=db)
            report = vt.query_hash(h_res.sha256)
            print(f"VT Score : {report.detection_ratio} ({report.verdict})")
        return 0

    if args.dir:
        b_mgr = BaselineManager(config, db)
        files = b_mgr.collect_files([args.dir])
        print(f"Discovered {len(files)} files in {args.dir}.")
        return 0

    # 2. Subcommands routing
    cmd = args.command

    if cmd == "baseline":
        b_mgr = BaselineManager(config, db)
        action = args.baseline_action
        if action == "create":
            print(f"Creating baseline '{args.name}' for: {args.paths}...")
            manifest = b_mgr.create_baseline(
                name=args.name,
                paths=args.paths,
                algo=args.algo,
                progress_callback=lambda idx, total, f: print(f"\rProcessed {idx}/{total} files...", end="", flush=True)
            )
            print(f"\n{Colors.GREEN}[✓] Baseline created successfully with {len(manifest.files)} files!{Colors.RESET}")
            return 0
        elif action == "list":
            baselines = db.list_baselines()
            print(f"\n{Colors.BOLD}Registered Baselines:{Colors.RESET}")
            for b in baselines:
                print(f"  • {Colors.CYAN}{b['name']}{Colors.RESET} ({b['file_count']} files, algo: {b['algo']}) - Paths: {b['root_paths']}")
            return 0
        elif action == "diff":
            res = b_mgr.diff_baselines(args.base_a, args.base_b)
            print(json.dumps(res, indent=2))
            return 0
        elif action == "migrate":
            profile = args.name or "default"
            try:
                ok = b_mgr.migrate_baseline(profile)
                if ok:
                    print(f"\n{Colors.GREEN}[✓] Baseline '{profile}' successfully migrated and re-signed with current master key!{Colors.RESET}")
                    return 0
            except Exception as e:
                print(f"\n{Colors.RED}[!] Migration failed: {e}{Colors.RESET}", file=sys.stderr)
                return 2
        else:
            parser.print_help()
            return 0

    elif cmd == "check":
        comp = IntegrityComparator(config, db)
        try:
            summary = comp.check_baseline(profile_name=args.profile, accept_migration=args.accept_migration)
        except BaselineTamperedError as e:
            print(f"{Colors.RED}[CRITICAL ERROR 2] {e}{Colors.RESET}", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"{Colors.RED}[ERROR 2] Verification failed: {e}{Colors.RESET}", file=sys.stderr)
            return 2

        if args.format == "json":
            print(json.dumps(summary.to_dict(), indent=2))
        else:
            print(f"\n--- FIM Integrity Check: Profile '{args.profile}' ---")
            print(f"Files Checked : {summary.current_files_scanned} / {summary.total_baseline_files}")
            print(f"Changes Found : {len(summary.findings)}")
            if not summary.has_changes:
                print(f"{Colors.GREEN}[✓] Baseline Verified. No changes detected.{Colors.RESET}")
            else:
                print(f"{Colors.RED}[!] ATTENTION: File changes detected:{Colors.RESET}")
                for f in summary.findings:
                    col = Colors.RED if f.severity in ("CRITICAL", "HIGH") else Colors.WARNING
                    print(f"  {col}[{f.severity}] {f.change_type}: {f.path}{Colors.RESET}")
                    print(f"      {f.description}")

        if args.export_html:
            ReportGenerator.export_to_html(summary, args.export_html)
            print(f"Exported HTML report: {args.export_html}")
        if args.export_json:
            ReportGenerator.export_to_json(summary, args.export_json)
            print(f"Exported JSON report: {args.export_json}")
        if args.export_csv:
            ReportGenerator.export_to_csv(summary, args.export_csv)
            print(f"Exported CSV report: {args.export_csv}")

        return summary.exit_code

    elif cmd == "watch":
        print(f"Starting real-time file integrity watcher on profile '{args.profile}'...")
        monitor = LiveMonitor(profile_name=args.profile, config=config, db=db)
        monitor.start(block=True)
        return 0

    elif cmd == "hash":
        hasher = HashEngine(chunk_size=config.chunk_size_bytes)
        res = hasher.hash_single_file(args.file, algorithms=[args.algo])
        if res.error:
            print(f"{Colors.RED}Error: {res.error}{Colors.RESET}")
            return 1
        print(f"{args.algo.upper()}: {res.get_primary(args.algo)}")
        return 0

    elif cmd == "report":
        comp = IntegrityComparator(config, db)
        summary = comp.check_baseline(profile_name=args.profile)
        if args.format == "html":
            ReportGenerator.export_to_html(summary, args.output)
        elif args.format == "json":
            ReportGenerator.export_to_json(summary, args.output)
        elif args.format == "csv":
            ReportGenerator.export_to_csv(summary, args.output)
        else:
            ReportGenerator.export_to_txt(summary, args.output)
        print(f"Report exported to: {args.output}")
        return 0

    elif cmd == "config":
        if args.config_action == "get":
            print(f"{args.key} = {config.get(args.key)}")
        elif args.config_action == "set":
            config.set(args.key, args.value)
            config.save()
            print(f"Updated {args.key} to: {args.value}")
        return 0

    elif cmd == "serve":
        run_server(host=args.host, port=args.port, config=config)
        return 0

    elif cmd == "menu" or cmd is None:
        menu = InteractiveMenu(config)
        menu.run()
        return 0

    return 0
