"""
Report Generator for File Integrity Monitor.
Exports scan results and history to JSON, CSV, and human-readable TXT formats.
"""

import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Union

from fim.scanner import DirectoryScanSummary, ScanResult

class ReportGenerator:
    """Generates structured export files (JSON, CSV, TXT) from scan results."""

    @staticmethod
    def export_to_json(
        data: Union[ScanResult, DirectoryScanSummary, List[Dict[str, Any]], Dict[str, Any]],
        output_path: str,
    ) -> str:
        """Exports data to JSON file."""
        path_obj = Path(output_path).expanduser().resolve()
        path_obj.parent.mkdir(parents=True, exist_ok=True)

        if hasattr(data, "to_dict"):
            payload = data.to_dict()
        elif isinstance(data, list):
            payload = [item.to_dict() if hasattr(item, "to_dict") else item for item in data]
        else:
            payload = data

        with open(path_obj, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        return str(path_obj)

    @staticmethod
    def export_to_csv(
        data: Union[DirectoryScanSummary, List[ScanResult], List[Dict[str, Any]]],
        output_path: str,
    ) -> str:
        """Exports scan results or history to CSV."""
        path_obj = Path(output_path).expanduser().resolve()
        path_obj.parent.mkdir(parents=True, exist_ok=True)

        items: List[Dict[str, Any]] = []
        if isinstance(data, DirectoryScanSummary):
            items = [r.to_dict() for r in data.results]
        elif isinstance(data, list):
            for item in data:
                if hasattr(item, "to_dict"):
                    items.append(item.to_dict())
                elif isinstance(item, dict):
                    items.append(item)
        elif hasattr(data, "to_dict"):
            items = [data.to_dict()]

        fieldnames = [
            "file_name",
            "threat_level",
            "md5",
            "sha256",
            "file_size",
            "vt_malicious",
            "vt_total",
            "file_path",
            "timestamp",
            "error",
        ]

        with open(path_obj, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for it in items:
                vt_info = it.get("vt_result") or {}
                row = {
                    "file_name": it.get("file_name", ""),
                    "threat_level": it.get("threat_level", ""),
                    "md5": it.get("md5") or it.get("md5_hash", ""),
                    "sha256": it.get("sha256") or it.get("sha256_hash", ""),
                    "file_size": it.get("file_size", 0),
                    "vt_malicious": vt_info.get("malicious", it.get("vt_malicious", 0)),
                    "vt_total": vt_info.get("total_engines", it.get("vt_total", 0)),
                    "file_path": it.get("file_path", ""),
                    "timestamp": it.get("timestamp") or it.get("scan_timestamp", ""),
                    "error": it.get("error", ""),
                }
                writer.writerow(row)

        return str(path_obj)

    @staticmethod
    def export_to_txt(
        data: Union[ScanResult, DirectoryScanSummary, List[ScanResult], List[Dict[str, Any]]],
        output_path: str,
    ) -> str:
        """Exports scan results to a formatted human-readable text report."""
        path_obj = Path(output_path).expanduser().resolve()
        path_obj.parent.mkdir(parents=True, exist_ok=True)

        lines: List[str] = [
            "=" * 70,
            " FILE INTEGRITY MONITOR - SCAN REPORT",
            f" Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 70,
            "",
        ]

        if isinstance(data, DirectoryScanSummary):
            lines.extend([
                "DIRECTORY SCAN SUMMARY",
                "-" * 70,
                f"Target Directory : {data.directory_path}",
                f"Total Files      : {data.total_files}",
                f"Safe Files       : {data.safe_files}",
                f"Suspicious Files : {data.suspicious_files}",
                f"Malicious Files  : {data.malicious_files}",
                f"Unknown Files    : {data.unknown_files}",
                f"Error Files      : {data.error_files}",
                f"Scan Duration    : {data.duration_seconds:.2f} seconds",
                "-" * 70,
                "",
                "DETAILED FILE LIST:",
                "",
            ])
            for idx, r in enumerate(data.results, 1):
                lines.extend([
                    f"[{idx}] {r.file_name} -> Threat: {r.threat_level}",
                    f"    Path   : {r.file_path}",
                    f"    Size   : {r.file_size} bytes",
                    f"    MD5    : {r.md5}",
                    f"    SHA256 : {r.sha256}",
                ])
                if r.vt_result:
                    lines.append(f"    VT Detections: {r.vt_result.malicious}/{r.vt_result.total_engines}")
                if r.error:
                    lines.append(f"    Error  : {r.error}")
                if r.recommendation:
                    lines.append(f"    Advice : {r.recommendation}")
                lines.append("")
        elif isinstance(data, ScanResult):
            lines.extend([
                "SINGLE FILE ANALYSIS",
                "-" * 70,
                f"File Name      : {data.file_name}",
                f"File Path      : {data.file_path}",
                f"File Size      : {data.file_size} bytes",
                f"MD5 Hash       : {data.md5}",
                f"SHA256 Hash    : {data.sha256}",
                f"Threat Level   : {data.threat_level}",
            ])
            if data.vt_result:
                lines.append(f"VirusTotal     : {data.vt_result.malicious}/{data.vt_result.total_engines} engines detected")
                if data.vt_result.detections:
                    lines.append("Top Detections :")
                    for d in data.vt_result.detections[:5]:
                        lines.append(f"  - {d.get('engine')}: {d.get('result')}")
            if data.recommendation:
                lines.append(f"Recommendation : {data.recommendation}")
            if data.error:
                lines.append(f"Error Message  : {data.error}")
            lines.append("-" * 70)
        else:
            lines.append("SCAN HISTORY REPORT")
            lines.append("-" * 70)
            items = data if isinstance(data, list) else [data]
            for idx, item in enumerate(items, 1):
                fname = item.get("file_name") or Path(item.get("file_path", "")).name
                lines.append(f"[{idx}] {fname} | Threat: {item.get('threat_level')} | MD5: {item.get('md5_hash') or item.get('md5')} | Date: {item.get('scan_timestamp') or item.get('timestamp')}")

        with open(path_obj, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        return str(path_obj)
