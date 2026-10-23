"""
YARA Threat Intelligence Scanner Engine for FIM v2.3.
Scans new and modified files for malicious patterns, webshells, reverse shells,
and dropper signatures.
Supports native yara-python when installed, and provides a built-in pure-Python
signature evaluator as an automatic fallback.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("fim.yara")

try:
    import yara

    HAVE_NATIVE_YARA = True
except ImportError:
    HAVE_NATIVE_YARA = False

DEFAULT_YARA_RULES = """
rule WebShell_PHP_Generic {
    meta:
        description = "Detects common PHP webshell patterns (eval base64 / system execution)"
        severity = "CRITICAL"
        attack_id = "T1505.003"
    strings:
        $eval1 = "eval(base64_decode(" nocase
        $eval2 = "eval(gzinflate(" nocase
        $eval3 = "assert($_POST" nocase
        $eval4 = "passthru($_GET" nocase
        $eval5 = "shell_exec($_REQUEST" nocase
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
        $wso = "WSOset" nocase
    condition:
        any of them
}

rule Suspicious_Reverse_Shell {
    meta:
        description = "Detects reverse shell execution payloads in scripts"
        severity = "HIGH"
        attack_id = "T1059.004"
    strings:
        $bash_rev1 = "/dev/tcp/" ascii
        $bash_rev2 = "bash -i >& /dev/tcp" ascii
        $nc_rev1 = "nc -e /bin/sh" ascii
        $nc_rev2 = "nc -e /bin/bash" ascii
        $python_rev = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)" ascii
        $perl_rev = "perl -e 'use Socket;" ascii
    condition:
        any of them
}

rule CryptoMiner_Signature {
    meta:
        description = "Detects cryptocurrency miner artifacts and stratum pool connections"
        severity = "HIGH"
        attack_id = "T1496"
    strings:
        $xmrig1 = "xmrig" nocase
        $stratum1 = "stratum+tcp://" ascii
        $stratum2 = "stratum+ssl://" ascii
        $pool = "mine.moneropool.com" ascii
    condition:
        any of them
}

rule Obfuscated_Script_Dropper {
    meta:
        description = "Detects base64 piped directly into bash or sh interpreter"
        severity = "HIGH"
        attack_id = "T1027"
    strings:
        $pipe_sh1 = "base64 -d | sh" ascii
        $pipe_sh2 = "base64 -d | bash" ascii
        $pipe_sh3 = "base64 --decode | bash" ascii
        $curl_bash = "curl -s http" ascii
    condition:
        ($curl_bash and ($pipe_sh1 or $pipe_sh2 or $pipe_sh3))
}
"""


@dataclass
class YaraMatch:
    rule_name: str
    description: str
    severity: str
    attack_id: str
    matched_strings: List[str] = field(default_factory=list)


class PurePythonYaraParser:
    """Lightweight rule parser and string/regex/hex pattern matcher for YARA rules."""

    def __init__(self, rule_text: str):
        self.rules: List[Dict[str, Any]] = []
        self._parse(rule_text)

    def _parse(self, text: str):
        # Find all rule blocks: rule <name> { ... }
        rule_pattern = re.compile(r"rule\s+(\w+)\s*\{(.*?)\n\}", re.DOTALL)
        for match in rule_pattern.finditer(text):
            rname = match.group(1)
            body = match.group(2)

            meta: Dict[str, str] = {}
            meta_m = re.search(r"meta:\s*(.*?)(strings:|condition:|$)", body, re.DOTALL)
            if meta_m:
                for line in meta_m.group(1).splitlines():
                    line = line.strip()
                    if "=" in line:
                        k, v = line.split("=", 1)
                        meta[k.strip()] = v.strip().strip('"')

            strings: List[Tuple[str, str, bool]] = []
            str_m = re.search(r"strings:\s*(.*?)(condition:|$)", body, re.DOTALL)
            if str_m:
                for line in str_m.group(1).splitlines():
                    line = line.strip()
                    if line.startswith("$") and "=" in line:
                        sname, sval = line.split("=", 1)
                        sname = sname.strip()
                        sval = sval.strip()
                        nocase = "nocase" in sval.lower()
                        # Clean value
                        cleaned = (
                            re.sub(r"\s+(nocase|ascii|wide)", "", sval, flags=re.IGNORECASE)
                            .strip()
                            .strip('"')
                        )
                        strings.append((sname, cleaned, nocase))

            self.rules.append({"name": rname, "meta": meta, "strings": strings})

    def match_content(self, data: bytes) -> List[YaraMatch]:
        matches: List[YaraMatch] = []
        text_content = data.decode("utf-8", errors="ignore")
        text_lower = text_content.lower()

        for r in self.rules:
            matched_strs = []
            for sname, sval, nocase in r["strings"]:
                if nocase:
                    if sval.lower() in text_lower:
                        matched_strs.append(sname)
                else:
                    if sval in text_content or sval.encode("utf-8") in data:
                        matched_strs.append(sname)

            if matched_strs:
                matches.append(
                    YaraMatch(
                        rule_name=r["name"],
                        description=r["meta"].get("description", f"Matched rule {r['name']}"),
                        severity=r["meta"].get("severity", "HIGH"),
                        attack_id=r["meta"].get("attack_id", "T1059"),
                        matched_strings=matched_strs,
                    )
                )

        return matches


class YaraEngine:
    """High-level YARA scanning engine with native and pure-python backends."""

    def __init__(self, rules_path: Optional[Union[str, Path]] = None):
        self.rules_path = Path(rules_path).expanduser().resolve() if rules_path else None
        self._native_rules = None
        self._pure_parser = None
        self._init_rules()

    def _init_rules(self):
        combined_rules = DEFAULT_YARA_RULES
        if self.rules_path and self.rules_path.exists():
            try:
                if self.rules_path.is_file():
                    combined_rules += "\n" + self.rules_path.read_text(encoding="utf-8")
                elif self.rules_path.is_dir():
                    for rfile in self.rules_path.glob("*.yar*"):
                        combined_rules += "\n" + rfile.read_text(encoding="utf-8")
            except Exception as e:
                logger.warning(f"Failed to load custom YARA rules from {self.rules_path}: {e}")

        if HAVE_NATIVE_YARA:
            try:
                self._native_rules = yara.compile(source=combined_rules)
                logger.debug("Compiled native YARA rules successfully.")
            except Exception as e:
                logger.warning(f"Native YARA compilation failed, using fallback engine: {e}")
                self._pure_parser = PurePythonYaraParser(combined_rules)
        else:
            self._pure_parser = PurePythonYaraParser(combined_rules)

    def scan_file(self, file_path: Union[str, Path], max_size_mb: int = 20) -> List[YaraMatch]:
        """
        Scans a file against YARA rules. Returns list of YaraMatch objects.
        """
        p = Path(file_path).expanduser().resolve()
        if not p.exists() or not p.is_file():
            return []

        try:
            sz = p.stat().st_size
            if sz > max_size_mb * 1024 * 1024:
                # Read first 1MB for large files
                data = p.read_bytes()[: 1024 * 1024]
            else:
                data = p.read_bytes()
        except Exception as e:
            logger.debug(f"Could not read file {p} for YARA scan: {e}")
            return []

        if self._native_rules:
            try:
                native_matches = self._native_rules.match(data=data)
                results = []
                for m in native_matches:
                    meta = m.meta or {}
                    results.append(
                        YaraMatch(
                            rule_name=m.rule,
                            description=meta.get("description", f"Matched YARA rule {m.rule}"),
                            severity=meta.get("severity", "HIGH"),
                            attack_id=meta.get("attack_id", "T1059"),
                            matched_strings=(
                                [s.identifier for s in m.strings] if hasattr(m, "strings") else []
                            ),
                        )
                    )
                return results
            except Exception as e:
                logger.debug(f"Native YARA match error on {p}: {e}")

        if self._pure_parser:
            return self._pure_parser.match_content(data)

        return []
