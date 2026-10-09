// Default YARA Detection Rules for File Integrity Monitor (FIM) v2.1
// Add custom .yar / .yara files to this directory to expand threat signatures.

rule WebShell_PHP_Advanced {
    meta:
        description = "Detects advanced PHP web shell patterns, backdoor commands, and obfuscated payload delivery"
        severity = "CRITICAL"
        attack_id = "T1505.003"
    strings:
        $eval1 = "eval(base64_decode(" nocase
        $eval2 = "eval(gzinflate(" nocase
        $assert = "assert($_POST" nocase
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
        $wso = "WSOset" nocase
    condition:
        any of them
}

rule Reverse_Shell_Exec {
    meta:
        description = "Detects interactive reverse shell spawned via bash, netcat, python, or perl"
        severity = "HIGH"
        attack_id = "T1059.004"
    strings:
        $dev_tcp = "/dev/tcp/" ascii
        $nc_e = "nc -e /bin/" ascii
        $py_sock = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)" ascii
        $perl_sock = "perl -e 'use Socket;" ascii
    condition:
        any of them
}

rule CryptoMiner_Artifacts {
    meta:
        description = "Detects cryptocurrency miner configurations and stratum mining connections"
        severity = "HIGH"
        attack_id = "T1496"
    strings:
        $xmrig = "xmrig" nocase
        $stratum_tcp = "stratum+tcp://" ascii
        $stratum_ssl = "stratum+ssl://" ascii
    condition:
        any of them
}
