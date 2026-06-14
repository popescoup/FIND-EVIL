/*
 * MABE Detector — YARA Rules
 * ==========================
 * Attack framework signatures for AI-driven lateral movement.
 * Source: GTG-1002 (Nov 2025), Dragos water utility (May 2026)
 *
 * NOTE: These rules are designed for scanning on-disk artifacts and
 * process memory. They cannot be applied to MABE JSON event exports
 * directly — use against native EVTX files or memory images.
 */

rule PythonLateralMovement {
    meta:
        description = "Python-based lateral movement framework"
        author      = "MABE Detector"
        reference   = "GTG-1002 (Nov 2025) — Dragos water utility (May 2026)"
        version     = "1.0"
    strings:
        $s1 = "import socket" ascii
        $s2 = "import subprocess" ascii
        $s3 = "AppData\\Local\\Temp\\python.exe" wide ascii
    condition:
        2 of them
}

rule MachineSpeedNetworkEnumeration {
    meta:
        description = "Machine-speed BFS network enumeration pattern"
        author      = "MABE Detector"
        reference   = "arXiv 2502.04227"
        version     = "1.0"
    strings:
        $s1 = "dst_host" ascii
        $s2 = "auth_attempt" ascii
        $s3 = "credential_harvest" ascii
    condition:
        all of them
}

rule KerberosASREPRoasting {
    meta:
        description = "AS-REP Roasting indicator"
        author      = "MABE Detector"
        reference   = "arXiv 2502.04227"
        version     = "1.0"
    strings:
        $s1 = "kerberos_tgt_request" ascii
        $s2 = "4768" ascii
        $s3 = "4771" ascii
    condition:
        2 of them
}
