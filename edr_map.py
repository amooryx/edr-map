#!/usr/bin/env python3
"""
EDR Map — EDR/AV Product Detection & Enumeration Tool
Identifies installed EDR/AV solutions on a compromised host for evasion planning.
Author: Omar Khalid (amooryx) | github.com/amooryx/edr-map
AUTHORIZED USE ONLY — for authorized red team engagements.
"""

import argparse
import json
import os
import platform
import subprocess
import sys

IS_WIN = platform.system() == "Windows"

EDR_SIGNATURES = {
    "CrowdStrike Falcon": {
        "processes": ["csagent.exe", "csfalconservice.exe", "falcond"],
        "services":  ["CSFalconService", "csagent"],
        "dirs":      [r"C:\Program Files\CrowdStrike", "/opt/CrowdStrike"],
        "reg_keys":  [r"HKLM\SYSTEM\CurrentControlSet\Services\CSFalconService"],
    },
    "SentinelOne": {
        "processes": ["SentinelAgent.exe", "SentinelServiceHost.exe", "sentineld"],
        "services":  ["SentinelAgent"],
        "dirs":      [r"C:\Program Files\SentinelOne", "/opt/sentinelone"],
    },
    "Microsoft Defender for Endpoint": {
        "processes": ["MsSense.exe", "SenseNdr.exe", "MsSenseS.exe"],
        "services":  ["Sense", "WdNisSvc"],
        "dirs":      [r"C:\Program Files\Windows Defender Advanced Threat Protection"],
    },
    "Carbon Black": {
        "processes": ["cb.exe", "cbdefense.exe", "cbdaemon"],
        "services":  ["CarbonBlack", "cb"],
        "dirs":      [r"C:\Program Files\Carbon Black", "/usr/share/cb"],
    },
    "Cylance": {
        "processes": ["CylanceSvc.exe", "cylanced"],
        "services":  ["CylanceSVC"],
        "dirs":      [r"C:\Program Files\Cylance"],
    },
    "Elastic EDR": {
        "processes": ["elastic-agent", "elastic-endpoint"],
        "dirs":      [r"C:\Program Files\Elastic", "/opt/Elastic"],
    },
    "Sophos": {
        "processes": ["SophosFS.exe", "SophosSafestore.exe", "savd"],
        "services":  ["Sophos Agent", "SAVService"],
    },
    "ESET": {
        "processes": ["ekrn.exe", "egui.exe", "esets_daemon"],
        "services":  ["ekrn"],
    },
    "McAfee/Trellix": {
        "processes": ["masvc.exe", "McShield.exe", "mfemms"],
        "services":  ["McAfeeFramework", "mfemms"],
    },
    "Symantec SEP": {
        "processes": ["SepMasterService.exe", "Smc.exe", "symantec"],
        "services":  ["SepMasterService"],
    },
}

def run(cmd: str) -> str:
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10).stdout.lower()
    except Exception:
        return ""

def get_running_processes() -> list[str]:
    if IS_WIN:
        out = run("tasklist /fo csv 2>nul")
        return [line.split(",")[0].strip('"').lower() for line in out.splitlines()[1:]]
    else:
        out = run("ps aux")
        return [line.split()[10].lower() for line in out.splitlines()[1:] if len(line.split()) > 10]

def get_services() -> list[str]:
    if IS_WIN:
        out = run("sc query type= all state= all")
        services = []
        for line in out.splitlines():
            if "service_name" in line.lower():
                services.append(line.split(":")[-1].strip().lower())
        return services
    else:
        out = run("systemctl list-units --type=service --no-pager")
        return [line.split()[0].lower() for line in out.splitlines() if ".service" in line]

def check_directory(path: str) -> bool:
    return os.path.isdir(path.replace(r"C:\\", "/mnt/c/") if not IS_WIN else path)

def detect_edrs() -> list[dict]:
    detected   = []
    processes  = get_running_processes()
    services   = get_services()

    for product, sigs in EDR_SIGNATURES.items():
        hits = {}
        for proc in sigs.get("processes", []):
            if proc.lower() in processes:
                hits.setdefault("processes", []).append(proc)
        for svc in sigs.get("services", []):
            if svc.lower() in services:
                hits.setdefault("services", []).append(svc)
        for d in sigs.get("dirs", []):
            if check_directory(d):
                hits.setdefault("dirs", []).append(d)
        if hits:
            detected.append({
                "product":    product,
                "indicators": hits,
                "confidence": "High" if len(hits) > 1 else "Medium",
            })
    return detected

def main():
    parser = argparse.ArgumentParser(
        description="EDR Map — EDR/AV Detection (Authorized use only)",
    )
    parser.add_argument("--out", help="Output JSON file")
    parser.add_argument("--quiet", "-q", action="store_true")
    args = parser.parse_args()

    print(f"[*] Scanning for EDR/AV products on {platform.system()} ...")
    detected = detect_edrs()

    if detected:
        print(f"[+] {len(detected)} EDR/AV product(s) detected:")
        for d in detected:
            print(f"  [{d['confidence']}] {d['product']}")
            for itype, ilist in d["indicators"].items():
                print(f"      {itype}: {', '.join(ilist)}")
    else:
        print("[-] No known EDR/AV signatures detected")
        print("    (May be a custom/unknown product or not running)")

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"os": platform.system(), "detected": detected}, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
