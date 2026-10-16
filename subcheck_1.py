#!/usr/bin/env python3
"""
subcheck.py - Cek subdomain aktif + fingerprinting + scanning kerentanan (CVE/CWE).

HANYA gunakan pada target yang kamu punya izin resmi untuk diuji:
milik sendiri, program bug bounty resmi (scope jelas), atau lab latihan
(HackTheBox, TryHackMe, dsb). Menyerang target tanpa izin adalah ilegal.

------------------------------------------------------------------
ALUR KERJA TOOL INI (2 tahap, bisa dijalankan terpisah atau sekaligus):

  Tahap 1 - LIVE CHECK & FINGERPRINT (dibangun di sini, Python murni)
      Mengecek subdomain mana yang hidup, lalu secara PASIF membaca:
        - header HTTP (Server, X-Powered-By, dll.)
        - meta generator tag (mis. WordPress, Joomla)
        - header keamanan yang hilang (CWE: missing security headers)
      Tidak mengirim payload serangan apa pun, hanya satu GET request.

  Tahap 2 - VULNERABILITY SCAN (CVE) via Nuclei
      Untuk mencocokkan versi software dengan database CVE secara
      akurat dan terus-update, tool ini memanggil Nuclei
      (https://github.com/projectdiscovery/nuclei), scanner open-source
      standar industri yang punya ribuan template CVE resmi.
      Saya TIDAK menulis ulang signature CVE secara manual di sini,
      karena rawan salah/ketinggalan zaman. Install Nuclei:

          go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          nuclei -update-templates

      Kalau Nuclei belum terpasang, tool tetap jalan untuk Tahap 1 saja.

Instalasi dependensi Python:
    pip install requests

Contoh pemakaian:
    # Hanya live check + fingerprint
    python subcheck.py -i subdomains.txt

    # Live check + fingerprint + scan CVE pakai Nuclei
    python subcheck.py -i subdomains.txt --nuclei

    # Atur tingkat keparahan template Nuclei yang dipakai
    python subcheck.py -i subdomains.txt --nuclei --severity medium,high,critical
------------------------------------------------------------------
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)

# Header keamanan yang sebaiknya ada (dipetakan ke CWE terkait)
SECURITY_HEADERS = {
    "Strict-Transport-Security": "CWE-319 (Cleartext Transmission) - HSTS tidak diset",
    "X-Frame-Options": "CWE-1021 (Clickjacking) - X-Frame-Options tidak diset",
    "X-Content-Type-Options": "CWE-430 (Deployment of Wrong Handler) - nosniff tidak diset",
    "Content-Security-Policy": "CWE-79 (XSS) - CSP tidak diset",
}

GREEN, YELLOW, RED, CYAN, GREY, RESET = (
    "\033[92m", "\033[93m", "\033[91m", "\033[96m", "\033[90m", "\033[0m"
)


def clean_domain(line: str) -> str:
    line = line.strip().lower()
    line = re.sub(r"^https?://", "", line)
    line = line.split("/")[0]
    line = line.lstrip("*.")
    return line


def check_subdomain(domain: str, timeout: int, follow: bool):
    """Live check + fingerprint pasif (1 request, tanpa payload serangan)."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(url, headers=HEADERS, timeout=timeout,
                              allow_redirects=follow, verify=False)
            body_sample = r.text[:20000]

            title_match = TITLE_RE.search(body_sample)
            title = " ".join(title_match.group(1).split())[:60] if title_match else ""

            gen_match = GENERATOR_RE.search(body_sample)
            generator = gen_match.group(1).strip() if gen_match else ""

            server = r.headers.get("Server", "")
            powered_by = r.headers.get("X-Powered-By", "")

            missing_headers = [note for h, note in SECURITY_HEADERS.items() if h not in r.headers]

            return {
                "domain": domain,
                "url": url,
                "status": r.status_code,
                "final_url": r.url,
                "title": title,
                "size": len(r.content),
                "server": server,
                "powered_by": powered_by,
                "generator": generator,
                "missing_headers": missing_headers,
            }
        except requests.RequestException:
            continue
    return None


def color_for(status: int) -> str:
    if status == 200:
        return GREEN
    if 300 <= status < 400:
        return YELLOW
    return RED


def run_nuclei(urls, severity: str, threads: int, output_json: str):
    """Jalankan Nuclei pada daftar URL yang sudah dipastikan hidup."""
    nuclei_bin = shutil.which("nuclei")
    if not nuclei_bin:
        print(f"\n{RED}[!] Nuclei tidak ditemukan di PATH.{RESET}")
        print("    Install dulu dengan:")
        print("      go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        print("      nuclei -update-templates")
        return

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(urls))
        tmp_path = tmp.name

    cmd = [
        nuclei_bin,
        "-l", tmp_path,
        "-severity", severity,
        "-c", str(threads),
        "-jsonl",
        "-o", output_json,
        "-silent",
    ]

    print(f"\n{CYAN}[*] Menjalankan Nuclei pada {len(urls)} target aktif...{RESET}")
    print(f"[*] Severity filter : {severity}")
    print(f"[*] Perintah        : {' '.join(cmd)}\n")

    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print("\n[!] Nuclei dihentikan oleh pengguna.")
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    if Path(output_json).exists() and Path(output_json).stat().st_size > 0:
        print(f"\n{GREEN}[+] Temuan kerentanan (ringkasan):{RESET}")
        with open(output_json, encoding="utf-8") as f:
            for line in f:
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    continue
                info = finding.get("info", {})
                sev = info.get("severity", "unknown").upper()
                name = info.get("name", "unknown")
                matched = finding.get("matched-at", finding.get("host", ""))
                ref = info.get("reference", [])
                classification = info.get("classification", {})
                cve = classification.get("cve-id", [])
                cwe = classification.get("cwe-id", [])
                sev_color = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW}.get(sev, GREY)
                print(f"{sev_color}[{sev}]{RESET} {name}")
                print(f"    Target : {matched}")
                if cve:
                    print(f"    CVE    : {', '.join(cve)}")
                if cwe:
                    print(f"    CWE    : {', '.join(cwe)}")
                if ref:
                    print(f"    Ref    : {ref[0]}")
                print()
        print(f"[+] Detail lengkap (JSON lines) disimpan di: {output_json}")
    else:
        print(f"\n[+] Tidak ada temuan dari Nuclei (atau scan tidak menghasilkan output).")


def main():
    parser = argparse.ArgumentParser(description="Cek subdomain aktif, fingerprint, dan scan kerentanan (CVE/CWE).")
    parser.add_argument("-i", "--input", required=True, help="File berisi daftar subdomain")
    parser.add_argument("-o", "--output", default="alive.txt", help="File output live check (default: alive.txt)")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Jumlah thread live check (default: 30)")
    parser.add_argument("--timeout", type=int, default=7, help="Timeout detik (default: 7)")
    parser.add_argument("--follow", action="store_true", help="Ikuti redirect (301/302)")
    parser.add_argument("--all", action="store_true", help="Tampilkan semua status, bukan hanya 200")

    parser.add_argument("--nuclei", action="store_true",
                        help="Lanjutkan ke scanning kerentanan CVE/CWE pakai Nuclei setelah live check")
    parser.add_argument("--severity", default="low,medium,high,critical",
                        help="Filter severity Nuclei, pisahkan dengan koma (default: low,medium,high,critical)")
    parser.add_argument("--nuclei-threads", type=int, default=25, help="Concurrency Nuclei (default: 25)")
    parser.add_argument("--nuclei-output", default="vuln_findings.jsonl", help="File hasil Nuclei (JSONL)")
    args = parser.parse_args()

    try:
        with open(args.input, encoding="utf-8") as f:
            domains = sorted({clean_domain(l) for l in f if l.strip() and not l.startswith("#")})
    except FileNotFoundError:
        sys.exit(f"[!] File tidak ditemukan: {args.input}")

    if not domains:
        sys.exit("[!] File input kosong.")

    print(f"[*] Total subdomain unik : {len(domains)}")
    print(f"[*] Thread / timeout     : {args.threads} / {args.timeout}s\n")
    print("=== TAHAP 1: Live check & fingerprint pasif ===\n")

    results = []
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(check_subdomain, d, args.timeout, args.follow): d for d in domains}
            for fut in as_completed(futures):
                res = fut.result()
                if res is None:
                    continue
                if not args.all and res["status"] != 200:
                    continue
                results.append(res)
                c = color_for(res["status"])
                tech = " / ".join(filter(None, [res["server"], res["powered_by"], res["generator"]]))
                print(f"{c}[{res['status']}]{RESET} {res['url']:<40} {GREY}{res['size']}B{RESET}  "
                      f"{CYAN}{tech}{RESET}")
                if res["title"]:
                    print(f"      title  : {res['title']}")
                if res["missing_headers"]:
                    for note in res["missing_headers"]:
                        print(f"      {YELLOW}header{RESET} : {note}")
    except KeyboardInterrupt:
        print("\n[!] Dihentikan oleh pengguna, menyimpan hasil sementara...")

    results.sort(key=lambda r: r["domain"])

    with open(args.output, "w", encoding="utf-8") as f:
        for r in results:
            tech = " / ".join(filter(None, [r["server"], r["powered_by"], r["generator"]]))
            f.write(f"{r['url']}\t{r['status']}\t{r['title']}\t{tech}\n")

    print(f"\n[+] Live check selesai. {len(results)} dari {len(domains)} subdomain tercatat.")
    print(f"[+] Hasil disimpan di: {args.output}")

    if args.nuclei:
        urls = [r["url"] for r in results]
        if not urls:
            print("\n[!] Tidak ada target aktif untuk discan Nuclei.")
            return
        print("\n=== TAHAP 2: Vulnerability scan (CVE/CWE) via Nuclei ===")
        run_nuclei(urls, args.severity, args.nuclei_threads, args.nuclei_output)
    else:
        print("\n[i] Jalankan ulang dengan --nuclei untuk scan CVE/CWE pada subdomain yang aktif ini.")


if __name__ == "__main__":
    main()
