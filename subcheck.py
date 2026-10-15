#!/usr/bin/env python3
"""
subcheck.py - Cek subdomain mana yang aktif dan bisa diakses.

Gunakan hanya pada target yang kamu punya izin untuk diuji
(milik sendiri, program bug bounty yang resmi, atau lab latihan).

Instalasi:
    pip install requests

Contoh pemakaian:
    python subcheck.py -i subdomains.txt
    python subcheck.py -i subdomains.txt -o hasil.txt -t 50
    python subcheck.py -i subdomains.txt --all          # tampilkan semua status code
    python subcheck.py -i subdomains.txt --follow       # ikuti redirect
"""

import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

# Matikan warning untuk sertifikat SSL yang tidak valid (umum di subdomain)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
}

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Warna terminal
GREEN, YELLOW, RED, GREY, RESET = "\033[92m", "\033[93m", "\033[91m", "\033[90m", "\033[0m"


def clean_domain(line: str) -> str:
    """Bersihkan baris input: hapus spasi, skema, path, dan wildcard."""
    line = line.strip().lower()
    line = re.sub(r"^https?://", "", line)
    line = line.split("/")[0]
    line = line.lstrip("*.")
    return line


def check_subdomain(domain: str, timeout: int, follow: bool):
    """Cek satu subdomain. Coba HTTPS dulu, kalau gagal baru HTTP."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(
                url,
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=follow,
                verify=False,
            )
            title = ""
            m = TITLE_RE.search(r.text[:20000])
            if m:
                title = " ".join(m.group(1).split())[:60]
            return {
                "domain": domain,
                "url": url,
                "status": r.status_code,
                "final_url": r.url,
                "title": title,
                "size": len(r.content),
            }
        except requests.RequestException:
            continue
    return None  # tidak bisa dijangkau sama sekali


def color_for(status: int) -> str:
    if status == 200:
        return GREEN
    if 300 <= status < 400:
        return YELLOW
    return RED


def main():
    parser = argparse.ArgumentParser(description="Cek subdomain aktif (HTTP 200).")
    parser.add_argument("-i", "--input", required=True, help="File berisi daftar subdomain")
    parser.add_argument("-o", "--output", default="alive.txt", help="File output (default: alive.txt)")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Jumlah thread (default: 30)")
    parser.add_argument("--timeout", type=int, default=7, help="Timeout detik (default: 7)")
    parser.add_argument("--follow", action="store_true", help="Ikuti redirect (301/302)")
    parser.add_argument("--all", action="store_true",
                        help="Tampilkan & simpan semua yang merespons, bukan hanya 200")
    args = parser.parse_args()

    try:
        with open(args.input, encoding="utf-8") as f:
            domains = sorted({clean_domain(l) for l in f if l.strip() and not l.startswith("#")})
    except FileNotFoundError:
        sys.exit(f"[!] File tidak ditemukan: {args.input}")

    if not domains:
        sys.exit("[!] File input kosong.")

    print(f"[*] Total subdomain unik : {len(domains)}")
    print(f"[*] Thread / timeout     : {args.threads} / {args.timeout}s")
    print(f"[*] Mode                 : {'semua status' if args.all else 'hanya 200 OK'}\n")

    results = []
    done = 0

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = {ex.submit(check_subdomain, d, args.timeout, args.follow): d for d in domains}
            for fut in as_completed(futures):
                done += 1
                res = fut.result()
                if res is None:
                    continue
                if not args.all and res["status"] != 200:
                    continue
                results.append(res)
                c = color_for(res["status"])
                print(f"{c}[{res['status']}]{RESET} {res['url']:<45} "
                      f"{GREY}{res['size']}B{RESET}  {res['title']}")
    except KeyboardInterrupt:
        print("\n[!] Dihentikan oleh pengguna, menyimpan hasil sementara...")

    results.sort(key=lambda r: r["domain"])

    with open(args.output, "w", encoding="utf-8") as f:
        for r in results:
            f.write(f"{r['url']}\t{r['status']}\t{r['title']}\n")

    print(f"\n[+] Selesai. {len(results)} dari {len(domains)} subdomain tercatat.")
    print(f"[+] Hasil disimpan di: {args.output}")


if __name__ == "__main__":
    main()
