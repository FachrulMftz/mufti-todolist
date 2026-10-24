#!/usr/bin/env python3
"""
webtech_detect.py - Pendeteksi teknologi web (fingerprinting pasif) dengan
pemeriksaan versi PHP terhadap batas maksimum (default: 8.4.26).

Hanya mengirim permintaan HTTP GET biasa. Gunakan hanya pada sistem milik
sendiri atau yang sudah mendapat izin tertulis untuk diuji.

Contoh:
    python3 webtech_detect.py https://example.com
    python3 webtech_detect.py -l targets.txt -t 10 -o hasil.json
    python3 webtech_detect.py -l targets.txt --only-vulnerable
    python3 webtech_detect.py https://example.com --max-php 8.3.0
"""

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

DEFAULT_MAX_PHP = "8.4.26"
USER_AGENT = "Mozilla/5.0 (compatible; webtech-detect/1.0)"
MAX_BODY = 512 * 1024  # baca maksimal 512 KB

# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------

# (nama, lokasi, regex). Grup 1 (jika ada) dipakai sebagai versi.
HEADER_SIGS = [
    ("PHP", "x-powered-by", r"PHP/?([\d.]+)?"),
    ("ASP.NET", "x-powered-by", r"ASP\.NET"),
    ("ASP.NET", "x-aspnet-version", r"([\d.]+)"),
    ("Express", "x-powered-by", r"Express"),
    ("Nginx", "server", r"nginx/?([\d.]+)?"),
    ("Apache", "server", r"Apache/?([\d.]+)?"),
    ("LiteSpeed", "server", r"LiteSpeed"),
    ("Microsoft-IIS", "server", r"Microsoft-IIS/?([\d.]+)?"),
    ("Cloudflare", "server", r"cloudflare"),
    ("Cloudflare", "cf-ray", r".+"),
    ("OpenResty", "server", r"openresty/?([\d.]+)?"),
    ("Caddy", "server", r"Caddy"),
    ("Varnish", "via", r"varnish"),
    ("Drupal", "x-generator", r"Drupal\s*([\d.]+)?"),
    ("Joomla", "x-content-encoded-by", r"Joomla"),
    ("Laravel", "set-cookie", r"laravel_session"),
    ("Symfony", "x-debug-token", r".+"),
    ("WordPress", "link", r"wp-json"),
    ("Magento", "set-cookie", r"frontend=|mage-cache"),
    ("CodeIgniter", "set-cookie", r"ci_session"),
    ("PHP", "set-cookie", r"PHPSESSID"),
    ("ASP.NET", "set-cookie", r"ASP\.NET_SessionId"),
    ("Java", "set-cookie", r"JSESSIONID"),
]

# (nama, regex pada body HTML). Grup 1 (jika ada) dipakai sebagai versi.
BODY_SIGS = [
    ("WordPress", r"wp-content/|wp-includes/"),
    ("WordPress", r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)?'),
    ("Joomla", r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!?\s*([\d.]+)?'),
    ("Drupal", r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s*([\d.]+)?'),
    ("Laravel", r'name=["\']csrf-token["\']|/vendor/laravel'),
    ("CodeIgniter", r"codeigniter"),
    ("Magento", r"Mage\.Cookies|/static/frontend/Magento"),
    ("PrestaShop", r'content=["\']PrestaShop'),
    ("OpenCart", r"catalog/view/theme|index\.php\?route="),
    ("phpMyAdmin", r"phpMyAdmin"),
    ("jQuery", r"jquery[.-]?([\d.]+)?(?:\.min)?\.js"),
    ("Bootstrap", r"bootstrap(?:\.min)?\.(?:css|js)|bootstrap@([\d.]+)"),
    ("React", r"react(?:-dom)?(?:\.production|\.development)?(?:\.min)?\.js|data-reactroot|__REACT"),
    ("Vue.js", r"vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js|data-v-[0-9a-f]{6,}"),
    ("Angular", r"ng-version=[\"']([\d.]+)[\"']|angular(?:\.min)?\.js"),
    ("Next.js", r"/_next/static|__NEXT_DATA__"),
    ("Nuxt.js", r"/_nuxt/|__NUXT__"),
    ("Tailwind CSS", r"tailwindcss|cdn\.tailwindcss\.com"),
    ("Google Analytics", r"google-analytics\.com|googletagmanager\.com|gtag\("),
    ("Livewire", r"livewire\.js|wire:id"),
]

# (nama, regex pada path URL akhir)
URL_SIGS = [
    ("PHP", r"\.php(?:$|\?|/)"),
    ("ASP.NET", r"\.aspx?(?:$|\?)"),
    ("Java", r"\.(?:jsp|do|action)(?:$|\?)"),
]

# ---------------------------------------------------------------------------
# Versi
# ---------------------------------------------------------------------------


def parse_version(text):
    """Ubah '8.4.26-1+deb12' menjadi tuple (8, 4, 26). None jika tidak valid."""
    if not text:
        return None
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", text.strip())
    if not m:
        return None
    return tuple(int(p) if p else 0 for p in m.groups())


def fmt_version(v):
    return ".".join(str(p) for p in v)


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        return None
    if not re.match(r"^https?://", raw, re.I):
        raw = "http://" + raw
    return raw


def fetch(url, timeout, verify_tls):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except urllib.error.HTTPError as e:
        resp = e  # HTTPError tetap membawa header dan body
    with resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = " ; ".join(resp.headers.get_all("Set-Cookie") or [])
        if cookies:
            headers["set-cookie"] = cookies
        body = resp.read(MAX_BODY).decode("utf-8", errors="replace")
        return resp.getcode(), resp.geturl(), headers, body


# ---------------------------------------------------------------------------
# Deteksi
# ---------------------------------------------------------------------------


def detect(url, timeout=10, verify_tls=True, max_php=DEFAULT_MAX_PHP):
    result = {
        "url": url,
        "final_url": None,
        "status": None,
        "technologies": {},
        "php": {"detected": False, "version": None, "within_limit": None, "limit": max_php},
        "error": None,
    }

    try:
        status, final_url, headers, body = fetch(url, timeout, verify_tls)
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    result["status"] = status
    result["final_url"] = final_url

    techs = {}  # nama -> set versi

    def add(name, version=None):
        techs.setdefault(name, set())
        if version:
            techs[name].add(version.rstrip("."))

    for name, header, pattern in HEADER_SIGS:
        value = headers.get(header)
        if value:
            m = re.search(pattern, value, re.I)
            if m:
                add(name, m.group(1) if m.groups() else None)

    # Versi PHP kadang ada di header Server (mis. "Apache/2.4 (Unix) PHP/8.2.1")
    server = headers.get("server", "")
    m = re.search(r"PHP/([\d.]+)", server, re.I)
    if m:
        add("PHP", m.group(1))

    for name, pattern in BODY_SIGS:
        m = re.search(pattern, body, re.I)
        if m:
            add(name, m.group(1) if m.groups() and m.group(1) else None)

    path = urlparse(final_url).path + ("?" + urlparse(final_url).query if urlparse(final_url).query else "")
    for name, pattern in URL_SIGS:
        if re.search(pattern, path, re.I):
            add(name)

    result["technologies"] = {k: sorted(v) for k, v in sorted(techs.items())}

    # Evaluasi PHP
    if "PHP" in techs:
        result["php"]["detected"] = True
        limit_t = parse_version(max_php)
        versions = sorted(
            (parse_version(v) for v in techs["PHP"] if parse_version(v)),
        )
        if versions:
            highest = versions[-1]
            result["php"]["version"] = fmt_version(highest)
            result["php"]["within_limit"] = highest <= limit_t

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def print_result(r):
    print(f"\n[*] {r['url']}")
    if r["error"]:
        print(f"    Error : {r['error']}")
        return
    print(f"    Status: {r['status']}  ->  {r['final_url']}")

    if r["technologies"]:
        print("    Teknologi terdeteksi:")
        for name, versions in r["technologies"].items():
            v = f" ({', '.join(versions)})" if versions else ""
            print(f"      - {name}{v}")
    else:
        print("    Tidak ada teknologi yang terdeteksi.")

    php = r["php"]
    if not php["detected"]:
        print("    PHP   : tidak terdeteksi")
    elif php["version"] is None:
        print("    PHP   : terdeteksi, versi tidak diekspos (tidak dapat dibandingkan)")
    else:
        verdict = "DI BAWAH/SAMA DENGAN batas" if php["within_limit"] else "DI ATAS batas"
        print(f"    PHP   : {php['version']}  ->  {verdict} {php['limit']}")


def main():
    ap = argparse.ArgumentParser(description="Deteksi teknologi web dan periksa versi PHP.")
    ap.add_argument("targets", nargs="*", help="URL atau domain target")
    ap.add_argument("-l", "--list", help="file berisi daftar target (satu per baris)")
    ap.add_argument("-t", "--threads", type=int, default=5, help="jumlah thread (default 5)")
    ap.add_argument("--timeout", type=float, default=10, help="timeout per request, detik (default 10)")
    ap.add_argument("--max-php", default=DEFAULT_MAX_PHP, help=f"batas versi PHP (default {DEFAULT_MAX_PHP})")
    ap.add_argument("--only-vulnerable", action="store_true",
                    help="tampilkan hanya target dengan PHP terdeteksi dan versi <= batas")
    ap.add_argument("--insecure", action="store_true", help="abaikan validasi sertifikat TLS")
    ap.add_argument("-o", "--output", help="simpan hasil ke file JSON")
    args = ap.parse_args()

    if not parse_version(args.max_php):
        ap.error("format --max-php tidak valid, contoh: 8.4.26")

    targets = list(args.targets)
    if args.list:
        try:
            with open(args.list, encoding="utf-8") as f:
                targets += [ln for ln in f.read().splitlines() if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            ap.error(f"tidak bisa membaca file: {e}")

    targets = [u for u in (normalize_url(t) for t in targets) if u]
    if not targets:
        ap.error("tidak ada target. Berikan URL atau gunakan -l file.txt")

    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        futures = {
            pool.submit(detect, u, args.timeout, not args.insecure, args.max_php): u
            for u in targets
        }
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            if args.only_vulnerable and not (r["php"]["within_limit"] is True):
                continue
            print_result(r)

    if args.only_vulnerable:
        results = [r for r in results if r["php"]["within_limit"] is True]

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Hasil disimpan ke {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
