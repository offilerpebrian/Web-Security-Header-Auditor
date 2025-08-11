#!/usr/bin/env python3
import argparse, json, sys, re
from urllib.parse import urlparse
import requests

TIMEOUT = 12

REQUIRED_HEADERS = {
    "content-security-policy": "Terapkan CSP untuk membatasi sumber konten (script/style/img).",
    "strict-transport-security": "Aktifkan HSTS agar selalu pakai HTTPS (includeSubDomains; preload bila siap).",
    "x-frame-options": "Gunakan X-Frame-Options: DENY atau SAMEORIGIN untuk mencegah clickjacking.",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff untuk blok MIME sniffing.",
    "referrer-policy": "Tambahkan Referrer-Policy (mis. 'strict-origin-when-cross-origin').",
    "permissions-policy": "Batasi API browser (camera, geolocation) via Permissions-Policy.",
    "cross-origin-opener-policy": "Tambahkan COOP (mis. 'same-origin') untuk isolasi browsing context.",
    "cross-origin-resource-policy": "Tambahkan CORP (mis. 'same-origin') untuk proteksi resource lintas-origin."
}

def normalize_url(u: str) -> str:
    if not u.startswith("http://") and not u.startswith("https://"):
        return "https://" + u
    return u

def fetch(url: str):
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        return resp
    except requests.RequestException as e:
        print(f"[!] Gagal mengakses {url}: {e}")
        sys.exit(2)

def is_https_final(resp: requests.Response) -> bool:
    return resp.url.startswith("https://")

def analyze_cookies(resp: requests.Response):
    findings = []
    cookies_list = []
    raw_headers = getattr(resp, "raw", None)
    raw_hdrs = getattr(raw_headers, "headers", None) if raw_headers is not None else None
    if raw_hdrs is not None and hasattr(raw_hdrs, "getlist"):
        cookies_list = raw_hdrs.getlist("Set-Cookie")
    else:
        sc = resp.headers.get("Set-Cookie")
        if sc:
            cookies_list = [sc]
    for c in cookies_list:
        name_match = re.match(r"^([^=;\s]+)=", c)
        name = name_match.group(1) if name_match else "(noname)"
        lc = c.lower()
        if "secure" not in lc:
            findings.append(f"Cookie: '{name}' tanpa Secure.")
        if "httponly" not in lc:
            findings.append(f"Cookie: '{name}' tanpa HttpOnly.")
        if "samesite=" not in lc:
            findings.append(f"Cookie: '{name}' tanpa SameSite.")
    return findings

def score_headers(present_headers: set, cookie_issues: list) -> int:
    base = 100
    for k in REQUIRED_HEADERS.keys():
        if k not in present_headers:
            base -= 10
    base -= 5 * len(cookie_issues)
    return max(0, min(100, base))

def main():
    ap = argparse.ArgumentParser(description="Web Security Header Auditor")
    ap.add_argument("url", help="URL target")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    args = ap.parse_args()
    url = normalize_url(args.url)
    resp = fetch(url)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    present = set(headers.keys())
    recommendations = []
    if not is_https_final(resp):
        recommendations.append("Situs tidak berakhir pada HTTPS. Paksa HTTPS (redirect 301) dan aktifkan HSTS.")
    missing = []
    for h, rec in REQUIRED_HEADERS.items():
        if h not in present:
            missing.append(h)
            recommendations.append(f"Header '{h}' hilang. {rec}")
    if "strict-transport-security" in present:
        hsts = headers["strict-transport-security"]
        if "max-age" not in hsts.lower():
            recommendations.append("HSTS tanpa max-age. Gunakan 'max-age=31536000; includeSubDomains; preload' bila siap.")
    if "content-security-policy" in present:
        csp = headers["content-security-policy"]
        if "unsafe-inline" in csp or "*" in csp:
            recommendations.append("CSP terlalu permisif. Perketat sumber script/style.")
    if "x-frame-options" in present:
        xfo = headers["x-frame-options"].lower()
        if xfo not in ("deny", "sameorigin"):
            recommendations.append("X-Frame-Options sebaiknya 'DENY' atau 'SAMEORIGIN'.")
    cookie_issues = analyze_cookies(resp)
    recommendations.extend(cookie_issues)
    score = score_headers(present, cookie_issues)
    result = {
        "target": resp.url,
        "status_code": resp.status_code,
        "https_enforced": is_https_final(resp),
        "present_headers": sorted(list(present)),
        "missing_headers": sorted(missing),
        "score": score,
        "recommendations": recommendations
    }
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("=== Web Security Header Auditor ===")
        print(f"Target          : {result['target']}")
        print(f"Status Code     : {result['status_code']}")
        print(f"HTTPS final     : {'Ya' if result['https_enforced'] else 'Tidak'}")
        print(f"Skor            : {result['score']}/100")
        print("\nHeader Ditemukan:")
        for h in sorted(REQUIRED_HEADERS.keys()):
            print(f" - {h}: {'✅' if h in present else '❌'}")
        if cookie_issues:
            print("\nIsu Cookie:")
            for i in cookie_issues:
                print(f" - {i}")
        if result["recommendations"]:
            print("\nRekomendasi:")
            for r in result["recommendations"]:
                print(f" - {r}")
        print("\nTip:")
        print("Jalankan dengan --json untuk integrasi CI. Gagal jika skor < 80.")

if __name__ == "__main__":
    main()
