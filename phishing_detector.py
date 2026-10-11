#!/usr/bin/env python3
"""
Phishing Website Detector
Defensive educational project for analyzing URLs.
Uses only Python standard-library modules.
"""

import csv
import ipaddress
import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "account",
    "secure", "security", "update", "password", "confirm",
    "bank", "wallet", "payment", "recover", "unlock"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly"
}

# Demonstration-only blacklist. Replace with a vetted threat-intelligence feed
# when using this project in a real environment.
BLACKLIST = {
    "example-malicious.test",
    "login-security.test",
    "account-verify.test",
}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def get_domain(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    return (parsed.hostname or "").lower().strip(".")


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url: str) -> dict:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    domain = (parsed.hostname or "").lower().strip(".")
    full_url = normalized.lower()

    score = 0
    reasons = []

    # Local blacklist check
    if domain in BLACKLIST:
        score += 60
        reasons.append("Domain matched the local demonstration blacklist")

    # Suspicious keywords
    keyword_hits = sorted(
        keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in full_url
    )
    if keyword_hits:
        score += min(30, len(keyword_hits) * 10)
        reasons.append("Suspicious keyword(s): " + ", ".join(keyword_hits))

    # IP address used instead of a domain name
    if domain and is_ip_address(domain):
        score += 25
        reasons.append("URL uses an IP address instead of a domain name")

    # Long URL
    if len(normalized) > 100:
        score += 10
        reasons.append("Unusually long URL")

    # Excessive subdomains
    labels = domain.split(".") if domain else []
    if len(labels) >= 4:
        score += 10
        reasons.append("Multiple subdomain levels detected")

    # @ can hide the real destination in a URL
    if "@" in parsed.netloc:
        score += 20
        reasons.append("Username/@ pattern found in network location")

    # Excessive hyphens
    if domain.count("-") >= 3:
        score += 10
        reasons.append("Domain contains several hyphens")

    # URL shortener
    if domain in SHORTENER_DOMAINS:
        score += 15
        reasons.append("Known URL-shortener domain detected")

    # HTTP rather than HTTPS
    if parsed.scheme.lower() == "http":
        score += 5
        reasons.append("Connection uses HTTP instead of HTTPS")

    # Cap score for simple presentation
    score = min(score, 100)

    if score >= 60:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "risk": risk,
        "reasons": reasons or ["No strong phishing indicators detected"],
    }


def print_result(result: dict) -> None:
    print("\n" + "=" * 65)
    print(f"URL   : {result['url']}")
    print(f"Domain: {result['domain']}")
    print(f"Risk  : {result['risk']}")
    print(f"Score : {result['score']}/100")
    print("Reasons:")
    for reason in result["reasons"]:
        print(f"  - {reason}")


def run_test_file(filename: str) -> None:
    with open(filename, newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            result = analyze_url(row["url"])
            print_result(result)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Defensive phishing URL detector"
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="URL to analyze"
    )
    parser.add_argument(
        "--test",
        metavar="CSV_FILE",
        help="Analyze URLs from a CSV file"
    )

    args = parser.parse_args()

    if args.test:
        run_test_file(args.test)
    elif args.url:
        print_result(analyze_url(args.url))
    else:
        parser.print_help()
