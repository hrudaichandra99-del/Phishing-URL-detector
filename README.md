# Phishing Website Detector

A Python-based cybersecurity project that detects potentially phishing URLs using blacklist matching and heuristic URL analysis.

## Features
- Checks URLs against a local blacklist of known/simulated malicious domains.
- Extracts URL characteristics such as:
  - URL length
  - Number of dots and subdomains
  - Presence of an IP address
  - Suspicious keywords
  - URL shortener domains
  - Excessive special characters
  - HTTPS usage
- Calculates a heuristic risk score.
- Classifies URLs as LOW, MEDIUM, or HIGH risk.
- Provides reasons behind the classification.
- Includes a small test dataset for validation.

## Project Structure

```text
phishing-url-detector/
├── phishing_detector.py
├── test_urls.csv
├── README.md
└── requirements.txt
```

## Installation

Python 3.9+ is recommended. The project uses only Python's standard library.

```bash
python phishing_detector.py
```

## How It Works

1. Normalize the URL.
2. Extract the domain.
3. Compare the domain against the local blacklist.
4. Analyze URL structure and suspicious indicators.
5. Assign weighted risk points.
6. Return a risk classification and explain the indicators.

## Example Output

```text
URL: https://secure-login-example.com/account/verify
Risk: HIGH
Score: 70
Reasons:
- Suspicious keyword detected: login
- Suspicious keyword detected: verify
- Domain resembles a login/verification page
```

## Limitations

This is a defensive educational project, not a replacement for commercial threat-intelligence feeds or browser security systems. A heuristic score can produce false positives and false negatives. The blacklist included in the repository is for demonstration/testing only and does not claim that the listed domains are malicious.

## Resume Description

**Phishing Website Detector — Python | Cybersecurity Project**
- Developed a Python-based URL analysis tool using blacklist matching and heuristic indicators to identify potentially phishing URLs.
- Implemented detection logic for suspicious keywords, IP-based URLs, URL length, subdomain patterns, URL shorteners, special characters, and HTTPS usage.
- Built a weighted risk-scoring system that classifies URLs and provides explainable reasons for each result.
- Validated the detection workflow using a test dataset containing benign and simulated suspicious URLs.
