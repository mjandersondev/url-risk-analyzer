import re
import tldextract
from urllib.parse import urlparse

def analyze(url: str) -> dict:
    findings = []
    score = 0

    parsed = urlparse(url if "://" in url else "http://" + url)
    ext = tldextract.extract(url)
    host = parsed.hostname or ""

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 30
        findings.append("Uses an IP address instead of a domain name")

    if ext.subdomain.count(".") >= 2:
        score +=15
        findings.append("Unusually many subdomains")

    if "@" in url:
        score += 25
        findings.append("Contains '@', which can hide the real destination")

    if parsed.scheme != "https":
        score += 10
        findings.append("Does not use HTTPS")

    if len(url) > 100:
        score += 10
        findings.append("Unusually long url")

    return {"url": url, "score": min(score, 100), "findings": findings}

if __name__ == "__main__":
    url = input("Enter a URL: ")
    print(analyze(url))
    
        