import ipaddress
import re
import socket
import tldextract
import requests
from urllib.parse import urlparse, urljoin

    # static checks with relevant scoring
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

# redirect check
MAX_HOPS = 10
TIMEOUT = 5
REDIRECT_CODES = {301, 302, 303, 307, 308}
SHORTENERS = {
    "tinyurl.com", "buff.ly", "cutt.ly", "rebrand.ly", "ow.ly",
    "bit.ly", "goo.gl", "is.gd", "t.co"
}

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; URLAnalyzer/0.1)"}

def _domain_of(url: str) -> str:
    """Registered domain (e.g. 'example.co.uk') for comparing hops."""
    host = urlparse(url).hostname or ""
    ext = tldextract.extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else host
 
 
def is_unsafe_target(url: str) -> bool:
    """True if the URL resolves to a private/internal address.
 
    Important for a public website: without this, someone could paste a link
    that redirects to http://localhost or a cloud metadata address and use
    your server to probe your own network (SSRF attack).
    """
    host = urlparse(url).hostname
    if not host:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False  # doesn't resolve; the request will fail on its own
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            return True
    return False
 
 
def trace_redirects(url: str) -> dict:
    """Follow redirects one hop at a time, without downloading page bodies.
 
    Returns {"chain": [urls...], "status": ...} where status is one of:
    "ok", "loop", "too_many", "blocked_start", "blocked_hop", "error".
    """
    current = url if "://" in url else "http://" + url
    chain = [current]
    seen = {current}
 
    for _ in range(MAX_HOPS):
        if is_unsafe_target(current):
            status = "blocked_start" if len(chain) == 1 else "blocked_hop"
            return {"chain": chain, "status": status}
 
        try:
            resp = requests.get(
                current, headers=HEADERS, timeout=TIMEOUT,
                allow_redirects=False, stream=True,  # stream: don't read body
            )
            resp.close()
        except requests.RequestException as exc:
            return {"chain": chain, "status": "error", "error": type(exc).__name__}
 
        location = resp.headers.get("Location")
        if resp.status_code not in REDIRECT_CODES or not location:
            return {"chain": chain, "status": "ok"}  # reached the destination
 
        nxt = urljoin(current, location)  # handles relative Location headers
        if urlparse(nxt).scheme not in ("http", "https"):
            return {"chain": chain + [nxt], "status": "blocked_hop"}
        if nxt in seen:
            return {"chain": chain + [nxt], "status": "loop"}
 
        chain.append(nxt)
        seen.add(nxt)
        current = nxt
 
    return {"chain": chain, "status": "too_many"}
 
 
def analyze_redirects(url: str) -> dict:
    findings = []
    score = 0
 
    trace = trace_redirects(url)
    chain, status = trace["chain"], trace["status"]
    hops = len(chain) - 1
 
    if status == "blocked_start":
        findings.append("Redirect check skipped: URL points to a private/internal address")
        return {"chain": chain, "final_url": chain[-1], "score": 0, "findings": findings}
 
    if status == "error":
        findings.append(f"Could not fully trace redirects ({trace['error']})")
    elif status == "loop":
        score += 20
        findings.append("Redirect loop detected")
    elif status == "too_many":
        score += 20
        findings.append(f"More than {MAX_HOPS} redirects")
    elif status == "blocked_hop":
        score += 30
        findings.append("Redirects to a private/internal address or non-web scheme")
 
    if hops >= 3:
        score += 10
        findings.append(f"Long redirect chain ({hops} hops)")
    if hops >= 6:
        score += 10
 
    hosts = [urlparse(u).hostname or "" for u in chain]
    if any(h in SHORTENERS for h in hosts):
        score += 10
        findings.append("Passes through a URL shortener, which hides the destination")
 
    domains = [_domain_of(u) for u in chain]
    distinct = list(dict.fromkeys(domains))  # keeps order, drops repeats
    if len(distinct) >= 2:
        score += 10
        findings.append(f"Redirects across {len(distinct)} different domains")
    if len(distinct) >= 4:
        score += 15
 
    for a, b in zip(chain, chain[1:]):
        if urlparse(a).scheme == "https" and urlparse(b).scheme == "http":
            score += 20
            findings.append("Downgrades from HTTPS to HTTP during redirect")
            break
 
    if any(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h) and h != hosts[0]
           for h in hosts[1:]):
        score += 25
        findings.append("Redirects to a bare IP address")
 
    # Run the static checks on where the link actually ends up
    final_url = chain[-1]
    if hops > 0 and status in ("ok", "loop", "too_many"):
        final = analyze(final_url)
        if final["score"] > 0:
            score += final["score"]
            findings += [f"Final destination: {f}" for f in final["findings"]]
 
    return {
        "chain": chain,
        "final_url": final_url,
        "score": min(score, 100),
        "findings": findings,
    }
 
 
def analyze_full(url: str) -> dict:
    """Static checks on the pasted URL + redirect analysis, combined."""
    static = analyze(url)
    redirects = analyze_redirects(url)
    score = static["score"] + redirects["score"]
    findings = static["findings"] + redirects["findings"]
 
    # An http:// link that immediately upgrades to https:// on the same
    # domain is harmless, so don't penalize it for lacking HTTPS.
    chain = redirects["chain"]
    if len(chain) > 1:
        first, second = urlparse(chain[0]), urlparse(chain[1])
        if (first.scheme == "http" and second.scheme == "https"
                and _domain_of(chain[0]) == _domain_of(chain[1])
                and "Does not use HTTPS" in findings):
            findings.remove("Does not use HTTPS")
            score -= 10
 
    return {
        "url": url,
        "score": max(min(score, 100), 0),
        "findings": findings,
        "redirect_chain": redirects["chain"],
        "final_url": redirects["final_url"],
    }
 
 
if __name__ == "__main__":
    url = input("Enter a URL: ")
    result = analyze_full(url)
    print(f"\nRisk score: {result['score']}/100")
    for f in result["findings"]:
        print(f" - {f}")
    print("\nRedirect chain:")
    for i, hop in enumerate(result["redirect_chain"]):
        print(f"  {i}. {hop}")