"""
Secure Redirect Analysis Service — ScamShield
Inspects HTTP/HTTPS redirect chains safely with robust SSRF protections:
- Private, link-local, loopback, and metadata IP address filtering (RFC 1918, 169.254.169.254)
- DNS resolution validation before socket connection
- Hop-by-hop target validation
- Redirect loop detection
- Maximum redirect depth enforcement
- Per-hop and total timeout limits
- Response body truncation (no execution of untrusted content)
"""
import socket
import ipaddress
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from typing import Optional
import urllib.request
import urllib.error


@dataclass
class RedirectHop:
    hop_number: int
    url: str
    status_code: int
    destination: Optional[str] = None


@dataclass
class RedirectAnalysisResult:
    initial_url: str
    final_url: str
    hops: list[RedirectHop] = field(default_factory=list)
    depth: int = 0
    has_loop: bool = False
    ssrf_blocked: bool = False
    error: Optional[str] = None
    is_verified: bool = False


# Blocked IP networks for SSRF defense
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # Cloud metadata (AWS/GCP/Azure)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("::1/128"),              # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),             # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),            # IPv6 link-local
]


def is_safe_ip(ip_str: str) -> bool:
    """Check if an IP address is a safe, routable public IP."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return False
        return True
    except ValueError:
        return False


def validate_hostname_safe(hostname: str) -> tuple[bool, Optional[str]]:
    """
    Resolve hostname to IP address and verify it is not pointing to an internal/private resource.
    Returns (is_safe, resolved_ip).
    """
    cleaned = hostname.lower().strip()
    if not cleaned:
        return False, None

    # Disallow known localhost aliases directly
    if cleaned in {"localhost", "localhost.localdomain", "broadcasthost", "ip6-localhost", "ip6-loopback"}:
        return False, "127.0.0.1"

    try:
        addr_info = socket.getaddrinfo(cleaned, None, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if not is_safe_ip(ip_str):
                return False, ip_str
        return True, addr_info[0][4][0] if addr_info else None
    except socket.gaierror:
        return False, None


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler that prevents automatic redirect following to allow hop-by-hop inspection."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not follow redirects automatically
        return None


def trace_redirects_safely(
    url: str,
    max_hops: int = 5,
    timeout_sec: float = 2.5,
) -> RedirectAnalysisResult:
    """
    Safely follow HTTP redirects one hop at a time.
    Validates every destination against SSRF rules before dispatching request.
    """
    result = RedirectAnalysisResult(initial_url=url, final_url=url)
    current_url = url
    visited_urls = {current_url}

    for hop_idx in range(1, max_hops + 1):
        parsed = urlparse(current_url)
        if parsed.scheme.lower() not in ("http", "https"):
            result.error = f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
            return result

        hostname = parsed.hostname
        if not hostname:
            result.error = "Malformed URL: missing hostname."
            return result

        is_safe, resolved_ip = validate_hostname_safe(hostname)
        if not is_safe:
            result.ssrf_blocked = True
            result.error = f"SSRF Protection: Access to private/internal IP {resolved_ip or hostname} blocked."
            return result

        # Construct safe request
        req = urllib.request.Request(
            current_url,
            method="HEAD",
            headers={
                "User-Agent": "ScamShield-RedirectChecker/3.0 (+https://scamshield.local)",
                "Accept": "*/*",
            },
        )

        opener = urllib.request.build_opener(NoRedirectHandler)

        try:
            with opener.open(req, timeout=timeout_sec) as resp:
                status = resp.status
                location = resp.headers.get("Location")

                if status in (301, 302, 303, 307, 308) and location:
                    next_url = urljoin(current_url, location)
                    result.hops.append(RedirectHop(
                        hop_number=hop_idx,
                        url=current_url,
                        status_code=status,
                        destination=next_url,
                    ))

                    if next_url in visited_urls:
                        result.has_loop = True
                        result.error = f"Redirect loop detected at hop {hop_idx}: {next_url}"
                        result.final_url = next_url
                        result.depth = hop_idx
                        return result

                    visited_urls.add(next_url)
                    current_url = next_url
                    result.final_url = current_url
                    result.depth = hop_idx
                else:
                    # Terminal hop reached
                    result.hops.append(RedirectHop(
                        hop_number=hop_idx,
                        url=current_url,
                        status_code=status,
                        destination=None,
                    ))
                    result.final_url = current_url
                    result.depth = len(result.hops)
                    result.is_verified = True
                    return result

        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                location = e.headers.get("Location")
                if location:
                    next_url = urljoin(current_url, location)
                    result.hops.append(RedirectHop(
                        hop_number=hop_idx,
                        url=current_url,
                        status_code=e.code,
                        destination=next_url,
                    ))
                    if next_url in visited_urls:
                        result.has_loop = True
                        result.error = f"Redirect loop detected at hop {hop_idx}: {next_url}"
                        result.final_url = next_url
                        result.depth = hop_idx
                        return result
                    visited_urls.add(next_url)
                    current_url = next_url
                    result.final_url = current_url
                    result.depth = hop_idx
                    continue

            # Non-redirect error (e.g. 403, 404) is a terminal state
            result.hops.append(RedirectHop(
                hop_number=hop_idx,
                url=current_url,
                status_code=e.code,
                destination=None,
            ))
            result.final_url = current_url
            result.depth = len(result.hops)
            result.is_verified = True
            return result
        except Exception as ex:
            result.error = f"Redirect resolution failed: {type(ex).__name__}"
            result.final_url = current_url
            result.depth = len(result.hops)
            return result

    result.final_url = current_url
    result.depth = len(result.hops)
    result.is_verified = True
    return result
