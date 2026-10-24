"""
Brand Domain Registry — ScamShield
Explicit registry of verified brand domains, aliases, official short-links,
and lookalike / impersonation detection logic.
"""
from dataclasses import dataclass, field
from typing import Optional
import unicodedata
import tldextract

# Initialize offline extractor (does not make network requests)
_extract = tldextract.TLDExtract(suffix_list_urls=None)


@dataclass
class BrandRecord:
    brand_id: str
    display_name: str
    official_domains: set[str]
    approved_subdomains: set[str] = field(default_factory=set)
    official_shorteners: set[str] = field(default_factory=set)
    keywords: list[str] = field(default_factory=list)
    source: str = "IANA/Official Security Disclosures"
    last_verified: str = "2026-10-19"


# Explicit Brand Registry
BRAND_REGISTRY: dict[str, BrandRecord] = {
    "instagram": BrandRecord(
        brand_id="instagram",
        display_name="Instagram",
        official_domains={"instagram.com", "cdninstagram.com", "threads.net"},
        approved_subdomains={"www", "help", "about", "business", "graph", "api", "i"},
        official_shorteners={"ig.me"},
        keywords=["instagram", "threads"],
    ),
    "snapchat": BrandRecord(
        brand_id="snapchat",
        display_name="Snapchat",
        official_domains={"snapchat.com", "snap.com", "sc-cdn.net"},
        approved_subdomains={"www", "story", "support", "business", "map", "ads", "web"},
        official_shorteners={"snapchat.com"},
        keywords=["snapchat"],
    ),
    "facebook": BrandRecord(
        brand_id="facebook",
        display_name="Facebook / Meta",
        official_domains={"facebook.com", "meta.com", "messenger.com"},
        approved_subdomains={"www", "m", "mobile", "business", "developers", "touch", "web"},
        official_shorteners={"fb.com", "fb.me", "m.me"},
        keywords=["facebook", "messenger"],
    ),
    "whatsapp": BrandRecord(
        brand_id="whatsapp",
        display_name="WhatsApp",
        official_domains={"whatsapp.com", "whatsapp.net"},
        approved_subdomains={"www", "web", "api", "chat", "v"},
        official_shorteners={"wa.me"},
        keywords=["whatsapp"],
    ),
    "youtube": BrandRecord(
        brand_id="youtube",
        display_name="YouTube",
        official_domains={"youtube.com", "ytimg.com"},
        approved_subdomains={"www", "m", "music", "gaming", "studio"},
        official_shorteners={"youtu.be"},
        keywords=["youtube"],
    ),
    "google": BrandRecord(
        brand_id="google",
        display_name="Google",
        official_domains={"google.com", "gmail.com", "googlemail.com", "googleapis.com", "gstatic.com"},
        approved_subdomains={"www", "accounts", "drive", "docs", "mail", "maps", "play", "support"},
        official_shorteners={"goo.gl"},
        keywords=["google", "gmail"],
    ),
    "microsoft": BrandRecord(
        brand_id="microsoft",
        display_name="Microsoft",
        official_domains={"microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com", "msn.com", "bing.com", "azure.com"},
        approved_subdomains={"www", "login", "portal", "account", "support"},
        official_shorteners={"msft.it", "aka.ms"},
        keywords=["microsoft", "outlook", "office365"],
    ),
    "apple": BrandRecord(
        brand_id="apple",
        display_name="Apple",
        official_domains={"apple.com", "icloud.com"},
        approved_subdomains={"www", "support", "developer", "id", "music", "tv"},
        official_shorteners={"apple.co"},
        keywords=["apple", "icloud"],
    ),
    "amazon": BrandRecord(
        brand_id="amazon",
        display_name="Amazon",
        official_domains={"amazon.com", "aws.amazon.com", "media-amazon.com"},
        approved_subdomains={"www", "smile", "pay", "sellercentral"},
        official_shorteners={"amzn.to"},
        keywords=["amazon"],
    ),
    "paypal": BrandRecord(
        brand_id="paypal",
        display_name="PayPal",
        official_domains={"paypal.com", "paypalobjects.com"},
        approved_subdomains={"www", "history"},
        official_shorteners={"paypal.me"},
        keywords=["paypal"],
    ),
    "netflix": BrandRecord(
        brand_id="netflix",
        display_name="Netflix",
        official_domains={"netflix.com"},
        approved_subdomains={"www", "help", "jobs"},
        official_shorteners={},
        keywords=["netflix"],
    ),
    "linkedin": BrandRecord(
        brand_id="linkedin",
        display_name="LinkedIn",
        official_domains={"linkedin.com"},
        approved_subdomains={"www", "media"},
        official_shorteners={"lnkd.in"},
        keywords=["linkedin"],
    ),
    "twitter": BrandRecord(
        brand_id="twitter",
        display_name="X / Twitter",
        official_domains={"twitter.com", "x.com"},
        approved_subdomains={"www", "mobile", "api", "help"},
        official_shorteners={"t.co"},
        keywords=["twitter"],
    ),
    "tiktok": BrandRecord(
        brand_id="tiktok",
        display_name="TikTok",
        official_domains={"tiktok.com", "tiktokv.com"},
        approved_subdomains={"www", "m", "ads", "business"},
        official_shorteners={"vt.tiktok.com"},
        keywords=["tiktok"],
    ),
    "spotify": BrandRecord(
        brand_id="spotify",
        display_name="Spotify",
        official_domains={"spotify.com", "scdn.co"},
        approved_subdomains={"www", "open", "artists"},
        official_shorteners={"spoti.fi"},
        keywords=["spotify"],
    ),
    "telegram": BrandRecord(
        brand_id="telegram",
        display_name="Telegram",
        official_domains={"telegram.org"},
        approved_subdomains={"web", "desktop", "api"},
        official_shorteners={"t.me"},
        keywords=["telegram"],
    ),
    "discord": BrandRecord(
        brand_id="discord",
        display_name="Discord",
        official_domains={"discord.com", "discordapp.com"},
        approved_subdomains={"www", "canary", "ptb", "support"},
        official_shorteners={"discord.gg"},
        keywords=["discord"],
    ),
    "github": BrandRecord(
        brand_id="github",
        display_name="GitHub",
        official_domains={"github.com", "github.io", "githubassets.com"},
        approved_subdomains={"www", "api", "raw", "gist"},
        official_shorteners={"git.io"},
        keywords=["github"],
    ),
    "chase": BrandRecord(
        brand_id="chase",
        display_name="JPMorgan Chase",
        official_domains={"chase.com"},
        approved_subdomains={"www", "secure01a", "secure03a"},
        keywords=["chase"],
    ),
    "bankofamerica": BrandRecord(
        brand_id="bankofamerica",
        display_name="Bank of America",
        official_domains={"bankofamerica.com", "bofa.com"},
        approved_subdomains={"www", "secure"},
        keywords=["bankofamerica", "bofa"],
    ),
    "wellsfargo": BrandRecord(
        brand_id="wellsfargo",
        display_name="Wells Fargo",
        official_domains={"wellsfargo.com"},
        approved_subdomains={"www", "connect"},
        keywords=["wellsfargo"],
    ),
    "sbi": BrandRecord(
        brand_id="sbi",
        display_name="State Bank of India",
        official_domains={"sbi.co.in", "onlinesbi.sbi", "statebankofindia.com"},
        approved_subdomains={"www", "retail", "merchant"},
        keywords=["onlinesbi", "statebankofindia"],
    ),
    "hdfc": BrandRecord(
        brand_id="hdfc",
        display_name="HDFC Bank",
        official_domains={"hdfcbank.com"},
        approved_subdomains={"www", "netbanking"},
        keywords=["hdfcbank"],
    ),
    "icici": BrandRecord(
        brand_id="icici",
        display_name="ICICI Bank",
        official_domains={"icicibank.com"},
        approved_subdomains={"www", "infinity"},
        keywords=["icicibank"],
    ),
    "binance": BrandRecord(
        brand_id="binance",
        display_name="Binance",
        official_domains={"binance.com"},
        approved_subdomains={"www", "accounts", "api"},
        keywords=["binance"],
    ),
    "coinbase": BrandRecord(
        brand_id="coinbase",
        display_name="Coinbase",
        official_domains={"coinbase.com"},
        approved_subdomains={"www", "pro"},
        keywords=["coinbase"],
    ),
}

# Aggregate all official domains & shorteners for O(1) checks
ALL_OFFICIAL_DOMAINS: set[str] = set()
ALL_OFFICIAL_SHORTENERS: set[str] = set()
for b in BRAND_REGISTRY.values():
    ALL_OFFICIAL_DOMAINS.update(b.official_domains)
    ALL_OFFICIAL_SHORTENERS.update(b.official_shorteners)

# Add generic well-known legitimate domains
ADDITIONAL_LEGITIMATE_DOMAINS = {
    "wikipedia.org", "wikimedia.org", "reddit.com", "redd.it", "dropbox.com",
    "zoom.us", "ebay.com", "openai.com", "chatgpt.com", "steamcommunity.com",
    "steampowered.com", "twitch.tv", "pinterest.com", "roblox.com", "epicgames.com",
    "stackoverflow.com", "cloudflare.com", "mozilla.org", "w3.org", "ietf.org",
    "cnn.com", "bbc.com", "nytimes.com", "theguardian.com", "reuters.com",
}
ALL_OFFICIAL_DOMAINS.update(ADDITIONAL_LEGITIMATE_DOMAINS)


def extract_domain_info(hostname: str) -> tuple[str, str, str]:
    """
    Extract (subdomain, domain_label, suffix) using tldextract.
    Example: 'm.instagram.co.uk' -> ('m', 'instagram', 'co.uk')
    """
    cleaned = hostname.lower().strip().rstrip(".")
    ext = _extract(cleaned)
    domain_label = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain
    root_domain = f"{domain_label}.{suffix}" if suffix else domain_label
    return subdomain, root_domain, domain_label, suffix


def is_official_domain(hostname: str) -> Optional[BrandRecord]:
    """
    Check if a hostname belongs to an official brand or verified legitimate service.
    Returns the matching BrandRecord if found, else None.
    Handles exact match, subdomains, and country-code variations.
    """
    cleaned = hostname.lower().strip().rstrip(".")
    subdomain, root_domain, domain_label, suffix = extract_domain_info(cleaned)

    # 1. Exact match against official root domains or shorteners
    if root_domain in ALL_OFFICIAL_DOMAINS or root_domain in ALL_OFFICIAL_SHORTENERS:
        for record in BRAND_REGISTRY.values():
            if root_domain in record.official_domains or root_domain in record.official_shorteners:
                return record
        return BrandRecord(
            brand_id="verified_service",
            display_name=root_domain,
            official_domains={root_domain},
        )

    # 2. Check each brand's domain patterns (including ccTLD variations like amazon.co.in)
    for record in BRAND_REGISTRY.values():
        for off_dom in record.official_domains:
            # Suffix match on host boundary: e.g. 'help.instagram.com' ends with '.instagram.com'
            if cleaned == off_dom or cleaned.endswith("." + off_dom):
                return record
            # ccTLD variations where brand domain matches domain_label
            # e.g. domain_label='amazon' with official domain 'amazon.com'
            off_ext = _extract(off_dom)
            if domain_label == off_ext.domain and domain_label in record.keywords:
                # Valid brand presence on recognized ccTLD
                # Make sure it's not a known free/abused TLD
                if suffix not in {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "win", "loan"}:
                    return record

        for short in record.official_shorteners:
            if cleaned == short or cleaned.endswith("." + short):
                return record

    return None


@dataclass
class BrandCheckFinding:
    is_impersonation: bool
    brand: Optional[BrandRecord]
    confidence: str  # "high" | "medium" | "low"
    reason: str
    details: str


def check_brand_impersonation(hostname: str) -> Optional[BrandCheckFinding]:
    """
    Examine a hostname to see if it is deceptively impersonating a known brand.
    Proper boundary checks ensure legitimate subdomains are never flagged.
    """
    cleaned = hostname.lower().strip().rstrip(".")
    official = is_official_domain(cleaned)
    if official:
        # Hostname is legitimate official domain — NOT impersonation
        return None

    subdomain, root_domain, domain_label, suffix = extract_domain_info(cleaned)

    # Check for brand keywords placed in deceptive positions
    for brand_id, record in BRAND_REGISTRY.items():
        for kw in record.keywords:
            if len(kw) < 4:
                continue

            # Check 1: Brand keyword inside the registered domain label but domain is NOT official
            # e.g., 'instagram-verify.com', 'secure-paypal-login.net'
            if kw in domain_label and domain_label != kw:
                return BrandCheckFinding(
                    is_impersonation=True,
                    brand=record,
                    confidence="high",
                    reason=f"Domain name '{root_domain}' contains brand name '{record.display_name}' but is not an official domain.",
                    details=f"Target: {record.display_name}. Real registered domain: {root_domain}. Official domains: {', '.join(sorted(record.official_domains)[:3])}.",
                )

            # Check 2: Brand keyword as a subdomain on an unrelated domain
            # e.g., 'instagram.com.attacker-controlled.net', 'paypal.security-update.xyz'
            sub_parts = subdomain.split(".") if subdomain else []
            if kw in sub_parts or any(p.startswith(kw) or p.endswith(kw) for p in sub_parts):
                return BrandCheckFinding(
                    is_impersonation=True,
                    brand=record,
                    confidence="high",
                    reason=f"Subdomain contains '{kw}' on an unrelated host '{root_domain}'.",
                    details=f"Attackers use deceptive subdomains to mimic {record.display_name}. Real destination is {root_domain}.",
                )

    return None
