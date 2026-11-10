"""Shared helpers: URL normalisation, SSRF-safe DNS/TLS, domain intelligence,
file signatures, and small formatting utilities.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import socket
import ssl
from collections.abc import Iterable
from datetime import UTC, datetime
from difflib import SequenceMatcher
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

import dns.resolver
import requests
import tldextract

USER_AGENT = "PhishGuard/0.1 (+https://github.com/ananthasudeesh/PhishGuard)"

# A bundled public-suffix snapshot avoids a network call on first use.
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in", "s.id",
    "rebrand.ly", "bl.ink", "t.ly", "shorte.st", "adf.ly", "bit.do",
    "mcaf.ee", "qr.ae", "x.co", "v.gd", "clck.ru", "u.to", "1url.com",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work",
    "click", "link", "country", "stream", "download", "racing", "win",
    "bid", "loan", "review", "science", "party", "gdn", "icu", "cyou",
    "sbs", "rest", "monster", "quest", "buzz", "lol", "autos", "boats",
    "homes", "makeup", "skin", "beauty", "mom", "bond", "cfd", "lat",
}

BRANDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "dropbox", "adobe", "dhl", "fedex",
    "ups", "usps", "bankofamerica", "chase", "wellsfargo", "hdfc", "icici",
    "sbi", "axis", "kotak", "paytm", "phonepe", "gpay", "flipkart", "myntra",
    "swiggy", "zomato", "irctc", "epfo", "incometax", "uidai", "binance",
    "coinbase", "metamask", "steam", "roblox", "discord", "telegram",
}

CREDENTIAL_WORDS = {
    "password", "passwd", "otp", "one-time", "onetime", "verify", "verification",
    "login", "log-in", "signin", "sign-in", "account", "unlock", "confirm",
    "update", "billing", "payment", "invoice", "bank", "card", "wallet",
    "seed phrase", "recovery phrase", "aadhaar", "ssn", "pan",
}

URGENCY_WORDS = {
    "urgent", "immediately", "act now", "final warning", "last chance",
    "within 24 hours", "within 48 hours", "account suspended", "suspended",
    "expires today", "expiring", "limited time", "verify now", "click now",
}

REWARD_WORDS = {
    "winner", "won", "prize", "lottery", "giveaway", "claim now", "free gift",
    "reward", "cashback", "bonus", "congratulations", "selected",
}

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "msi", "msp", "cpl", "msc", "jar",
    "apk", "dll", "sys", "drv", "lnk", "url", "reg", "iso", "img", "vhd",
    "vhdx", "vmdk", "dmg", "pkg", "app", "deb", "rpm", "run", "bin",
}

DOCUMENT_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt",
    "csv", "jpg", "jpeg", "png", "gif", "webp", "svg", "html", "htm",
    "zip", "rar", "7z", "tar", "gz",
}

MIME_BY_EXTENSION = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "ppt": "application/vnd.ms-powerpoint",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "zip": "application/zip",
    "rar": "application/vnd.rar",
    "7z": "application/x-7z-compressed",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "html": "text/html",
    "htm": "text/html",
    "txt": "text/plain",
    "csv": "text/csv",
    "exe": "application/x-dosexec",
    "js": "text/javascript",
    "ps1": "text/plain",
}

_URL_RE = re.compile(
    r"(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>\"'\]\[{}]+"
)
_BARE_DOMAIN_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|co|in|info|biz|xyz|top|site|online|shop|app|dev|"
    r"me|ly|tk|ml|ga|cf|gq|zip|mov|click|link|live|pro|store|club|icu)\b"
    r"(?:/[^\s<>\"'\]\[{}]*)?"
)


def refang(text: str) -> str:
    """Turn common defanged indicators back into normal text."""
    return (
        text.strip()
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("[at]", "@")
        .replace(" at ", "@")
    )


def normalize_url(value: str) -> str:
    value = refang(value)
    if value.startswith("//"):
        value = "https:" + value
    parsed = urlsplit(value)
    if not parsed.scheme:
        value = "https://" + value
    return value


def is_http_url(value: str) -> bool:
    try:
        parsed = urlsplit(normalize_url(value))
        return parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)
    except ValueError:
        return False


def host_from_url(value: str) -> str:
    try:
        return (urlsplit(normalize_url(value)).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def registered_domain(value: str) -> str:
    host = host_from_url(value) if "://" in value else value.lower().strip().rstrip(".")
    if not host:
        return ""
    extracted = _TLD_EXTRACT(host)
    if extracted.suffix and extracted.domain:
        return f"{extracted.domain}.{extracted.suffix}"
    return host


def domain_label(value: str) -> str:
    extracted = _TLD_EXTRACT(value.lower().strip().rstrip("."))
    return extracted.domain or value.lower().split(".")[0]


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    try:
        return not ipaddress.ip_address(value.strip("[]")).is_global
    except ValueError:
        return True


def resolve_public_ips(host: str) -> list[str]:
    """Resolve a hostname and return only globally routable addresses.

    This is the SSRF guard used before any outbound connection. If *any*
    answer is private/reserved, the host is rejected entirely.
    """
    host = host.strip().rstrip(".")
    if not host:
        return []
    if is_ip_address(host):
        return [] if is_private_ip(host) else [host.strip("[]")]

    addresses: set[str] = set()
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = 3.0
        for record_type in ("A", "AAAA"):
            try:
                for answer in resolver.resolve(host, record_type):
                    addresses.add(str(answer))
            except Exception:
                continue
    except Exception:
        pass

    if not addresses:
        try:
            for item in socket.getaddrinfo(host, None):
                addresses.add(item[4][0])
        except OSError:
            return []

    public = [address for address in addresses if not is_private_ip(address)]
    if not public or len(public) != len(addresses):
        return []
    return sorted(public)


def dns_records(domain: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = 3.0
    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            records[record_type] = [str(answer).strip('"') for answer in resolver.resolve(domain, record_type)]
        except Exception:
            records[record_type] = []
    return records


def tls_certificate(host: str) -> dict:
    """Inspect a TLS certificate by connecting to a validated public IP.

    The connection is pinned to an IP that passed :func:`resolve_public_ips`,
    while SNI/Host verification still uses the original hostname.
    """
    ips = resolve_public_ips(host)
    if not ips:
        return {"ok": False, "error": "No public IP address"}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ips[0], 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                return {
                    "ok": True,
                    "valid": True,
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "issuer": _flatten_name(cert.get("issuer", [])),
                    "subject": _flatten_name(cert.get("subject", [])),
                    "ip": ips[0],
                }
    except ssl.SSLCertVerificationError as exc:
        return {"ok": True, "valid": False, "error": str(exc), "ip": ips[0]}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "ip": ips[0]}


def _flatten_name(parts: Iterable) -> str:
    values: list[str] = []
    for group in parts:
        for key, value in group:
            if key in {"commonName", "organizationName"}:
                values.append(value)
    return ", ".join(values)


@lru_cache(maxsize=128)
def rdap_domain_age_days(domain: str) -> int | None:
    """Return domain age in days using public RDAP, or ``None``."""
    if not domain or is_ip_address(domain):
        return None
    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=6,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"},
            allow_redirects=True,
        )
        if response.status_code != 200:
            return None
        payload = response.json()
    except Exception:
        return None

    for event in payload.get("events", []):
        action = str(event.get("eventAction", "")).lower()
        if action in {"registration", "registered"}:
            date_text = str(event.get("eventDate", "")).replace("Z", "+00:00")
            try:
                registered = datetime.fromisoformat(date_text)
                if registered.tzinfo is None:
                    registered = registered.replace(tzinfo=UTC)
                return max(0, (datetime.now(UTC) - registered).days)
            except ValueError:
                return None
    return None


def extract_urls(text: str, *, include_bare_domains: bool = True) -> list[str]:
    """Extract unique URLs, preserving order and stripping punctuation."""
    if not text:
        return []
    cleaned = re.sub(r"(?i)\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", " ", text)
    spans: list[tuple[int, int, str]] = [
        (match.start(), match.end(), match.group(0)) for match in _URL_RE.finditer(cleaned)
    ]
    if include_bare_domains:
        for match in _BARE_DOMAIN_RE.finditer(cleaned):
            # Do not add "bit.ly/x" when "http://bit.ly/x" was already found.
            if any(start <= match.start() < end for start, end, _ in spans):
                continue
            spans.append((match.start(), match.end(), match.group(0)))
    spans.sort(key=lambda item: item[0])
    seen: set[tuple[str, str, str]] = set()
    result: list[str] = []
    for _start, _end, match in spans:
        value = match.rstrip(".,;:!?)]}\u2019\u201d'\"")
        value = value.replace("&amp;", "&")
        try:
            parsed = urlsplit(normalize_url(value))
            key = ((parsed.hostname or "").lower(), parsed.path.rstrip("/"), parsed.query)
        except ValueError:
            key = (value.lower().rstrip("/"), "", "")
        if key[0] and key not in seen:
            seen.add(key)
            result.append(value)
    return result


def is_shortener(host: str) -> bool:
    host = host.lower().strip(".")
    return any(host == item or host.endswith("." + item) for item in SHORTENERS)


def is_suspicious_tld(host: str) -> bool:
    suffix = _TLD_EXTRACT(host).suffix.lower()
    return bool(suffix) and suffix.split(".")[-1] in SUSPICIOUS_TLDS


def brand_token_in_host(host: str) -> str | None:
    host = host.lower()
    for brand in BRANDS:
        if len(brand) < 4:
            continue
        if brand in host:
            return brand
    return None


def _deleet(value: str) -> str:
    """Normalise common digit-for-letter substitutions used in fake domains."""
    table = str.maketrans(
        {
            "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
            "7": "t", "8": "b", "@": "a", "$": "s",
        }
    )
    return value.lower().translate(table)


def brand_is_lookalike(host: str) -> str | None:
    """Detect a registered domain that closely resembles a known brand."""
    label = domain_label(host)
    if len(label) < 5:
        return None
    normalised = _deleet(label)
    for brand in BRANDS:
        if len(brand) < 5 or label == brand:
            continue
        if normalised == brand:
            return brand
        ratio = SequenceMatcher(None, label, brand).ratio()
        ratio_normalised = SequenceMatcher(None, normalised, brand).ratio()
        if max(ratio, ratio_normalised) >= 0.82:
            return brand
    return None


def brand_in_subdomain_only(host: str) -> str | None:
    brand = brand_token_in_host(host)
    if not brand:
        return None
    registrable = registered_domain(host)
    if registrable and brand not in registrable.split(".")[0]:
        return brand
    return None


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def path_keywords(url: str) -> list[str]:
    try:
        parsed = urlsplit(normalize_url(url))
    except ValueError:
        return []
    haystack = f"{parsed.path} {parsed.query}".lower()
    return sorted({word for word in CREDENTIAL_WORDS if word in haystack})


def contains_any(text: str, words: Iterable[str]) -> list[str]:
    lowered = (text or "").lower()
    return sorted({word for word in words if word in lowered})


def hash_bytes(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def file_extension(filename: str) -> str:
    name = (filename or "").lower().strip()
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1]


def double_extension(filename: str) -> str | None:
    parts = (filename or "").lower().split(".")
    if len(parts) < 3:
        return None
    last, previous = parts[-1], parts[-2]
    if last in DANGEROUS_EXTENSIONS and previous in DOCUMENT_EXTENSIONS:
        return f"{previous}.{last}"
    return None


def detect_mime(data: bytes, filename: str = "") -> str:
    """Best-effort magic detection without a libmagic system dependency."""
    head = data[:512]
    if head.startswith(b"%PDF"):
        return "application/pdf"
    if head.startswith(b"PK\x03\x04"):
        return "application/zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/x-ole-storage"
    if head.startswith(b"MZ"):
        return "application/x-dosexec"
    if head.startswith(b"\x7fELF"):
        return "application/x-elf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp"
    if head.lstrip().startswith(b"{\\rtf"):
        return "application/rtf"
    if head.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        return "text/html"
    if head.startswith(b"Rar!\x1a\x07"):
        return "application/vnd.rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed"
    if head.startswith(b"\x1f\x8b"):
        return "application/gzip"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "application/x-tar"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "application/x-ms-shortcut"
    if len(data) > 32774 and data[32769:32774] == b"CD001":
        return "application/x-iso9660-image"
    if head.startswith(b"\xe4\x52\x5c\x7b"):
        return "application/onenote"
    if head.startswith(b"#!"):
        return "text/x-script"
    if filename and "." in filename:
        return MIME_BY_EXTENSION.get(file_extension(filename), "application/octet-stream")
    return "application/octet-stream"


def safe_truncate(value: str, limit: int = 500) -> str:
    value = value or ""
    return value if len(value) <= limit else value[: limit - 1] + "…"


def strip_url_fragment(url: str) -> str:
    try:
        parsed = urlsplit(url)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
    except ValueError:
        return url
