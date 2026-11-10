"""URL / link analyzer.

The public deployment deliberately does **not** fetch or render the page.
It uses lexical analysis, DNS, TLS, RDAP and opt-in threat intelligence.
That keeps the app from becoming an SSRF proxy or a browser-based malware
sandbox.
"""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlsplit

from ..intel import IntelClient
from ..models import AnalysisResult, Severity, Signal
from ..scoring import finalize
from ..utils import (
    brand_in_subdomain_only,
    brand_is_lookalike,
    brand_token_in_host,
    dns_records,
    file_extension,
    is_ip_address,
    is_private_ip,
    is_shortener,
    is_suspicious_tld,
    normalize_url,
    path_keywords,
    rdap_domain_age_days,
    registered_domain,
    resolve_public_ips,
    safe_truncate,
    shannon_entropy,
    tls_certificate,
)


def analyze_url(
    raw_url: str,
    *,
    use_intel: bool = False,
    online: bool = True,
    intel: IntelClient | None = None,
) -> AnalysisResult:
    target = (raw_url or "").strip()
    result = AnalysisResult(analyzer="URL", target=target)
    if not target:
        result.error = "No URL supplied"
        return finalize(result)

    try:
        normalized = normalize_url(target)
        parsed = urlsplit(normalized)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError as exc:
        result.error = f"Invalid URL: {exc}"
        return finalize(result)

    if parsed.scheme.lower() not in {"http", "https"}:
        result.add(
            Signal(
                id="url.unsupported_scheme",
                title="Unsupported or dangerous URL scheme",
                severity=Severity.HIGH,
                category="url",
                description="Only http and https links are safe to inspect as web addresses.",
                evidence=parsed.scheme,
                weight=45,
            )
        )
        return finalize(result)

    if not host:
        result.error = "The URL has no hostname"
        return finalize(result)

    registrable = registered_domain(host)
    result.metadata.update(
        {
            "normalized": normalized,
            "scheme": parsed.scheme.lower(),
            "host": host,
            "registered_domain": registrable,
            "port": parsed.port,
            "path": safe_truncate(parsed.path, 300),
            "query": safe_truncate(parsed.query, 300),
            "ip_literal": is_ip_address(host),
            "checks": "passive (no page fetch)",
        }
    )

    result.add(
        Signal(
            id="url.valid",
            title="URL parsed successfully",
            severity=Severity.INFO,
            category="url",
            description="The input is a syntactically valid http(s) URL.",
            evidence=normalized,
            weight=0,
        )
    )

    _lexical_signals(result, normalized, parsed, host, registrable)

    if online:
        _network_signals(result, host, registrable, parsed.scheme.lower(), use_intel, intel)

    if use_intel and intel:
        _intel_signals(result, normalized, registrable, host, intel)

    result.recommendations = [
        "Do not enter credentials or payment details after following an unexpected link.",
        "Verify the registered domain through the organisation's official app or website.",
        "If the link arrived by email or social media, report the message and delete it.",
    ]
    return finalize(result)


def _lexical_signals(result: AnalysisResult, normalized: str, parsed, host: str, registrable: str) -> None:
    if parsed.username or parsed.password:
        result.add(
            Signal(
                id="url.userinfo",
                title="URL contains embedded credentials",
                severity=Severity.HIGH,
                category="url",
                description="Text before '@' can disguise the real destination.",
                evidence=safe_truncate(normalized, 250),
                weight=30,
            )
        )

    if is_ip_address(host):
        result.add(
            Signal(
                id="url.ip_literal",
                title="Link uses a raw IP address",
                severity=Severity.MEDIUM,
                category="url",
                description="Legitimate consumer services normally use a domain name.",
                evidence=host,
                weight=25,
            )
        )
        if is_private_ip(host):
            result.add(
                Signal(
                    id="url.private_ip",
                    title="Link points to a private or reserved IP",
                    severity=Severity.CRITICAL,
                    category="url",
                    description="This can target internal networks and should never be opened.",
                    evidence=host,
                    weight=70,
                )
            )

    if host.startswith("xn--") or ".xn--" in host:
        result.add(
            Signal(
                id="url.punycode",
                title="Punycode / internationalised domain",
                severity=Severity.MEDIUM,
                category="url",
                description="Punycode can hide lookalike Unicode characters.",
                evidence=host,
                weight=25,
            )
        )
    elif any(ord(char) > 127 for char in host):
        result.add(
            Signal(
                id="url.non_ascii_host",
                title="Non-ASCII characters in hostname",
                severity=Severity.MEDIUM,
                category="url",
                description="Unicode hostnames can imitate well-known brands.",
                evidence=host,
                weight=20,
            )
        )

    labels = [label for label in host.split(".") if label]
    if len(labels) >= 5:
        result.add(
            Signal(
                id="url.many_subdomains",
                title="Unusually deep subdomain chain",
                severity=Severity.LOW,
                category="url",
                description="Long subdomain chains are often used to bury the real domain.",
                evidence=host,
                weight=12,
            )
        )

    if is_suspicious_tld(host):
        result.add(
            Signal(
                id="url.suspicious_tld",
                title="High-risk top-level domain",
                severity=Severity.MEDIUM,
                category="url",
                description="This TLD is frequently abused for low-cost phishing campaigns.",
                evidence=host,
                weight=15,
            )
        )

    if is_shortener(host):
        result.add(
            Signal(
                id="url.shortener",
                title="URL shortener hides the destination",
                severity=Severity.MEDIUM,
                category="url",
                description="The visible link does not reveal where it will take the user.",
                evidence=host,
                weight=12,
            )
        )

    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and port not in {80, 443}:
        result.add(
            Signal(
                id="url.unusual_port",
                title="Unusual network port",
                severity=Severity.MEDIUM,
                category="url",
                description="Phishing infrastructure often uses non-standard ports.",
                evidence=str(port),
                weight=12,
            )
        )

    if parsed.scheme.lower() == "http":
        result.add(
            Signal(
                id="url.no_https",
                title="Link does not use HTTPS",
                severity=Severity.LOW,
                category="url",
                description="Traffic can be intercepted or modified in transit.",
                evidence=normalized,
                weight=5,
            )
        )

    if len(normalized) > 200:
        weight = 15
    elif len(normalized) > 120:
        weight = 8
    else:
        weight = 0
    if weight:
        result.add(
            Signal(
                id="url.long",
                title="Very long URL",
                severity=Severity.LOW,
                category="url",
                description="Long URLs can hide the destination or push it out of view.",
                evidence=f"{len(normalized)} characters",
                weight=weight,
            )
        )

    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        result.add(
            Signal(
                id="url.many_hyphens",
                title="Many hyphens in hostname",
                severity=Severity.LOW,
                category="url",
                description="Attackers often combine brand words with hyphens in fake domains.",
                evidence=host,
                weight=8,
            )
        )

    digit_count = sum(char.isdigit() for char in host)
    if digit_count >= 4:
        result.add(
            Signal(
                id="url.many_digits",
                title="Digit-heavy hostname",
                severity=Severity.LOW,
                category="url",
                description="Random-looking digits are common in disposable phishing domains.",
                evidence=host,
                weight=5,
            )
        )

    lookalike = brand_is_lookalike(host)
    if lookalike:
        result.add(
            Signal(
                id="url.brand_lookalike",
                title="Domain closely resembles a known brand",
                severity=Severity.HIGH,
                category="url",
                description=f"The registered domain looks similar to '{lookalike}'.",
                evidence=registrable,
                weight=35,
            )
        )

    subdomain_brand = brand_in_subdomain_only(host)
    if subdomain_brand:
        result.add(
            Signal(
                id="url.brand_subdomain",
                title="Brand name appears only in a subdomain",
                severity=Severity.HIGH,
                category="url",
                description=f"'{subdomain_brand}' is not the registered domain; the real owner is different.",
                evidence=f"{host} -> {registrable}",
                weight=28,
            )
        )
    elif brand_token_in_host(host) and not lookalike:
        brand = brand_token_in_host(host)
        result.add(
            Signal(
                id="url.brand_token",
                title="Brand name in hostname",
                severity=Severity.LOW,
                category="url",
                description=f"'{brand}' appears in the host; confirm the registered domain is official.",
                evidence=registrable,
                weight=8,
            )
        )

    keywords = path_keywords(normalized)
    if keywords:
        result.add(
            Signal(
                id="url.credential_keywords",
                title="Credential or payment language in the URL",
                severity=Severity.MEDIUM,
                category="url",
                description="Paths containing login, verify, invoice, or payment words are common in phishing.",
                evidence=", ".join(keywords[:6]),
                weight=10,
            )
        )

    if file_extension(parsed.path) in {
        "exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "hta", "msi",
        "apk", "jar", "lnk", "iso", "img",
    }:
        result.add(
            Signal(
                id="url.executable_download",
                title="Link points to an executable download",
                severity=Severity.HIGH,
                category="url",
                description="Opening this link may download a program rather than a web page.",
                evidence=parsed.path,
                weight=30,
            )
        )

    if normalized.count("%") >= 5:
        result.add(
            Signal(
                id="url.heavy_encoding",
                title="Heavily percent-encoded URL",
                severity=Severity.LOW,
                category="url",
                description="Encoding can be used to hide keywords from casual inspection.",
                evidence=f"{normalized.count('%')} encoded characters",
                weight=8,
            )
        )

    if shannon_entropy(host) > 3.7 and len(host) > 20:
        result.add(
            Signal(
                id="url.high_entropy_host",
                title="Random-looking hostname",
                severity=Severity.LOW,
                category="url",
                description="High-entropy hostnames can indicate automatically generated infrastructure.",
                evidence=host,
                weight=10,
            )
        )


def _network_signals(
    result: AnalysisResult,
    host: str,
    registrable: str,
    scheme: str,
    use_intel: bool,
    intel: IntelClient | None,
) -> None:
    ips = resolve_public_ips(host)
    result.metadata["resolved_ips"] = ips
    if not ips:
        result.add(
            Signal(
                id="url.no_public_dns",
                title="Hostname does not resolve to a public address",
                severity=Severity.HIGH,
                category="url",
                description="The domain may be inactive, internal, or intentionally hidden.",
                evidence=host,
                weight=25,
            )
        )
        return

    records = dns_records(registrable)
    result.metadata["dns"] = {key: values[:4] for key, values in records.items()}
    if not records.get("NS"):
        result.add(
            Signal(
                id="url.no_ns",
                title="No name-server records found",
                severity=Severity.MEDIUM,
                category="url",
                description="A domain without NS records is unusual for a live public service.",
                evidence=registrable,
                weight=15,
            )
        )

    age = intel.domain_age(registrable) if intel else rdap_domain_age_days(registrable)
    result.metadata["domain_age_days"] = age
    if age is not None:
        if age < 30:
            result.add(
                Signal(
                    id="url.new_domain",
                    title="Domain is very new",
                    severity=Severity.HIGH,
                    category="url",
                    description="Domains registered within the last 30 days are heavily used in phishing.",
                    evidence=f"{age} days old",
                    weight=30,
                )
            )
        elif age < 90:
            result.add(
                Signal(
                    id="url.recent_domain",
                    title="Domain is recently registered",
                    severity=Severity.MEDIUM,
                    category="url",
                    description="New domains have less reputation history.",
                    evidence=f"{age} days old",
                    weight=15,
                )
            )

    if scheme == "https":
        certificate = tls_certificate(host)
        result.metadata["tls"] = certificate
        if not certificate.get("ok"):
            result.add(
                Signal(
                    id="url.tls_failed",
                    title="Could not establish a valid TLS connection",
                    severity=Severity.MEDIUM,
                    category="url",
                    description="The site may be unavailable, misconfigured, or blocking inspection.",
                    evidence=str(certificate.get("error", "unknown"))[:200],
                    weight=15,
                )
            )
        elif certificate.get("valid") is False:
            result.add(
                Signal(
                    id="url.tls_invalid",
                    title="TLS certificate is invalid",
                    severity=Severity.HIGH,
                    category="url",
                    description="A certificate error means the connection cannot be trusted.",
                    evidence=str(certificate.get("error", ""))[:200],
                    weight=30,
                )
            )
        else:
            not_after = certificate.get("not_after")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                    if expiry < datetime.now(UTC):
                        result.add(
                            Signal(
                                id="url.tls_expired",
                                title="TLS certificate has expired",
                                severity=Severity.MEDIUM,
                                category="url",
                                description="An expired certificate is a sign of poor maintenance or a throwaway site.",
                                evidence=not_after,
                                weight=20,
                            )
                        )
                except ValueError:
                    pass


def _intel_signals(
    result: AnalysisResult,
    normalized: str,
    registrable: str,
    host: str,
    intel: IntelClient,
) -> None:
    vt = intel.virustotal_url(normalized)
    result.metadata["virustotal"] = vt.to_dict()
    if vt.error:
        result.metadata.setdefault("intel_errors", []).append(f"VirusTotal: {vt.error}")
    elif vt.found:
        if vt.malicious >= 3:
            weight, severity, title = 85, Severity.CRITICAL, "VirusTotal: multiple engines flag this URL"
        elif vt.malicious >= 1:
            weight, severity, title = 65, Severity.HIGH, "VirusTotal: an engine flags this URL"
        elif vt.suspicious >= 2:
            weight, severity, title = 45, Severity.MEDIUM, "VirusTotal: suspicious URL reputation"
        else:
            weight, severity, title = 0, Severity.INFO, "VirusTotal: no detections"
        result.add(
            Signal(
                id="intel.virustotal_url",
                title=title,
                severity=severity,
                category="intel",
                description="Crowdsourced multi-engine reputation result.",
                evidence=f"malicious={vt.malicious}, suspicious={vt.suspicious}, harmless={vt.harmless}",
                weight=weight,
                source="VirusTotal",
            )
        )

    gsb = intel.google_safe_browsing(normalized)
    result.metadata["safe_browsing"] = gsb.to_dict()
    if gsb.error:
        result.metadata.setdefault("intel_errors", []).append(f"Safe Browsing: {gsb.error}")
    elif gsb.found:
        result.add(
            Signal(
                id="intel.safe_browsing",
                title="Google Safe Browsing match",
                severity=Severity.CRITICAL,
                category="intel",
                description="The URL matches a known malware or social-engineering threat.",
                evidence=", ".join(gsb.categories) or "threat match",
                weight=85,
                source="Google Safe Browsing",
            )
        )

    scan = intel.urlscan_domain(registrable)
    result.metadata["urlscan"] = scan.to_dict()
    if scan.error:
        result.metadata.setdefault("intel_errors", []).append(f"urlscan.io: {scan.error}")
    elif scan.found:
        if scan.malicious >= 1:
            weight, severity, title = 60, Severity.HIGH, "urlscan.io: malicious scan result"
        elif scan.suspicious >= 2:
            weight, severity, title = 35, Severity.MEDIUM, "urlscan.io: suspicious scan history"
        else:
            weight, severity, title = 0, Severity.INFO, "urlscan.io: no malicious scans found"
        result.add(
            Signal(
                id="intel.urlscan",
                title=title,
                severity=severity,
                category="intel",
                description="Public URL-scan history for this domain.",
                evidence=f"malicious={scan.malicious}, suspicious={scan.suspicious}, total={scan.undetected + scan.malicious + scan.suspicious}",
                weight=weight,
                source="urlscan.io",
            )
        )
