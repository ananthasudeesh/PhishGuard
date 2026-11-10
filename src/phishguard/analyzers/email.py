"""Email (.eml) analyzer.

Parses headers, authentication results, body links, HTML forms, and
attachment metadata. It never executes an attachment and never fetches the
message's remote images.
"""

from __future__ import annotations

import re
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from email.utils import parseaddr

import dns.resolver
from bs4 import BeautifulSoup

from ..intel import IntelClient
from ..models import AnalysisResult, Severity, Signal
from ..scoring import finalize
from ..utils import (
    BRANDS,
    CREDENTIAL_WORDS,
    REWARD_WORDS,
    URGENCY_WORDS,
    contains_any,
    extract_urls,
    format_bytes,
    hash_bytes,
    registered_domain,
    safe_truncate,
)
from .file import analyze_file_bytes
from .url import analyze_url

_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_RECEIVED_SPF_RE = re.compile(r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"(?i)\b(?:https?://)?(?:www\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)")


def analyze_eml(
    data: bytes,
    filename: str = "message.eml",
    *,
    use_intel: bool = False,
    online: bool = True,
    intel: IntelClient | None = None,
    max_urls: int = 5,
    max_attachments: int = 5,
) -> AnalysisResult:
    result = AnalysisResult(analyzer="Email", target=filename or "message.eml")
    if not data:
        result.error = "Empty email file"
        return finalize(result)
    if len(data) > 25 * 1024 * 1024:
        result.error = "Email is larger than the 25 MB analysis limit"
        return finalize(result)

    try:
        message = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:
        result.error = f"Could not parse the email: {exc}"
        return finalize(result)

    from_header = _first_header(message, "From")
    reply_to_header = _first_header(message, "Reply-To")
    return_path_header = _first_header(message, "Return-Path")
    sender_header = _first_header(message, "Sender")
    subject = _first_header(message, "Subject")
    date_header = _first_header(message, "Date")
    message_id = _first_header(message, "Message-ID")

    from_name, from_email = parseaddr(from_header)
    _reply_name, reply_email = parseaddr(reply_to_header)
    return_email = parseaddr(return_path_header)[1]
    sender_email = parseaddr(sender_header)[1]

    from_domain = _email_domain(from_email)
    reply_domain = _email_domain(reply_email)
    return_domain = _email_domain(return_email)
    sender_domain = _email_domain(sender_email)

    result.metadata.update(
        {
            "subject": safe_truncate(subject, 300),
            "from": safe_truncate(from_header, 300),
            "from_name": safe_truncate(from_name, 200),
            "from_email": from_email,
            "from_domain": from_domain,
            "reply_to": safe_truncate(reply_to_header, 300),
            "reply_to_domain": reply_domain,
            "return_path_domain": return_domain,
            "sender_domain": sender_domain,
            "date": safe_truncate(date_header, 120),
            "message_id": safe_truncate(message_id, 300),
            "size": format_bytes(len(data)),
            "hashes": hash_bytes(data),
        }
    )

    result.add(
        Signal(
            id="email.parsed",
            title="Email parsed successfully",
            severity=Severity.INFO,
            category="email",
            description="Headers, body, links, and attachment metadata were extracted locally.",
            evidence=filename or "message.eml",
            weight=0,
        )
    )

    if not from_header and not subject:
        result.add(
            Signal(
                id="email.no_headers",
                title="Message has no recognisable headers",
                severity=Severity.MEDIUM,
                category="email",
                description="This may not be a valid .eml file.",
                weight=20,
            )
        )

    _identity_signals(result, from_name, from_domain, reply_domain, return_domain, sender_domain, message_id)
    auth_values = _auth_signals(result, message, from_domain)
    result.metadata["authentication"] = auth_values

    body_text, html_text, html_links, html_anchors, has_password_form, attachments = _extract_parts(
        message, max_attachments=max_attachments
    )
    result.metadata["body_preview"] = safe_truncate(body_text or html_text, 600)
    result.metadata["html_link_count"] = len(html_links)
    result.metadata["has_password_form"] = has_password_form
    result.metadata["attachment_count"] = len(attachments)

    _content_signals(result, subject, body_text or html_text)
    if has_password_form:
        result.add(
            Signal(
                id="email.password_form",
                title="Email contains a password input form",
                severity=Severity.HIGH,
                category="credentials",
                description="Legitimate organisations do not ask for passwords inside an email body.",
                evidence="HTML <input type=password>",
                weight=30,
            )
        )

    _html_link_signals(result, html_anchors)

    urls = extract_urls(f"{body_text}\n{html_text}\n" + "\n".join(html_links))
    result.metadata["url_count"] = len(urls)
    url_reports = []
    for index, url in enumerate(urls[:max_urls], start=1):
        report = analyze_url(url, use_intel=use_intel, online=online, intel=intel)
        url_reports.append(report.to_dict())
        if report.score > 0:
            result.add(
                Signal(
                    id=f"email.url_{index}",
                    title=f"Suspicious link #{index} in message",
                    severity=_severity_from_score(report.score),
                    category="url",
                    description="The linked URL has its own risk indicators; open the URL report for details.",
                    evidence=safe_truncate(url, 250),
                    weight=min(55, max(10, report.score // 2)),
                )
            )
            for signal in report.signals[:2]:
                if signal.weight >= 20:
                    result.add(
                        Signal(
                            id=f"email.url_{index}.{signal.id}",
                            title=f"Link #{index}: {signal.title}",
                            severity=signal.severity,
                            category="url",
                            description=signal.description,
                            evidence=safe_truncate(signal.evidence, 250),
                            weight=min(40, round(signal.weight * 0.5)),
                            source=signal.source,
                        )
                    )
    result.metadata["url_reports"] = url_reports

    attachment_reports = []
    for index, attachment in enumerate(attachments[:max_attachments], start=1):
        report = analyze_file_bytes(
            attachment["data"],
            attachment["filename"],
            use_intel=use_intel,
            online=online,
            intel=intel,
        )
        attachment_reports.append(report.to_dict())
        if report.score > 0:
            result.add(
                Signal(
                    id=f"email.attachment_{index}",
                    title=f"Attachment #{index} has risk indicators",
                    severity=_severity_from_score(report.score),
                    category="attachment",
                    description="The attachment was analysed statically and was not opened.",
                    evidence=f"{attachment['filename']} ({format_bytes(len(attachment['data']))})",
                    weight=min(60, max(10, report.score // 2)),
                )
            )
    result.metadata["attachment_reports"] = attachment_reports

    result.recommendations = [
        "Verify the sender through a separate, trusted channel before acting.",
        "Do not open attachments or enable macros in an unexpected message.",
        "Hover over links and confirm the registered domain before clicking.",
        "Report the message to your email provider or security team.",
    ]
    return finalize(result)


def _first_header(message, name: str) -> str:
    value = message.get(name, "")
    if value is None:
        return ""
    return str(value).replace("\n", " ").replace("\r", " ").strip()


def _email_domain(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].lower().strip().rstrip(".")


def _identity_signals(
    result: AnalysisResult,
    from_name: str,
    from_domain: str,
    reply_domain: str,
    return_domain: str,
    sender_domain: str,
    message_id: str,
) -> None:
    if from_domain and reply_domain and reply_domain != from_domain:
        result.add(
            Signal(
                id="email.reply_to_mismatch",
                title="Reply-To domain differs from From domain",
                severity=Severity.HIGH,
                category="email",
                description="Replies would go to a different organisation than the one shown.",
                evidence=f"From: {from_domain} | Reply-To: {reply_domain}",
                weight=22,
            )
        )

    if from_domain and return_domain and return_domain != from_domain:
        result.add(
            Signal(
                id="email.return_path_mismatch",
                title="Return-Path differs from From domain",
                severity=Severity.MEDIUM,
                category="email",
                description="This is common in bulk mail but can also indicate spoofing or a compromised sender.",
                evidence=f"From: {from_domain} | Return-Path: {return_domain}",
                weight=10,
            )
        )

    if from_domain and sender_domain and sender_domain != from_domain:
        result.add(
            Signal(
                id="email.sender_mismatch",
                title="Sender header differs from From domain",
                severity=Severity.MEDIUM,
                category="email",
                description="A mismatch can indicate forwarding or impersonation.",
                evidence=f"From: {from_domain} | Sender: {sender_domain}",
                weight=10,
            )
        )

    name_lower = (from_name or "").lower()
    if name_lower:
        for brand in BRANDS:
            if len(brand) >= 4 and brand in name_lower:
                registrable = registered_domain(from_domain) if from_domain else ""
                if brand not in registrable:
                    result.add(
                        Signal(
                            id="email.display_name_spoof",
                            title="Display name claims a brand on an unrelated domain",
                            severity=Severity.HIGH,
                            category="email",
                            description=f"The display name mentions '{brand}', but the sending domain is not that brand.",
                            evidence=f"{from_name} <{from_domain}>",
                            weight=30,
                        )
                    )
                break

    if from_domain:
        lookalike = _lookalike_brand(from_domain)
        if lookalike:
            result.add(
                Signal(
                    id="email.lookalike_domain",
                    title="Sender domain resembles a known brand",
                    severity=Severity.HIGH,
                    category="email",
                    description=f"The sender domain is similar to '{lookalike}' but is not the official domain.",
                    evidence=from_domain,
                    weight=32,
                )
            )

    if message_id and from_domain:
        message_domain = _email_domain(message_id.split("<")[-1].split(">")[0]) if "@" in message_id else ""
        if message_domain and message_domain != from_domain:
            result.add(
                Signal(
                    id="email.message_id_mismatch",
                    title="Message-ID domain differs from sender",
                    severity=Severity.LOW,
                    category="email",
                    description="A mismatched Message-ID is a weak indicator of spoofing or bulk infrastructure.",
                    evidence=f"Message-ID domain: {message_domain}",
                    weight=5,
                )
            )


def _lookalike_brand(domain: str) -> str | None:
    from difflib import SequenceMatcher

    label = domain.split(".")[0] if domain else ""
    if len(label) < 5:
        return None
    for brand in BRANDS:
        if len(brand) < 5 or label == brand:
            continue
        if SequenceMatcher(None, label, brand).ratio() >= 0.86:
            return brand
    return None


def _auth_signals(result: AnalysisResult, message, from_domain: str) -> dict[str, str]:
    auth_header = " ".join(str(value) for value in message.get_all("Authentication-Results", []))
    received_spf = " ".join(str(value) for value in message.get_all("Received-SPF", []))
    values: dict[str, str] = {}
    for mechanism, status in _AUTH_RE.findall(auth_header):
        values[mechanism.lower()] = status.lower()
    if "spf" not in values and received_spf:
        match = _RECEIVED_SPF_RE.search(received_spf)
        if match:
            values["spf"] = match.group(1).lower()

    weights = {"spf": 25, "dkim": 20, "dmarc": 25}
    for mechanism in ("spf", "dkim", "dmarc"):
        status = values.get(mechanism)
        if status in {"fail", "softfail", "permerror"}:
            result.add(
                Signal(
                    id=f"email.auth_{mechanism}_fail",
                    title=f"{mechanism.upper()} authentication failed",
                    severity=Severity.HIGH if mechanism != "dkim" else Severity.MEDIUM,
                    category="email",
                    description=f"The receiving mail system reported {mechanism.upper()}={status}.",
                    evidence=safe_truncate(auth_header or received_spf, 300),
                    weight=weights[mechanism],
                )
            )
        elif status is None and mechanism == "dmarc":
            result.add(
                Signal(
                    id="email.no_dmarc_result",
                    title="No DMARC result in headers",
                    severity=Severity.LOW,
                    category="email",
                    description="The message does not show a DMARC evaluation, so sender alignment is unverified.",
                    evidence="Authentication-Results header missing dmarc",
                    weight=8,
                )
            )

    if from_domain:
        policy = _dmarc_policy(from_domain)
        values["dmarc_policy"] = policy or "none"
        if not policy:
            result.add(
                Signal(
                    id="email.no_dmarc_record",
                    title="Sending domain has no DMARC record",
                    severity=Severity.MEDIUM,
                    category="email",
                    description="Without DMARC, the domain is easier to impersonate.",
                    evidence=from_domain,
                    weight=12,
                )
            )
        elif policy == "none":
            result.add(
                Signal(
                    id="email.dmarc_none",
                    title="DMARC policy is monitoring-only",
                    severity=Severity.INFO,
                    category="email",
                    description="The domain publishes DMARC but does not enforce rejection or quarantine.",
                    evidence=f"p=none for {from_domain}",
                    weight=0,
                )
            )
    return values


def _dmarc_policy(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=3)
        for answer in answers:
            text = str(answer).replace('"', "")
            if text.lower().startswith("v=dmarc1"):
                match = re.search(r"\bp\s*=\s*(none|quarantine|reject)", text, re.IGNORECASE)
                if match:
                    return match.group(1).lower()
                return "none"
    except Exception:
        return None
    return None


def _decode_filename(value: str | None) -> str:
    if not value:
        return ""
    try:
        parts = decode_header(value)
        return "".join(
            part.decode(charset or "utf-8", errors="replace") if isinstance(part, bytes) else part
            for part, charset in parts
        )
    except Exception:
        return value


def _extract_parts(message, *, max_attachments: int = 5) -> tuple[str, str, list[str], list[tuple[str, str]], bool, list[dict]]:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []
    total_body = 0

    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = (part.get_content_type() or "").lower()
        filename = _decode_filename(part.get_filename())
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        if filename:
            if len(attachments) < max_attachments and len(payload) <= 10 * 1024 * 1024:
                attachments.append({"filename": filename, "content_type": content_type, "data": payload})
            continue
        if content_type not in {"text/plain", "text/html"}:
            continue
        if total_body > 2 * 1024 * 1024:
            continue
        try:
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            text = payload.decode("utf-8", errors="replace")
        total_body += len(text)
        if content_type == "text/html":
            html_parts.append(text)
        else:
            text_parts.append(text)

    html = "\n".join(html_parts)
    soup = BeautifulSoup(html, "html.parser") if html else None
    html_text = soup.get_text(" ", strip=True) if soup else ""
    html_links: list[str] = []
    html_anchors: list[tuple[str, str]] = []
    has_password_form = False
    if soup:
        for anchor in soup.find_all("a", href=True):
            href = str(anchor.get("href", "")).strip()
            if href:
                html_links.append(href)
                html_anchors.append((anchor.get_text(" ", strip=True), href))
        has_password_form = bool(soup.find("input", attrs={"type": re.compile("password", re.IGNORECASE)}))
        for form in soup.find_all("form"):
            if form.find("input", attrs={"type": re.compile("password", re.IGNORECASE)}):
                has_password_form = True
                break

    return "\n".join(text_parts), html_text, html_links, html_anchors, has_password_form, attachments


def _content_signals(result: AnalysisResult, subject: str, body: str) -> None:
    subject_hits = contains_any(subject, URGENCY_WORDS | REWARD_WORDS | CREDENTIAL_WORDS)
    body_hits = contains_any(body, URGENCY_WORDS | REWARD_WORDS | CREDENTIAL_WORDS)
    if subject_hits:
        result.add(
            Signal(
                id="email.subject_language",
                title="Pressure or credential language in the subject",
                severity=Severity.MEDIUM,
                category="email",
                description="Urgency, reward, or account language is common in phishing.",
                evidence=", ".join(subject_hits[:6]),
                weight=10,
            )
        )
    if body_hits:
        result.add(
            Signal(
                id="email.body_language",
                title="Pressure or credential language in the body",
                severity=Severity.LOW,
                category="email",
                description="The message uses language frequently seen in phishing.",
                evidence=", ".join(body_hits[:8]),
                weight=8,
            )
        )


def _html_link_signals(result: AnalysisResult, anchors: list[tuple[str, str]]) -> None:
    mismatches = 0
    brand_mismatches = 0
    for visible_text, href in anchors[:20]:
        if not href.lower().startswith(("http://", "https://")):
            continue
        href_domain = registered_domain(href)
        if not href_domain:
            continue
        if _lookalike_brand(href_domain):
            mismatches += 1

        text_lower = visible_text.lower()
        text_domain = ""
        domain_match = _DOMAIN_RE.search(visible_text)
        if domain_match:
            text_domain = registered_domain(domain_match.group(1))
        if text_domain and text_domain != href_domain:
            mismatches += 1

        for brand in BRANDS:
            if len(brand) >= 4 and brand in text_lower and brand not in href_domain:
                brand_mismatches += 1
                break

    if mismatches:
        result.add(
            Signal(
                id="email.link_lookalike",
                title="Email contains mismatched or lookalike link destinations",
                severity=Severity.HIGH,
                category="url",
                description="The visible link text or destination resembles a brand but points elsewhere.",
                evidence=f"{mismatches} mismatched or lookalike link(s)",
                weight=25,
            )
        )
    if brand_mismatches:
        result.add(
            Signal(
                id="email.link_brand_mismatch",
                title="Link text names a brand but points to another domain",
                severity=Severity.HIGH,
                category="url",
                description="Attackers often show an official-looking label while linking to their own site.",
                evidence=f"{brand_mismatches} brand-labelled link(s)",
                weight=25,
            )
        )


def _severity_from_score(score: int) -> Severity:
    if score >= 70:
        return Severity.CRITICAL
    if score >= 50:
        return Severity.HIGH
    if score >= 30:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO
