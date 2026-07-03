from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass

DEFAULT_PROTECTED_BRANDS = (
    "google",
    "microsoft",
    "apple",
    "meta",
    "paypal",
    "amazon",
    "github",
    "facebook",
    "instagram",
    "whatsapp",
    "telegram",
    "outlook",
    "gmail",
    "dropbox",
    "icloud",
    "netflix",
    "spotify",
    "bankofamerica",
    "chase",
    "wellsfargo",
)


@dataclass(frozen=True)
class DestinationEnrichmentInput:
    site_hint: str | None = None
    dns_query_name: str | None = None
    tls_sni: str | None = None
    http_host: str | None = None
    dst_ip: str | None = None
    dst_port: int = 443
    fetch_certificate: bool = False
    protected_brands: tuple[str, ...] = DEFAULT_PROTECTED_BRANDS


def analyze_destination(payload: DestinationEnrichmentInput) -> dict[str, object]:
    host = next(
        (
            value.strip().lower()
            for value in [payload.http_host, payload.tls_sni, payload.site_hint, payload.dns_query_name]
            if value and value.strip()
        ),
        "",
    )
    normalized_host = _normalize_host(host) if host else None
    registrable_domain = _registrable_domain(normalized_host) if normalized_host else None
    brand_match = _best_brand_match(registrable_domain, payload.protected_brands) if registrable_domain else None
    lookalike_score = _lookalike_score(registrable_domain or "", brand_match)
    punycode_present = bool(normalized_host and "xn--" in normalized_host)
    digit_substitution_present = bool(normalized_host and any(char.isdigit() for char in normalized_host))
    suspicious_tld = bool(
        normalized_host and normalized_host.endswith((".zip", ".mov", ".top", ".xyz", ".click", ".gq", ".work"))
    )
    threat_tags: list[str] = []
    if punycode_present:
        threat_tags.append("punycode_domain")
    if suspicious_tld:
        threat_tags.append("suspicious_tld")
    if lookalike_score >= 0.55:
        threat_tags.append("phishing_lookalike")
    if digit_substitution_present and lookalike_score >= 0.45:
        threat_tags.append("digit_substitution_lookalike")
    if payload.dst_port == 80:
        threat_tags.append("plaintext_web")
    if payload.dst_port not in {53, 80, 123, 443, 853} and payload.dst_port > 0:
        threat_tags.append("unusual_destination_port")

    mitre_techniques = _mitre_from_tags(threat_tags, dns_seen=bool(payload.dns_query_name), encrypted_seen=bool(payload.tls_sni or payload.site_hint))

    response: dict[str, object] = {
        "normalized_host": normalized_host,
        "registrable_domain": registrable_domain,
        "brand_match": brand_match,
        "lookalike_score": lookalike_score,
        "punycode_present": punycode_present,
        "digit_substitution_present": digit_substitution_present,
        "suspicious_tld": suspicious_tld,
        "threat_tags": threat_tags,
        "mitre_techniques": mitre_techniques,
    }
    if payload.fetch_certificate and normalized_host:
        response["tls_certificate"] = _fetch_certificate_metadata(normalized_host, payload.dst_port)
    return response


def _normalize_host(host: str) -> str:
    value = host.strip().strip(".").lower()
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except Exception:  # noqa: BLE001
        ascii_host = value
    return ascii_host.removeprefix("www.")


def _registrable_domain(host: str) -> str:
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return host
    last = labels[-1]
    second_last = labels[-2]
    third_last = labels[-3]
    second_level = {"co", "com", "org", "net", "gov", "ac"}
    if len(last) == 2 and second_last in second_level:
        return f"{third_last}.{second_last}.{last}"
    return f"{second_last}.{last}"


def _best_brand_match(domain: str, protected: tuple[str, ...] = DEFAULT_PROTECTED_BRANDS) -> str | None:
    bare = _canonical_lookalike(domain.split(".")[0])
    if not bare:
        return None
    best = min(protected, key=lambda value: _levenshtein(bare, value))
    return best if _lookalike_score(domain, best) >= 0.45 else None


def normalize_protected_brands_csv(raw: str | None) -> tuple[str, ...]:
    values = []
    for line in (raw or "").splitlines():
        item = line.strip().lower()
        if item and item not in values:
            values.append(item)
    return tuple(values) if values else DEFAULT_PROTECTED_BRANDS


def _lookalike_score(domain: str, brand: str | None) -> float:
    if not domain or not brand:
        return 0.0
    bare = _canonical_lookalike(domain.split(".")[0])
    if bare == brand:
        return 1.0
    distance = _levenshtein(bare, brand)
    max_len = max(len(bare), len(brand), 1)
    return max(0.0, min(1.0, 1.0 - (distance / max_len)))


def _canonical_lookalike(value: str) -> str:
    return (
        value.lower()
        .replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("7", "t")
        .replace("rn", "m")
    )


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    costs = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        previous = i - 1
        costs[0] = i
        for j, right_char in enumerate(right, start=1):
            current = costs[j]
            costs[j] = min(
                costs[j] + 1,
                costs[j - 1] + 1,
                previous + (0 if left_char == right_char else 1),
            )
            previous = current
    return costs[-1]


def _mitre_from_tags(tags: list[str], *, dns_seen: bool, encrypted_seen: bool) -> list[str]:
    techniques = set()
    if any("lookalike" in tag for tag in tags):
        techniques.add("T1566")
    if dns_seen:
        techniques.add("T1071.004")
    if encrypted_seen:
        techniques.add("T1573")
        techniques.add("T1071.001")
    if "unusual_destination_port" in tags:
        techniques.add("T1571")
    return sorted(techniques)


def _fetch_certificate_metadata(host: str, port: int) -> dict[str, object]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5.0) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
                return {
                    "subject": certificate.get("subject"),
                    "issuer": certificate.get("issuer"),
                    "subject_alt_name": certificate.get("subjectAltName"),
                    "not_before": certificate.get("notBefore"),
                    "not_after": certificate.get("notAfter"),
                }
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
