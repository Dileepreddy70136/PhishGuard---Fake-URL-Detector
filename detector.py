"""Heuristic checks for potentially deceptive URLs.

This module deliberately does not visit or resolve submitted URLs. Its output is
an indicator for review, not a guarantee that a URL is safe or malicious.
"""

import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit


MAX_URL_LENGTH = 2048

SUSPICIOUS_TLDS = {
    "accountant",
    "cam",
    "click",
    "country",
    "gq",
    "icu",
    "link",
    "loan",
    "ml",
    "mom",
    "online",
    "rest",
    "top",
    "work",
    "zip",
}

URL_SHORTENERS = {
    "bit.ly",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}

BRAND_DOMAINS = {
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.in"),
    "apple": ("apple.com",),
    "facebook": ("facebook.com", "fb.com"),
    "google": ("google.com", "google.co.uk", "google.ca", "google.de", "google.co.in"),
    "microsoft": ("microsoft.com", "live.com", "outlook.com"),
    "netflix": ("netflix.com",),
    "paypal": ("paypal.com",),
}

SENSITIVE_TERMS = {
    "account",
    "banking",
    "confirm",
    "login",
    "password",
    "payment",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}

REDIRECT_PARAMETERS = {"continue", "dest", "destination", "next", "redirect", "url"}


def _is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _normalize_url(value):
    if not isinstance(value, str):
        raise ValueError("Enter a URL as text.")

    value = value.strip()
    if not value:
        raise ValueError("Enter a URL to check.")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URLs must be {MAX_URL_LENGTH} characters or fewer.")
    if any(ord(character) < 32 or character.isspace() for character in value):
        raise ValueError("The URL cannot contain spaces or control characters.")

    has_uri_scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value) is not None
    looks_like_host_port = re.match(r"^[^/:]+:\d+(?:/|$)", value) is not None
    candidate = value if "://" in value or (has_uri_scheme and not looks_like_host_port) else f"https://{value}"
    try:
        parts = urlsplit(candidate)
    except ValueError as error:
        raise ValueError("Enter a valid URL with a properly formatted host and port.") from error

    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs can be checked.")

    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as error:
        raise ValueError("Enter a valid URL with a properly formatted host and port.") from error

    if not hostname:
        raise ValueError("The URL must include a valid hostname.")

    is_ip_address = _is_ip_address(hostname)
    if is_ip_address:
        ascii_hostname = hostname.lower()
    else:
        try:
            ascii_hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("The hostname could not be interpreted.") from error

        if (
            len(ascii_hostname) > 253
            or not ascii_hostname
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or re.fullmatch(r"[a-z0-9-]+", label) is None
                for label in ascii_hostname.split(".")
            )
        ):
            raise ValueError("Enter a valid hostname.")

    return parts, ascii_hostname, port


def analyze_url(value):
    """Return a risk score and reasons for a URL, without making network calls."""
    parts, hostname, port = _normalize_url(value)
    labels = hostname.split(".")
    score = 0
    reasons = []

    def flag(points, message):
        nonlocal score
        score += points
        reasons.append(message)

    if parts.username is not None or parts.password is not None:
        flag(25, "This link has extra text before the website name, which can be used to disguise its destination.")

    if _is_ip_address(hostname):
        flag(25, "Instead of a familiar website name, this link uses a string of numbers.")
    else:
        host_without_www = hostname.removeprefix("www.")
        if host_without_www in URL_SHORTENERS:
            flag(20, "This is a shortened link, so it hides where you’ll end up.")
        if labels[-1] in SUSPICIOUS_TLDS:
            flag(15, f"This link ends in .{labels[-1]}, an address ending that’s worth checking closely.")
        if any("xn--" in label for label in labels):
            flag(20, "Some letters in this website name may be designed to look like other letters.")

        for brand, allowed_domains in BRAND_DOMAINS.items():
            contains_brand = any(brand in label for label in labels[:-1])
            if contains_brand and not any(
                host_without_www == domain or host_without_www.endswith(f".{domain}")
                for domain in allowed_domains
            ):
                flag(25, f"The website name mentions {brand}, but it doesn’t match that company’s usual web address.")
                break

    if len(labels) >= 5:
        flag(10, "There are a lot of extra sections in this website name.")
    if "-" in hostname:
        flag(5, "The website name has hyphens, sometimes used to imitate a familiar site.")
    if parts.scheme.lower() != "https":
        flag(10, "This link doesn’t use a secure HTTPS connection.")
    if port is not None and port not in {80, 443}:
        flag(10, f"This link uses an unusual connection setting ({port}).")

    searchable_url = f"{hostname}{parts.path}".lower()
    found_terms = sorted(term for term in SENSITIVE_TERMS if term in searchable_url)
    if found_terms:
        flag(10, "The link uses words like sign-in or verify, which can show up in fake login links.")

    if len(value) > 120:
        flag(5, "This is a very long link, so it may be harder to tell where it leads.")

    for key, parameter_value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in REDIRECT_PARAMETERS and "://" in parameter_value:
            flag(10, "The link contains another web address, which may hide where you’ll end up.")
            break

    score = min(score, 100)
    if score >= 40:
        verdict = "High risk"
    elif score >= 20:
        verdict = "Suspicious"
    else:
        verdict = "No obvious warning signs"

    return {
        "verdict": verdict,
        "score": score,
        "reasons": reasons or ["We didn’t spot common warning signs, but it’s still worth checking who sent it."],
        "hostname": hostname,
        "normalized_url": parts.geturl(),
    }
