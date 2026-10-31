import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import Dict, Any, List

SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "su.pr", "rebrand.ly", "cutt.ly", "trib.al"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "club", "buzz", "info", "tk", "ml", "ga", "cf",
    "gq", "ru", "su", "fit", "live", "support", "rest", "icu", "click", "cam",
    "country", "stream", "download", "racing", "science", "party"
}

BRAND_KEYWORDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "chase", "wellsfargo", "binance", "coinbase", "icloud",
    "dropbox", "bankofamerica", "citibank", "whatsapp", "telegram", "twitter",
    "yahoo", "outlook", "steam", "roblox", "ebay", "adobe"
]

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action", "suspended", "alert", "expire",
    "warning", "limited", "attention", "deactivated", "locked"
]

SECURITY_KEYWORDS = [
    "secure", "login", "signin", "account", "banking", "update", "confirm",
    "password", "credential", "auth", "verify", "verification", "wallet",
    "recovery", "security", "portal", "access", "validate"
]

HACKED_KEYWORDS = [
    "admin", "shell", "c99", "r57", "wp-admin", "hack", "exploit", "root",
    "vuln", "cmd", "backup", "priv", "bypass", "sql", "inject"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".zip", ".tar", ".sh", ".apk", ".bat", ".cmd",
    ".vbs", ".js", ".jar", ".dll", ".pif", ".msi", ".iso", ".bin"
]

# Official clean, reproducible feature columns (65 features)
FEATURE_COLUMNS: List[str] = [
    "domain_len", "path_len", "query_len", "path_depth", "subdomain_count",
    "query_param_count", "has_port", "is_ip_host", "has_punycode", "is_https",
    "is_shortener", "digit_count_v2", "letter_count_v2", "special_count_v2",
    "digit_ratio", "letter_ratio", "special_ratio", "token_count", "max_token_len",
    "avg_token_len", "url_entropy", "host_entropy", "url_len_v2", "url_len",
    "@", "?", "-", "=", ".", "#", "%", "+", "$", "!", "*", ",",
    "digits", "letters", "https", "Shortining_Service", "having_ip_address",
    "phish_urgency_words", "phish_security_words", "phish_brand_mentions",
    "phish_brand_hijack", "phish_multiple_subdomains", "phish_long_path",
    "phish_many_params", "phish_suspicious_tld", "phish_adv_exact_brand_match",
    "phish_adv_brand_in_subdomain", "phish_adv_brand_in_path",
    "phish_adv_hyphen_count", "phish_adv_number_count",
    "phish_adv_suspicious_tld", "phish_adv_long_domain",
    "phish_adv_many_subdomains", "phish_adv_encoded_chars",
    "phish_adv_path_keywords", "phish_adv_has_redirect",
    "phish_adv_many_params", "path_has_hacked_terms",
    "suspicious_extension", "path_underscore_count", "is_gov_edu"
]

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return float(round(-sum((c / total) * math.log2(c / total) for c in counts.values()), 4))

def extract_features(raw_url: str) -> Dict[str, Any]:
    """
    Extract reproducible lexical, structural, and heuristic features from a raw URL string.
    Zero external network calls, zero web browsing. 100% reproducible.
    """
    url = raw_url.strip()
    
    parsed_has_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url))
    normalized_url = url if parsed_has_scheme else "http://" + url
    
    try:
        parsed = urlparse(normalized_url)
    except Exception:
        parsed = urlparse("http://invalid.url")

    # Host & Domain
    host = parsed.netloc.split(":")[0].lower() if parsed.netloc else ""
    port = parsed.port
    has_port = 1 if port is not None else 0
    
    # Path & Query (RFC 3986 Standard Normalization: Host authority with empty path has canonical path "/")
    path = parsed.path if parsed.path else ""
    if not path and host:
        path = "/"
        if not normalized_url.endswith("/"):
            normalized_url += "/"
        if not url.endswith("/"):
            url += "/"
            
    query = parsed.query if parsed.query else ""
    
    domain_len = len(host)
    path_len = len(path)
    query_len = len(query)
    url_len_v2 = len(normalized_url)
    
    url_len = len(url.split("://", 1)[1]) if "://" in url else len(url)
    
    path_clean = path.strip("/")
    path_depth = len(path_clean.split("/")) if path_clean else 0
    
    domain_parts = host.split(".")
    cctld_candidates = {"com.br", "co.uk", "org.uk", "co.in", "gov.in", "edu.in", "ac.uk", "gov.uk"}
    is_cctld = any(host.endswith("." + c) for c in cctld_candidates)
    base_parts = 3 if is_cctld else 2
    subdomain_count = max(0, len(domain_parts) - base_parts)
    
    try:
        params = parse_qs(query)
        query_param_count = len(params)
    except Exception:
        query_param_count = query.count("&") + 1 if query else 0
        
    is_ip = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) else 0
    has_punycode = 1 if "xn--" in host else 0
    is_https = 1 if parsed.scheme.lower() == "https" else 0
    is_shortener = 1 if host in SHORTENERS else 0
    
    digit_count_v2 = sum(c.isdigit() for c in normalized_url)
    letter_count_v2 = sum(c.isalpha() for c in normalized_url)
    special_count_v2 = len(normalized_url) - digit_count_v2 - letter_count_v2
    
    total_len = max(len(normalized_url), 1)
    digit_ratio = round(digit_count_v2 / total_len, 4)
    letter_ratio = round(letter_count_v2 / total_len, 4)
    special_ratio = round(special_count_v2 / total_len, 4)
    
    tokens = [t for t in re.split(r'[/.:?&=_#\-+@]', normalized_url) if t]
    token_count = len(tokens)
    max_token_len = max(len(t) for t in tokens) if tokens else 0
    avg_token_len = round(sum(len(t) for t in tokens) / max(token_count, 1), 2)
    
    url_entropy = shannon_entropy(normalized_url)
    host_entropy = shannon_entropy(host)
    
    char_at = normalized_url.count("@")
    char_question = normalized_url.count("?")
    char_hyphen = normalized_url.count("-")
    char_equal = normalized_url.count("=")
    char_dot = normalized_url.count(".")
    char_hash = normalized_url.count("#")
    char_percent = normalized_url.count("%")
    char_plus = normalized_url.count("+")
    char_dollar = normalized_url.count("$")
    char_excl = normalized_url.count("!")
    char_star = normalized_url.count("*")
    char_comma = normalized_url.count(",")
    
    body = normalized_url.split("://", 1)[1] if "://" in normalized_url else normalized_url
    digits = sum(c.isdigit() for c in body)
    letters = sum(c.isalpha() for c in body)
    
    https_flag = 1 if "https" in normalized_url.lower() else 0
    shortening_flag = is_shortener
    having_ip_flag = is_ip
    
    url_lower = normalized_url.lower()
    host_lower = host.lower()
    path_lower = path.lower()
    
    phish_urgency_words = sum(1 for kw in URGENCY_KEYWORDS if kw in url_lower)
    phish_security_words = sum(1 for kw in SECURITY_KEYWORDS if kw in url_lower)
    
    brand_matches = [b for b in BRAND_KEYWORDS if b in url_lower]
    phish_brand_mentions = len(brand_matches)
    
    brand_hijack = 0
    for b in BRAND_KEYWORDS:
        if b in url_lower and not (host_lower == f"{b}.com" or host_lower == f"www.{b}.com" or host_lower.endswith(f".{b}.com")):
            brand_hijack = 1
            break
            
    phish_multiple_subdomains = 1 if subdomain_count >= 2 else 0
    phish_long_path = 1 if path_len > 30 or path_depth >= 3 else 0
    phish_many_params = 1 if query_param_count >= 3 else 0
    
    tld = host.split(".")[-1] if "." in host else ""
    phish_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    
    phish_adv_exact_brand_match = 1 if any(b == host.split(".")[0] for b in BRAND_KEYWORDS) else 0
    subdomains_part = ".".join(domain_parts[:-base_parts]) if len(domain_parts) > base_parts else ""
    phish_adv_brand_in_subdomain = 1 if any(b in subdomains_part for b in BRAND_KEYWORDS) else 0
    phish_adv_brand_in_path = 1 if any(b in path_lower for b in BRAND_KEYWORDS) else 0
    phish_adv_hyphen_count = host.count("-")
    phish_adv_number_count = sum(c.isdigit() for c in host)
    phish_adv_suspicious_tld = phish_suspicious_tld
    phish_adv_long_domain = 1 if domain_len > 25 else 0
    phish_adv_many_subdomains = 1 if subdomain_count >= 3 else 0
    phish_adv_encoded_chars = normalized_url.count("%")
    phish_adv_path_keywords = 1 if any(kw in path_lower for kw in SECURITY_KEYWORDS + URGENCY_KEYWORDS) else 0
    phish_adv_has_redirect = 1 if ("//" in path or "redirect" in url_lower or "url=" in url_lower or "link=" in url_lower) else 0
    phish_adv_many_params = 1 if query_param_count >= 4 else 0
    
    path_has_hacked_terms = 1 if any(term in path_lower for term in HACKED_KEYWORDS) else 0
    suspicious_extension = 1 if any(url_lower.endswith(ext) or ext in path_lower for ext in SUSPICIOUS_EXTENSIONS) else 0
    path_underscore_count = path.count("_")
    is_gov_edu = 1 if any(host.endswith(sfx) for sfx in [".gov", ".edu", ".gov.in", ".edu.in", ".ac.uk", ".gov.uk"]) else 0

    return {
        "domain_len": int(domain_len),
        "path_len": int(path_len),
        "query_len": int(query_len),
        "path_depth": int(path_depth),
        "subdomain_count": int(subdomain_count),
        "query_param_count": int(query_param_count),
        "has_port": int(has_port),
        "is_ip_host": int(is_ip),
        "has_punycode": int(has_punycode),
        "is_https": int(is_https),
        "is_shortener": int(is_shortener),
        "digit_count_v2": int(digit_count_v2),
        "letter_count_v2": int(letter_count_v2),
        "special_count_v2": int(special_count_v2),
        "digit_ratio": float(digit_ratio),
        "letter_ratio": float(letter_ratio),
        "special_ratio": float(special_ratio),
        "token_count": int(token_count),
        "max_token_len": int(max_token_len),
        "avg_token_len": float(avg_token_len),
        "url_entropy": float(url_entropy),
        "host_entropy": float(host_entropy),
        "url_len_v2": int(url_len_v2),
        "url_len": int(url_len),
        "@": int(char_at),
        "?": int(char_question),
        "-": int(char_hyphen),
        "=": int(char_equal),
        ".": int(char_dot),
        "#": int(char_hash),
        "%": int(char_percent),
        "+": int(char_plus),
        "$": int(char_dollar),
        "!": int(char_excl),
        "*": int(char_star),
        ",": int(char_comma),
        "digits": int(digits),
        "letters": int(letters),
        "https": int(https_flag),
        "Shortining_Service": int(shortening_flag),
        "having_ip_address": int(having_ip_flag),
        "phish_urgency_words": int(phish_urgency_words),
        "phish_security_words": int(phish_security_words),
        "phish_brand_mentions": int(phish_brand_mentions),
        "phish_brand_hijack": int(brand_hijack),
        "phish_multiple_subdomains": int(phish_multiple_subdomains),
        "phish_long_path": int(phish_long_path),
        "phish_many_params": int(phish_many_params),
        "phish_suspicious_tld": int(phish_suspicious_tld),
        "phish_adv_exact_brand_match": int(phish_adv_exact_brand_match),
        "phish_adv_brand_in_subdomain": int(phish_adv_brand_in_subdomain),
        "phish_adv_brand_in_path": int(phish_adv_brand_in_path),
        "phish_adv_hyphen_count": int(phish_adv_hyphen_count),
        "phish_adv_number_count": int(phish_adv_number_count),
        "phish_adv_suspicious_tld": int(phish_adv_suspicious_tld),
        "phish_adv_long_domain": int(phish_adv_long_domain),
        "phish_adv_many_subdomains": int(phish_adv_many_subdomains),
        "phish_adv_encoded_chars": int(phish_adv_encoded_chars),
        "phish_adv_path_keywords": int(phish_adv_path_keywords),
        "phish_adv_has_redirect": int(phish_adv_has_redirect),
        "phish_adv_many_params": int(phish_adv_many_params),
        "path_has_hacked_terms": int(path_has_hacked_terms),
        "suspicious_extension": int(suspicious_extension),
        "path_underscore_count": int(path_underscore_count),
        "is_gov_edu": int(is_gov_edu)
    }
