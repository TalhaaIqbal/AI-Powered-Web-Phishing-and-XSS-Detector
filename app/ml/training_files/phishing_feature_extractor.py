"""
Converts a raw URL into the exact 30-feature vector (-1 / 0 / 1) that the
phishing.csv-trained models (xgboost_model.pkl, random_forest_model.pkl) expect.

Column order MUST match training data exactly:
UsingIP, LongURL, ShortURL, Symbol@, Redirecting//, PrefixSuffix-, SubDomains,
HTTPS, DomainRegLen, Favicon, NonStdPort, HTTPSDomainURL, RequestURL, AnchorURL,
LinksInScriptTags, ServerFormHandler, InfoEmail, AbnormalURL, WebsiteForwarding,
StatusBarCust, DisableRightClick, UsingPopupWindow, IframeRedirection, AgeofDomain,
DNSRecording, WebsiteTraffic, PageRank, GoogleIndex, LinksPointingToPage, StatsReport

Some features (WebsiteTraffic, PageRank, GoogleIndex, DNSRecording, AgeofDomain,
DomainRegLen) need live network/whois lookups, which can be slow or fail for
unreachable/very new sites. Each lookup is wrapped in try/except — on failure we
default to the "suspicious" value (-1) rather than crash, since a phishing tool
failing open is worse than failing toward "flag it."
"""
import re
import socket
from datetime import datetime
from urllib.parse import urlparse

import requests
import whois
from bs4 import BeautifulSoup

FEATURE_ORDER = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", "PrefixSuffix-",
    "SubDomains", "HTTPS", "DomainRegLen", "Favicon", "NonStdPort", "HTTPSDomainURL",
    "RequestURL", "AnchorURL", "LinksInScriptTags", "ServerFormHandler", "InfoEmail",
    "AbnormalURL", "WebsiteForwarding", "StatusBarCust", "DisableRightClick",
    "UsingPopupWindow", "IframeRedirection", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage", "StatsReport",
]

SHORTENERS = r"bit\.ly|goo\.gl|shorte\.st|tinyurl|ow\.ly|t\.co|is\.gd|cli\.gs|" \
             r"buff\.ly|adf\.ly|bitly\.com|tr\.im|cur\.lv"


class PhishingFeatureExtractor:
    def __init__(self, url: str):
        self.url = url if "://" in url else f"http://{url}"
        self.domain = urlparse(self.url).netloc.split(":")[0]
        try:
            self.response = requests.get(self.url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            self.soup = BeautifulSoup(self.response.text, "html.parser")
        except Exception:
            self.response = None
            self.soup = None
        try:
            self.whois_data = whois.whois(self.domain)
        except Exception:
            self.whois_data = None

    # --- 1-7: pure string/regex checks on the URL itself, no network needed ---

    def using_ip(self) -> int:
        try:
            socket.inet_aton(self.domain)
            return -1
        except OSError:
            return 1

    def long_url(self) -> int:
        length = len(self.url)
        if length < 54:
            return 1
        elif length <= 75:
            return 0
        return -1

    def short_url(self) -> int:
        return -1 if re.search(SHORTENERS, self.url, re.IGNORECASE) else 1

    def symbol_at(self) -> int:
        return -1 if "@" in self.url else 1

    def redirecting_slash(self) -> int:
        return -1 if self.url.rfind("//") > 7 else 1

    def prefix_suffix(self) -> int:
        return -1 if "-" in self.domain else 1

    def sub_domains(self) -> int:
        dots = self.domain.count(".")
        if dots == 1:
            return 1
        elif dots == 2:
            return 0
        return -1

    def https(self) -> int:
        return 1 if urlparse(self.url).scheme == "https" else -1

    # --- 8-9: whois lookups ---

    def domain_reg_len(self) -> int:
        if not self.whois_data or not self.whois_data.expiration_date or not self.whois_data.creation_date:
            return -1
        try:
            exp = self.whois_data.expiration_date
            cre = self.whois_data.creation_date
            exp = exp[0] if isinstance(exp, list) else exp
            cre = cre[0] if isinstance(cre, list) else cre
            age_days = (exp - cre).days
            return 1 if age_days / 365 >= 1 else -1
        except Exception:
            return -1

    def age_of_domain(self) -> int:
        if not self.whois_data or not self.whois_data.creation_date:
            return -1
        try:
            cre = self.whois_data.creation_date
            cre = cre[0] if isinstance(cre, list) else cre
            age_days = (datetime.now() - cre).days
            return 1 if age_days / 30 >= 6 else -1
        except Exception:
            return -1

    def dns_recording(self) -> int:
        return 1 if self.whois_data else -1

    # --- 10-19: needs the fetched page HTML ---

    def favicon(self) -> int:
        if not self.soup:
            return -1
        for link in self.soup.find_all("link", href=True):
            href = link["href"]
            if self.domain in href or href.startswith("/"):
                return 1
        return -1

    def non_std_port(self) -> int:
        port = urlparse(self.url).port
        return 1 if port is None or port in (80, 443) else -1

    def https_domain_url(self) -> int:
        return -1 if "https" in self.domain.lower() else 1

    def request_url(self) -> int:
        if not self.soup:
            return -1
        tags = self.soup.find_all(["img", "audio", "embed", "iframe"])
        if not tags:
            return 1
        external = sum(1 for t in tags if t.get("src") and self.domain not in t.get("src", ""))
        pct = external / len(tags)
        return 1 if pct < 0.22 else (0 if pct < 0.61 else -1)

    def anchor_url(self) -> int:
        if not self.soup:
            return -1
        anchors = self.soup.find_all("a", href=True)
        if not anchors:
            return 1
        suspicious = sum(
            1 for a in anchors
            if a["href"].startswith("#") or "javascript:void" in a["href"].lower() or
            (self.domain not in a["href"] and a["href"].startswith("http"))
        )
        pct = suspicious / len(anchors)
        return 1 if pct < 0.31 else (0 if pct < 0.67 else -1)

    def links_in_script_tags(self) -> int:
        if not self.soup:
            return -1
        tags = self.soup.find_all(["link", "script"])
        if not tags:
            return 1
        total, external = 0, 0
        for t in tags:
            src = t.get("href") or t.get("src")
            if src:
                total += 1
                if self.domain not in src and src.startswith("http"):
                    external += 1
        if total == 0:
            return 1
        pct = external / total
        return 1 if pct < 0.17 else (0 if pct < 0.81 else -1)

    def server_form_handler(self) -> int:
        if not self.soup:
            return -1
        forms = self.soup.find_all("form", action=True)
        if not forms:
            return 1
        for f in forms:
            action = f["action"]
            if action in ("", "about:blank"):
                return -1
            if self.domain not in action and action.startswith("http"):
                return 0
        return 1

    def info_email(self) -> int:
        if not self.response:
            return -1
        return -1 if re.search(r"mailto:|\.submit\(", self.response.text, re.IGNORECASE) else 1

    def abnormal_url(self) -> int:
        if not self.whois_data:
            return -1
        return 1 if self.domain in str(self.whois_data) else -1

    # --- 20-23: behavioral page checks ---

    def website_forwarding(self) -> int:
        if not self.response:
            return -1
        redirects = len(self.response.history)
        if redirects <= 1:
            return 1
        elif redirects <= 4:
            return 0
        return -1

    def status_bar_cust(self) -> int:
        if not self.response:
            return -1
        return -1 if re.search(r"onmouseover\s*=", self.response.text, re.IGNORECASE) else 1

    def disable_right_click(self) -> int:
        if not self.response:
            return -1
        return -1 if re.search(r"event\.button\s*==\s*2", self.response.text, re.IGNORECASE) else 1

    def using_popup_window(self) -> int:
        if not self.response:
            return -1
        return -1 if re.search(r"alert\s*\(", self.response.text, re.IGNORECASE) else 1

    def iframe_redirection(self) -> int:
        if not self.soup:
            return -1
        return -1 if self.soup.find_all("iframe") else 1

    # --- 24, 26-29: external reputation signals (best-effort, may need API keys) ---

    def website_traffic(self) -> int:
        # Without a live Alexa/Tranco API this is a stub — defaults to neutral/suspicious.
        # Swap in a Tranco list lookup for a real signal: https://tranco-list.eu
        return -1

    def page_rank(self) -> int:
        # Stub — Google killed public PageRank; use a third-party domain-authority API if you want this live.
        return -1

    def google_index(self) -> int:
        # Best-effort: a real check would hit a search API; defaulting to "indexed" (1) to avoid false positives
        # from a missing/blocked search call.
        return 1

    def links_pointing_to_page(self) -> int:
        # Backlink count needs a paid API (Moz/Ahrefs); stub default.
        return 0

    def stats_report(self) -> int:
        # Lightweight heuristic: flag known bad hosting patterns in the domain itself.
        suspicious_hosts = ["000webhostapp", "weebly", "wixsite", "freehostia"]
        return -1 if any(h in self.domain for h in suspicious_hosts) else 1

    # --- assemble ---

    def get_features_dict(self) -> dict:
        return {
            "UsingIP": self.using_ip(),
            "LongURL": self.long_url(),
            "ShortURL": self.short_url(),
            "Symbol@": self.symbol_at(),
            "Redirecting//": self.redirecting_slash(),
            "PrefixSuffix-": self.prefix_suffix(),
            "SubDomains": self.sub_domains(),
            "HTTPS": self.https(),
            "DomainRegLen": self.domain_reg_len(),
            "Favicon": self.favicon(),
            "NonStdPort": self.non_std_port(),
            "HTTPSDomainURL": self.https_domain_url(),
            "RequestURL": self.request_url(),
            "AnchorURL": self.anchor_url(),
            "LinksInScriptTags": self.links_in_script_tags(),
            "ServerFormHandler": self.server_form_handler(),
            "InfoEmail": self.info_email(),
            "AbnormalURL": self.abnormal_url(),
            "WebsiteForwarding": self.website_forwarding(),
            "StatusBarCust": self.status_bar_cust(),
            "DisableRightClick": self.disable_right_click(),
            "UsingPopupWindow": self.using_popup_window(),
            "IframeRedirection": self.iframe_redirection(),
            "AgeofDomain": self.age_of_domain(),
            "DNSRecording": self.dns_recording(),
            "WebsiteTraffic": self.website_traffic(),
            "PageRank": self.page_rank(),
            "GoogleIndex": self.google_index(),
            "LinksPointingToPage": self.links_pointing_to_page(),
            "StatsReport": self.stats_report(),
        }

    def get_features_array(self) -> list[int]:
        """Returns the feature vector in the EXACT column order the model was trained on."""
        feats = self.get_features_dict()
        return [feats[col] for col in FEATURE_ORDER]