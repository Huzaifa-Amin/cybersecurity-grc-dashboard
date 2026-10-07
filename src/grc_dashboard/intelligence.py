from __future__ import annotations

import json
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from xml.etree import ElementTree

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ADVISORIES_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
KEV_MAX_BYTES = 20_000_000
ADVISORIES_MAX_BYTES = 3_000_000


class ThreatFeedUnavailable(RuntimeError):
    """A trusted public threat feed could not be fetched or validated."""


def _download(url: str, maximum_bytes: int, timeout: float) -> tuple[bytes, datetime]:
    request = Request(
        url,
        headers={
            "Accept": "application/json, application/rss+xml, application/xml",
            "User-Agent": "Northstar-GRC/1.0 (+https://github.com/Huzaifa-Amin/cybersecurity-grc-dashboard)",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(maximum_bytes + 1)
            if len(payload) > maximum_bytes:
                raise ThreatFeedUnavailable("The upstream response exceeded the allowed size.")
            if response.status < 200 or response.status >= 300:
                raise ThreatFeedUnavailable(f"The upstream server returned HTTP {response.status}.")
    except ThreatFeedUnavailable:
        raise
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        raise ThreatFeedUnavailable(f"Could not reach the official CISA feed: {error}") from error
    return payload, datetime.now(timezone.utc)


def fetch_kev_catalog(timeout: float = 15.0) -> dict[str, Any]:
    payload, retrieved_at = _download(KEV_URL, KEV_MAX_BYTES, timeout)
    try:
        catalog = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ThreatFeedUnavailable("CISA's KEV response was not valid JSON.") from error
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
        raise ThreatFeedUnavailable("CISA's KEV response has an unexpected data structure.")
    vulnerabilities = []
    for item in catalog["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        vulnerabilities.append(
            {
                "CVE": cve_id,
                "Vendor": str(item.get("vendorProject", "")),
                "Product": str(item.get("product", "")),
                "Vulnerability": str(item.get("vulnerabilityName", "")),
                "Date added": str(item.get("dateAdded", "")),
                "Due date": str(item.get("dueDate", "")),
                "Ransomware use": str(item.get("knownRansomwareCampaignUse", "Unknown")),
                "Required action": str(item.get("requiredAction", "")),
                "Source notes": str(item.get("notes", "")),
            }
        )
    vulnerabilities.sort(key=lambda item: item["Date added"], reverse=True)
    return {
        "source": "CISA Known Exploited Vulnerabilities Catalog",
        "source_url": KEV_URL,
        "catalog_version": str(catalog.get("catalogVersion", "Unavailable")),
        "source_released": str(catalog.get("dateReleased", "Unavailable")),
        "retrieved_at": retrieved_at,
        "vulnerabilities": vulnerabilities,
    }


def fetch_cisa_advisories(timeout: float = 15.0) -> dict[str, Any]:
    payload, retrieved_at = _download(ADVISORIES_URL, ADVISORIES_MAX_BYTES, timeout)
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as error:
        raise ThreatFeedUnavailable("CISA's advisory response was not valid XML.") from error
    advisories: list[dict[str, str]] = []
    for item in root.findall(".//item"):
        title = item.findtext("title", default="").strip()
        link = item.findtext("link", default="").strip()
        if not title or not link.startswith("https://www.cisa.gov/"):
            continue
        raw_date = item.findtext("pubDate", default="").strip()
        try:
            published = parsedate_to_datetime(raw_date).astimezone(timezone.utc).isoformat()
        except (TypeError, ValueError, OverflowError):
            published = "Unavailable"
        advisories.append(
            {
                "Title": title[:300],
                "Published (UTC)": published,
                "Official advisory": link,
            }
        )
    if not advisories:
        raise ThreatFeedUnavailable("CISA's advisory feed contained no usable entries.")
    return {
        "source": "CISA Cybersecurity Advisories",
        "source_url": ADVISORIES_URL,
        "retrieved_at": retrieved_at,
        "advisories": advisories,
    }
