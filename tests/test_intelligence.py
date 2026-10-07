from __future__ import annotations

import io
import json

import pytest

from src.grc_dashboard import intelligence
from src.grc_dashboard.intelligence import (
    ThreatFeedUnavailable,
    fetch_cisa_advisories,
    fetch_kev_catalog,
)


class FakeResponse(io.BytesIO):
    status = 200

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def test_kev_catalog_validates_and_returns_source_provenance(monkeypatch) -> None:
    payload = json.dumps(
        {
            "catalogVersion": "2026.10.01",
            "dateReleased": "2026-10-01T00:00:00.000Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2025-12345",
                    "vendorProject": "Example",
                    "product": "Product",
                    "dateAdded": "2025-01-01",
                    "requiredAction": "Apply the vendor update.",
                },
                {"cveID": "malformed"},
                {
                    "cveID": "CVE-2026-12345",
                    "vendorProject": "Example",
                    "product": "New Product",
                    "dateAdded": "2026-01-01",
                },
            ],
        }
    ).encode()
    monkeypatch.setattr(intelligence, "urlopen", lambda *_args, **_kwargs: FakeResponse(payload))
    catalog = fetch_kev_catalog()
    assert catalog["catalog_version"] == "2026.10.01"
    assert catalog["source_url"] == intelligence.KEV_URL
    assert catalog["retrieved_at"].tzinfo is not None
    assert [item["CVE"] for item in catalog["vulnerabilities"]] == [
        "CVE-2026-12345",
        "CVE-2025-12345",
    ]


def test_kev_catalog_rejects_unexpected_payload(monkeypatch) -> None:
    monkeypatch.setattr(
        intelligence, "urlopen", lambda *_args, **_kwargs: FakeResponse(b'{"wrong": []}')
    )
    with pytest.raises(ThreatFeedUnavailable, match="unexpected data structure"):
        fetch_kev_catalog()


def test_cisa_advisories_keep_only_canonical_https_links(monkeypatch) -> None:
    payload = b"""<?xml version="1.0"?><rss><channel>
    <item><title>Security advisory</title><link>https://www.cisa.gov/news-events/alerts/example</link>
    <pubDate>Tue, 06 Oct 2026 12:00:00 GMT</pubDate></item>
    <item><title>Untrusted link</title><link>https://example.com/fake</link></item>
    </channel></rss>"""
    monkeypatch.setattr(intelligence, "urlopen", lambda *_args, **_kwargs: FakeResponse(payload))
    result = fetch_cisa_advisories()
    assert len(result["advisories"]) == 1
    assert result["advisories"][0]["Title"] == "Security advisory"
    assert result["advisories"][0]["Published (UTC)"].startswith("2026-10-06")


def test_cisa_feed_rejects_response_over_size_limit(monkeypatch) -> None:
    monkeypatch.setattr(intelligence, "KEV_MAX_BYTES", 4)
    monkeypatch.setattr(
        intelligence,
        "urlopen",
        lambda *_args, **_kwargs: FakeResponse(b"oversized"),
    )
    with pytest.raises(ThreatFeedUnavailable):
        fetch_kev_catalog(timeout=0.1)
