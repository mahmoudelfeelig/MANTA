from __future__ import annotations

from app.destination_enrichment import DestinationEnrichmentInput, analyze_destination, normalize_protected_brands_csv


def test_analyze_destination_detects_lookalike() -> None:
    result = analyze_destination(
        DestinationEnrichmentInput(
            site_hint="g00gle.com",
            dst_port=443,
            fetch_certificate=False,
        )
    )

    assert result["normalized_host"] == "g00gle.com"
    assert result["brand_match"] == "google"
    assert result["lookalike_score"] >= 0.55
    assert "T1566" in result["mitre_techniques"]


def test_analyze_destination_respects_custom_protected_brands() -> None:
    result = analyze_destination(
        DestinationEnrichmentInput(
            site_hint="examp1ebank-login.com",
            dst_port=443,
            fetch_certificate=False,
            protected_brands=normalize_protected_brands_csv("examplebank"),
        )
    )

    assert result["brand_match"] == "examplebank"
    assert result["lookalike_score"] >= 0.55
