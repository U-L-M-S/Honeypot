"""
Tests for IPIntelligence class - GeoIP, AbuseIPDB, VirusTotal lookups.
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

import pytest

import main
from main import IPIntelligence


class TestIPIntelligenceInit:
    """Tests for IPIntelligence initialization."""

    def test_init_creates_empty_cache(self, tmp_path):
        """Should initialize with empty cache if no cache file exists."""
        with patch.object(main, 'IP_INTEL_CACHE', tmp_path / "nonexistent.json"):
            intel = IPIntelligence()
            assert intel.cache == {}

    def test_init_loads_existing_cache(self, tmp_path):
        """Should load cache from existing file."""
        cache_file = tmp_path / "cache.json"
        cache_data = {"192.168.1.1": {"geo": {"country": "Test"}}}
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f)

        with patch.object(main, 'IP_INTEL_CACHE', cache_file):
            intel = IPIntelligence()
            assert "192.168.1.1" in intel.cache

    def test_init_handles_corrupt_cache(self, tmp_path):
        """Should handle corrupt cache file gracefully."""
        cache_file = tmp_path / "cache.json"
        with open(cache_file, 'w') as f:
            f.write("not valid json{{{")

        with patch.object(main, 'IP_INTEL_CACHE', cache_file):
            intel = IPIntelligence()
            assert intel.cache == {}


class TestCacheValidation:
    """Tests for cache validation logic."""

    def test_cache_valid_for_recent_entry(self):
        """Cache should be valid for entries within TTL."""
        intel = IPIntelligence()
        intel.cache["10.0.0.1"] = {
            "cached_at": datetime.now().isoformat()
        }
        assert intel._is_cache_valid("10.0.0.1") is True

    def test_cache_invalid_for_old_entry(self):
        """Cache should be invalid for entries older than TTL."""
        intel = IPIntelligence()
        old_time = datetime.now() - timedelta(seconds=intel.CACHE_TTL + 100)
        intel.cache["10.0.0.1"] = {
            "cached_at": old_time.isoformat()
        }
        assert intel._is_cache_valid("10.0.0.1") is False

    def test_cache_invalid_for_missing_ip(self):
        """Cache should be invalid for IPs not in cache."""
        intel = IPIntelligence()
        assert intel._is_cache_valid("1.2.3.4") is False

    def test_cache_invalid_without_timestamp(self):
        """Cache should be invalid for entries without cached_at."""
        intel = IPIntelligence()
        intel.cache["10.0.0.1"] = {"geo": {"country": "Test"}}
        assert intel._is_cache_valid("10.0.0.1") is False


class TestGeoIPLookup:
    """Tests for GeoIP lookup functionality."""

    def test_geoip_success(self):
        """Should parse successful GeoIP response."""
        intel = IPIntelligence()

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "regionName": "California",
            "city": "San Francisco",
            "zip": "94102",
            "lat": 37.7749,
            "lon": -122.4194,
            "timezone": "America/Los_Angeles",
            "isp": "Test ISP",
            "org": "Test Org",
            "as": "AS12345 Test ASN",
            "asname": "Test ASN Name",
            "mobile": False,
            "proxy": True,
            "hosting": False
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock()

        with patch('urllib.request.urlopen', return_value=mock_response):
            result = intel._get_geoip("8.8.8.8")

        assert result["country"] == "United States"
        assert result["country_code"] == "US"
        assert result["city"] == "San Francisco"
        assert result["isp"] == "Test ISP"
        assert result["is_proxy"] is True
        assert result["is_hosting"] is False

    def test_geoip_failure(self):
        """Should handle failed GeoIP response."""
        intel = IPIntelligence()

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "status": "fail",
            "message": "reserved range"
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock()

        with patch('urllib.request.urlopen', return_value=mock_response):
            result = intel._get_geoip("192.168.1.1")

        assert "error" in result

    def test_geoip_network_error(self):
        """Should handle network errors gracefully."""
        intel = IPIntelligence()

        with patch('urllib.request.urlopen', side_effect=Exception("Network error")):
            result = intel._get_geoip("8.8.8.8")

        assert "error" in result


class TestAbuseIPDBLookup:
    """Tests for AbuseIPDB lookup functionality."""

    def test_abuseipdb_returns_none_without_key(self):
        """Should return None if no API key is set."""
        intel = IPIntelligence()

        with patch.object(main, 'ABUSEIPDB_API_KEY', ""):
            result = intel._get_abuseipdb("8.8.8.8")

        assert result is None

    def test_abuseipdb_success(self):
        """Should parse successful AbuseIPDB response."""
        intel = IPIntelligence()

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "data": {
                "abuseConfidenceScore": 75,
                "totalReports": 150,
                "lastReportedAt": "2024-01-15T12:00:00Z",
                "isWhitelisted": False,
                "usageType": "Data Center/Web Hosting/Transit",
                "domain": "example.com",
                "hostnames": ["host1.example.com"],
                "isTor": True,
                "reports": [
                    {"categories": [18, 22]},  # Brute-Force, SSH
                ]
            }
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock()

        with patch.object(main, 'ABUSEIPDB_API_KEY', "test-key"):
            with patch('urllib.request.urlopen', return_value=mock_response):
                result = intel._get_abuseipdb("1.2.3.4")

        assert result["abuse_score"] == 75
        assert result["total_reports"] == 150
        assert result["is_tor"] is True
        assert "Brute-Force" in result["categories"]
        assert "SSH" in result["categories"]

    def test_abuseipdb_rate_limit(self):
        """Should handle rate limit errors."""
        intel = IPIntelligence()

        import urllib.error
        error = urllib.error.HTTPError(
            url="https://api.abuseipdb.com",
            code=429,
            msg="Too Many Requests",
            hdrs={},
            fp=None
        )

        with patch.object(main, 'ABUSEIPDB_API_KEY', "test-key"):
            with patch('urllib.request.urlopen', side_effect=error):
                result = intel._get_abuseipdb("1.2.3.4")

        assert result["error"] == "rate_limited"


class TestVirusTotalLookup:
    """Tests for VirusTotal lookup functionality."""

    def test_virustotal_returns_none_without_key(self):
        """Should return None if no API key is set."""
        intel = IPIntelligence()

        with patch.object(main, 'VIRUSTOTAL_API_KEY', ""):
            result = intel._get_virustotal("8.8.8.8")

        assert result is None

    def test_virustotal_success(self):
        """Should parse successful VirusTotal response."""
        intel = IPIntelligence()

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 50,
                        "undetected": 20
                    },
                    "reputation": -5,
                    "as_owner": "Test AS Owner",
                    "network": "1.0.0.0/8",
                    "total_votes": {
                        "harmless": 10,
                        "malicious": 5
                    }
                }
            }
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock()

        with patch.object(main, 'VIRUSTOTAL_API_KEY', "test-key"):
            with patch('urllib.request.urlopen', return_value=mock_response):
                result = intel._get_virustotal("1.2.3.4")

        assert result["malicious"] == 3
        assert result["suspicious"] == 1
        assert result["reputation"] == -5
        assert result["as_owner"] == "Test AS Owner"


class TestThreatLevelCalculation:
    """Tests for threat level calculation."""

    def test_low_threat_clean_ip(self):
        """Clean IP should have low threat level."""
        intel = IPIntelligence()

        clean_intel = {
            "geo": {
                "is_proxy": False,
                "is_hosting": False,
                "is_mobile": False
            },
            "abuse": {
                "abuse_score": 0,
                "total_reports": 0,
                "is_tor": False,
                "categories": []
            },
            "virustotal": {
                "malicious": 0,
                "suspicious": 0
            }
        }

        level, reasons = intel.get_threat_level(clean_intel)
        assert level == "low"
        assert len(reasons) == 0

    def test_high_threat_tor_node(self):
        """TOR exit node should increase threat level."""
        intel = IPIntelligence()

        tor_intel = {
            "geo": {"is_proxy": True, "is_hosting": False, "is_mobile": False},
            "abuse": {
                "abuse_score": 60,
                "total_reports": 50,
                "is_tor": True,
                "categories": ["SSH"]
            },
            "virustotal": None
        }

        level, reasons = intel.get_threat_level(tor_intel)
        assert level in ("high", "critical")
        assert any("TOR" in r for r in reasons)

    def test_critical_threat_known_attacker(self):
        """Known attacker with high abuse score should be critical."""
        intel = IPIntelligence()

        attacker_intel = {
            "geo": {"is_proxy": True, "is_hosting": True, "is_mobile": False},
            "abuse": {
                "abuse_score": 95,
                "total_reports": 500,
                "is_tor": False,
                "categories": ["SSH", "Brute-Force", "Hacking"]
            },
            "virustotal": {
                "malicious": 10,
                "suspicious": 5
            }
        }

        level, reasons = intel.get_threat_level(attacker_intel)
        assert level == "critical"
        assert len(reasons) >= 3

    def test_medium_threat_hosting_ip(self):
        """Hosting/datacenter IP with some reports should be medium."""
        intel = IPIntelligence()

        hosting_intel = {
            "geo": {"is_proxy": False, "is_hosting": True, "is_mobile": False},
            "abuse": {
                "abuse_score": 30,
                "total_reports": 15,
                "is_tor": False,
                "categories": []
            },
            "virustotal": None
        }

        level, reasons = intel.get_threat_level(hosting_intel)
        assert level in ("low", "medium")


class TestAbuseCategories:
    """Tests for abuse category parsing."""

    def test_parse_abuse_categories(self):
        """Should parse category IDs to names."""
        intel = IPIntelligence()

        reports = [
            {"categories": [18, 22]},  # Brute-Force, SSH
            {"categories": [14, 15]},  # Port Scan, Hacking
        ]

        categories = intel._parse_abuse_categories(reports)

        assert "Brute-Force" in categories
        assert "SSH" in categories
        assert "Port Scan" in categories
        assert "Hacking" in categories

    def test_parse_empty_reports(self):
        """Should handle empty reports list."""
        intel = IPIntelligence()
        categories = intel._parse_abuse_categories([])
        assert categories == []

    def test_parse_unknown_categories(self):
        """Should ignore unknown category IDs."""
        intel = IPIntelligence()
        reports = [{"categories": [999, 1000]}]
        categories = intel._parse_abuse_categories(reports)
        assert categories == []


class TestFormatSummary:
    """Tests for summary formatting."""

    def test_format_summary_with_full_data(self):
        """Should format complete intel data."""
        intel = IPIntelligence()

        full_intel = {
            "ip": "1.2.3.4",
            "geo": {
                "country": "United States",
                "city": "New York",
                "isp": "Test ISP",
                "asn": "AS12345",
                "is_proxy": True,
                "is_hosting": False,
                "is_mobile": False
            },
            "abuse": {
                "abuse_score": 75,
                "total_reports": 100,
                "is_tor": True,
                "categories": ["SSH", "Brute-Force"]
            },
            "virustotal": {
                "malicious": 5,
                "suspicious": 2
            }
        }

        summary = intel.format_summary(full_intel)

        assert "New York" in summary
        assert "United States" in summary
        assert "Test ISP" in summary
        assert "75%" in summary
        assert "TOR" in summary

    def test_format_summary_with_minimal_data(self):
        """Should handle minimal intel data."""
        intel = IPIntelligence()

        minimal_intel = {
            "ip": "1.2.3.4",
            "geo": {"error": "lookup failed"},
            "abuse": None,
            "virustotal": None
        }

        summary = intel.format_summary(minimal_intel)

        # Should still include threat level
        assert "Threat Level" in summary


class TestGetIntel:
    """Tests for the main get_intel method."""

    def test_get_intel_uses_cache(self, tmp_path):
        """Should return cached data if valid."""
        with patch.object(main, 'IP_INTEL_CACHE', tmp_path / "cache.json"):
            intel = IPIntelligence()
            intel.cache["8.8.8.8"] = {
                "cached_at": datetime.now().isoformat(),
                "geo": {"country": "Cached Country"},
                "abuse": None,
                "virustotal": None
            }

            result = intel.get_intel("8.8.8.8")

            assert result["geo"]["country"] == "Cached Country"

    def test_get_intel_fetches_fresh_data(self, tmp_path):
        """Should fetch fresh data if cache is invalid."""
        with patch.object(main, 'IP_INTEL_CACHE', tmp_path / "cache.json"):
            intel = IPIntelligence()

            mock_response = MagicMock()
            mock_response.read.return_value = json.dumps({
                "status": "success",
                "country": "Fresh Country",
                "countryCode": "FC",
                "regionName": "Region",
                "city": "City",
                "zip": "12345",
                "lat": 0,
                "lon": 0,
                "timezone": "UTC",
                "isp": "ISP",
                "org": "Org",
                "as": "AS1",
                "asname": "ASName",
                "mobile": False,
                "proxy": False,
                "hosting": False
            }).encode()
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock()

            with patch('urllib.request.urlopen', return_value=mock_response):
                result = intel.get_intel("1.2.3.4")

            assert result["geo"]["country"] == "Fresh Country"
            assert "1.2.3.4" in intel.cache

    def test_get_intel_saves_to_cache(self, tmp_path):
        """Should save fresh data to cache file."""
        cache_file = tmp_path / "cache.json"
        with patch.object(main, 'IP_INTEL_CACHE', cache_file):
            intel = IPIntelligence()

            mock_response = MagicMock()
            mock_response.read.return_value = json.dumps({
                "status": "success",
                "country": "Test",
                "countryCode": "TS",
                "regionName": "",
                "city": "",
                "zip": "",
                "lat": 0,
                "lon": 0,
                "timezone": "",
                "isp": "",
                "org": "",
                "as": "",
                "asname": "",
                "mobile": False,
                "proxy": False,
                "hosting": False
            }).encode()
            mock_response.__enter__ = lambda s: s
            mock_response.__exit__ = MagicMock()

            with patch('urllib.request.urlopen', return_value=mock_response):
                intel.get_intel("5.6.7.8")

            # Check file was created
            assert cache_file.exists()

            # Check content
            with open(cache_file, 'r') as f:
                saved_cache = json.load(f)
            assert "5.6.7.8" in saved_cache
