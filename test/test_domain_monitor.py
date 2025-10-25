#!/usr/bin/env python3
"""
Test suite for domain_monitor.py using pytest
"""

import sys
import os
import pytest
import tempfile
from datetime import datetime
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.domain_checker import check_domain
from src.config import Config
from src.domain_info import DomainInfo
from src.database import DatabaseManager

@pytest.fixture
def test_config():
    """Create test configuration with minimal delay."""
    import tempfile

    # Create a temporary database file for testing
    db_file = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    db_path = db_file.name
    db_file.close()

    config = Config()
    config.data['general']['query_delay'] = 0.5  # Use shorter delay for testing
    config.data['general']['query_jitter'] = 0.2
    config.data['general']['db_path'] = db_path

    # Reinitialize database with the temp file
    config.db = DatabaseManager(db_path)

    return config

def test_domain_info_initialization():
    """Test DomainInfo class initialization."""
    info = DomainInfo("example.com")
    assert info.domain == "example.com"
    assert info.expiration_date is None
    assert info.days_until_expiration is None
    assert info.status == []
    assert info.nameservers == []
    assert info.is_expired is False
    assert info.has_concerning_status is False
    assert info.nameservers_changed is False
    assert info.added_nameservers == []
    assert info.removed_nameservers == []
    assert info.error is None

@pytest.mark.parametrize("domain", [
    "google.com",
    "github.com"
])
def test_check_domain_returns_data(domain, test_config, monkeypatch):
    """Test that check_domain returns data for all expected fields."""

    # Mock the whois and dns resolver calls to avoid network dependencies
    class MockWhois:
        def __init__(self, domain):
            self.domain = domain
            self.nameservers = ["ns1.example.com", "ns2.example.com"]
            self.expiration_date = datetime.now().replace(year=datetime.now().year + 1)
            self.status = ["clientTransferProhibited", "serverDeleteProhibited"]

    def mock_whois(domain):
        return MockWhois(domain)

    class MockNSRecord:
        def __init__(self, ns_name):
            self.ns_name = ns_name

        def to_text(self):
            return self.ns_name + '.'

    class MockDNSResolver:
        def resolve(self, domain, record_type):
            if record_type == 'NS':
                return [MockNSRecord("ns1.example.com"), MockNSRecord("ns2.example.com")]
            elif record_type == 'A':
                class MockARecord:
                    def __str__(self):
                        return "1.2.3.4"
                return [MockARecord()]
            return []

    monkeypatch.setattr("src.domain_checker.whois.whois", mock_whois)
    monkeypatch.setattr("src.domain_checker.dns.resolver", MockDNSResolver())

    # Now run through our function
    info = check_domain(domain, test_config, force_check=True)

    # Print diagnostic info
    print(f"\nDomain info for {domain}:")
    print(f"Error: {info.error}")
    print(f"Expiration date: {info.expiration_date}")
    print(f"Days until expiration: {info.days_until_expiration}")
    print(f"Status: {info.status}")
    print(f"Nameservers: {info.nameservers}")

    # Basic checks
    assert info.domain == domain
    assert info.error is None

    # Check expiration date
    assert info.expiration_date is not None
    assert isinstance(info.expiration_date, datetime)

    # Check days until expiration
    assert info.days_until_expiration is not None
    assert isinstance(info.days_until_expiration, int)

    # Check status
    assert info.status is not None
    assert len(info.status) > 0
    assert all(isinstance(s, str) for s in info.status)

    # Check nameservers
    assert info.nameservers is not None
    assert len(info.nameservers) > 0
    assert all(isinstance(ns, str) for ns in info.nameservers)

    # Check derived flags
    assert isinstance(info.is_expired, bool)
    assert isinstance(info.has_concerning_status, bool)
    assert isinstance(info.nameservers_changed, bool)


def test_database_manager():
    """Test the DatabaseManager class for nameserver tracking."""
    # Use a temporary file for the test database
    with tempfile.NamedTemporaryFile(suffix='.db') as db_file:
        db = DatabaseManager(db_file.name)

        # Test initialization
        assert os.path.exists(db_file.name)

        # Test adding nameservers
        domain = "testdomain.com"
        nameservers1 = ["ns1.example.com", "ns2.example.com"]

        # First update should not report a change (first time seeing the domain)
        changed, added, removed = db.update_nameservers(domain, nameservers1)
        assert not changed
        assert not added  # No additions recorded for first check
        assert not removed

        # Verify the nameservers were stored
        stored_ns = db.get_current_nameservers(domain)
        assert sorted([ns.lower() for ns in stored_ns]) == sorted([ns.lower() for ns in nameservers1])

        # Second update with the same nameservers should not report a change
        changed, added, removed = db.update_nameservers(domain, nameservers1)
        assert not changed
        assert not added
        assert not removed

        # Update with different nameservers should report a change
        nameservers2 = ["ns2.example.com", "ns3.example.com"]
        changed, added, removed = db.update_nameservers(domain, nameservers2)
        assert changed
        assert added == ["ns3.example.com"]
        assert removed == ["ns1.example.com"]

        # Verify the updated nameservers
        stored_ns = db.get_current_nameservers(domain)
        assert sorted([ns.lower() for ns in stored_ns]) == sorted([ns.lower() for ns in nameservers2])

        # Check history
        history = db.get_nameserver_history(domain)
        assert len(history) == 2  # One add and one remove event (only from the second update)

        # Test case insensitivity (nameservers in different case should not trigger a change)
        upper_ns = [ns.upper() for ns in nameservers2]
        changed, added, removed = db.update_nameservers(domain, upper_ns)
        assert not changed
        assert not added
        assert not removed


def test_nameserver_change_detection_in_check_domain(test_config, monkeypatch):
    """Test nameserver change detection in the check_domain function."""
    domain = "example.com"

    # Mock the whois and dns resolver calls to control the test
    class MockWhois:
        def __init__(self, domain):
            self.domain = domain
            self.nameservers = ["ns1.example.com", "ns2.example.com"]
            self.expiration_date = datetime.now().replace(year=datetime.now().year + 1)
            self.status = "clientTransferProhibited"

    def mock_whois(domain):
        return MockWhois(domain)

    # First check with the mock nameservers
    monkeypatch.setattr("src.domain_checker.whois.whois", mock_whois)

    # First check should not show a change (first time seeing the domain)
    info1 = check_domain(domain, test_config, force_check=True)
    assert not info1.nameservers_changed
    assert info1.nameservers == ["ns1.example.com", "ns2.example.com"]

    # Now change the nameservers for the next check
    class MockWhoisChanged(MockWhois):
        def __init__(self, domain):
            super().__init__(domain)
            self.nameservers = ["ns2.example.com", "ns3.example.com"]

    def mock_whois_changed(domain):
        return MockWhoisChanged(domain)

    monkeypatch.setattr("src.domain_checker.whois.whois", mock_whois_changed)

    # Second check should detect the nameserver change (force check to bypass cache)
    info2 = check_domain(domain, test_config, force_check=True)
    assert info2.nameservers_changed
    assert sorted(info2.nameservers) == sorted(["ns2.example.com", "ns3.example.com"])
    assert sorted(info2.added_nameservers) == sorted(["ns3.example.com"])
    assert sorted(info2.removed_nameservers) == sorted(["ns1.example.com"])


def test_domain_whois_caching(test_config, monkeypatch):
    """Test that domain WHOIS data is cached and retrieved correctly."""
    domain = "example.com"

    # Mock the whois call
    class MockWhois:
        def __init__(self, domain):
            self.domain = domain
            self.nameservers = ["ns1.example.com", "ns2.example.com"]
            self.expiration_date = datetime.now().replace(year=datetime.now().year + 1)
            self.status = "clientTransferProhibited"

    def mock_whois(domain):
        return MockWhois(domain)

    whois_call_count = 0
    def counting_mock_whois(domain):
        nonlocal whois_call_count
        whois_call_count += 1
        return MockWhois(domain)

    monkeypatch.setattr("src.domain_checker.whois.whois", counting_mock_whois)

    # Set cache_hours to a high value so cache doesn't expire
    test_config.data['general']['cache_hours'] = 48

    # First check should do WHOIS lookup
    info1 = check_domain(domain, test_config, force_check=False)
    assert whois_call_count == 1
    assert info1.error is None

    # Second check should use cached data (no new WHOIS call)
    info2 = check_domain(domain, test_config, force_check=False)
    assert whois_call_count == 1  # Should still be 1
    assert info2.error is None
    assert info2.expiration_date == info1.expiration_date
    assert info2.status == info1.status

    # Force check should bypass cache
    info3 = check_domain(domain, test_config, force_check=True)
    assert whois_call_count == 2  # Should increment
    assert info3.error is None


def test_domain_whois_cache_expiry(test_config, monkeypatch):
    """Test that domain WHOIS cache expires correctly."""
    domain = "example.com"

    class MockWhois:
        def __init__(self, domain):
            self.domain = domain
            self.nameservers = ["ns1.example.com", "ns2.example.com"]
            self.expiration_date = datetime.now().replace(year=datetime.now().year + 1)
            self.status = "clientTransferProhibited"

    whois_call_count = 0
    def counting_mock_whois(domain):
        nonlocal whois_call_count
        whois_call_count += 1
        return MockWhois(domain)

    monkeypatch.setattr("src.domain_checker.whois.whois", counting_mock_whois)

    # Set cache_hours to 0 so cache always expires
    test_config.data['general']['cache_hours'] = 0

    # First check
    info1 = check_domain(domain, test_config, force_check=False)
    assert whois_call_count == 1
    assert info1 is not None

    # Second check should do new WHOIS lookup due to expired cache
    info2 = check_domain(domain, test_config, force_check=False)
    assert whois_call_count == 2
    assert info2 is not None


def test_database_domain_whois_storage():
    """Test storing and retrieving domain WHOIS data."""
    with tempfile.NamedTemporaryFile(suffix='.db') as db_file:
        db = DatabaseManager(db_file.name)

        domain = "testdomain.com"
        exp_date = datetime.now().replace(year=datetime.now().year + 1)
        status = ["clientTransferProhibited", "serverDeleteProhibited"]

        # Test initial storage
        changed, changes = db.update_domain_whois(
            domain, exp_date, status, False, False, 365, None
        )
        assert not changed  # First time, so no change detected

        # Test retrieval
        cached_data = db.get_cached_domain_info(domain)
        assert cached_data is not None
        assert cached_data['domain'] == domain
        assert cached_data['expiration_date'] == exp_date
        assert cached_data['status'] == status
        assert cached_data['has_concerning_status'] == 0  # SQLite returns 0/1 for boolean
        assert cached_data['is_expired'] == 0
        assert cached_data['days_until_expiration'] == 365
        assert cached_data['error'] is None

        # Test change detection
        new_status = ["clientTransferProhibited", "pendingDelete"]
        changed, changes = db.update_domain_whois(
            domain, exp_date, new_status, True, False, 365, None
        )
        assert changed
        assert 'status' in changes
        assert changes['status']['old'] == status
        assert changes['status']['new'] == new_status

        # Test cache age check
        assert not db.should_check_domain(domain, 24)  # Just updated
        assert db.should_check_domain(domain, 0)  # Expired cache
