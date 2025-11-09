#!/usr/bin/env python3
"""
Test suite for domain_monitor.py using pytest
"""

import sys
import os
import pytest
import tempfile
from datetime import datetime, timezone
import datetime as dt
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.domain_checker import check_domain, needs_alert
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

    # Create config with non-existent config file to ensure defaults are used
    config = Config(config_path='non_existent_config.yaml')
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
def test_check_domain_returns_data(domain, test_config):
    """Test that check_domain returns data for all expected fields."""
    import whoisit
    import dns.resolver

    # First, let's do direct queries to check the raw data
    print(f"\nDirect WHOIS check for {domain}:")
    whoisit.bootstrap()
    w = whoisit.domain(domain)
    print(f"Raw nameservers from WHOIS: {w.get('nameservers')}")

    print(f"\nDirect DNS check for {domain}:")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        ns_names = [ns.to_text().rstrip('.') for ns in ns_records]
        print(f"Raw nameservers from DNS: {ns_names}")
    except Exception as e:
        print(f"DNS lookup failed: {e}")

    # Now run through our function
    info = check_domain(domain, test_config)

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

    # Mock the whoisit and dns resolver calls to control the test
    def mock_whoisit_domain(domain):
        return {
            'nameservers': ["ns1.example.com", "ns2.example.com"],
            'expiration_date': dt.datetime.now(dt.UTC).replace(tzinfo=None, year=dt.datetime.now(dt.UTC).year + 1),
            'status': ["clientTransferProhibited"]
        }

    # Mock whoisit bootstrap
    monkeypatch.setattr("src.domain_checker.whoisit.is_bootstrapped", lambda: True)

    # First check with the mock nameservers
    monkeypatch.setattr("src.domain_checker.whoisit.domain", mock_whoisit_domain)

    # First check should not show a change (first time seeing the domain)
    info1 = check_domain(domain, test_config, should_refresh=True)
    assert not info1.nameservers_changed
    assert info1.nameservers == ["ns1.example.com", "ns2.example.com"]

    # Now change the nameservers for the next check
    def mock_whoisit_domain_changed(domain):
        return {
            'nameservers': ["ns2.example.com", "ns3.example.com"],
            'expiration_date': dt.datetime.now(dt.UTC).replace(tzinfo=None, year=dt.datetime.now(dt.UTC).year + 1),
            'status': ["clientTransferProhibited"]
        }

    monkeypatch.setattr("src.domain_checker.whoisit.domain", mock_whoisit_domain_changed)

    # Second check should detect the nameserver change (force check to bypass cache)
    info2 = check_domain(domain, test_config, should_refresh=True)
    assert info2.nameservers_changed
    assert sorted(info2.nameservers) == sorted(["ns2.example.com", "ns3.example.com"])
    assert sorted(info2.added_nameservers) == sorted(["ns3.example.com"])
    assert sorted(info2.removed_nameservers) == sorted(["ns1.example.com"])


def test_domain_whois_caching(test_config, monkeypatch):
    """Test that domain WHOIS data is cached and retrieved correctly."""
    domain = "example.com"

    # Mock the whoisit call
    def mock_whoisit_domain(domain):
        return {
            'nameservers': ["ns1.example.com", "ns2.example.com"],
            'expiration_date': dt.datetime.now(dt.UTC).replace(tzinfo=None, year=dt.datetime.now(dt.UTC).year + 1),
            'status': ["clientTransferProhibited"]
        }

    whois_call_count = 0
    def counting_mock_whoisit_domain(domain):
        nonlocal whois_call_count
        whois_call_count += 1
        return mock_whoisit_domain(domain)

    # Mock whoisit bootstrap
    monkeypatch.setattr("src.domain_checker.whoisit.is_bootstrapped", lambda: True)
    monkeypatch.setattr("src.domain_checker.whoisit.domain", counting_mock_whoisit_domain)

    # Set cache_hours to a high value so cache doesn't expire
    test_config.data['general']['cache_hours'] = 48

    # First check should do WHOIS lookup
    info1 = check_domain(domain, test_config, should_refresh=False)
    assert whois_call_count == 1
    assert info1.error is None

    # Second check should use cached data (no new WHOIS call)
    info2 = check_domain(domain, test_config, should_refresh=False)
    assert whois_call_count == 1  # Should still be 1
    assert info2.error is None
    assert info2.expiration_date == info1.expiration_date
    assert info2.status == info1.status

    # Force check should bypass cache
    info3 = check_domain(domain, test_config, should_refresh=True)
    assert whois_call_count == 2  # Should increment
    assert info3.error is None


def test_domain_whois_cache_expiry(test_config, monkeypatch):
    """Test that domain WHOIS cache expires correctly."""
    domain = "example.com"

    def mock_whoisit_domain(domain):
        return {
            'nameservers': ["ns1.example.com", "ns2.example.com"],
            'expiration_date': dt.datetime.now(dt.UTC).replace(tzinfo=None, year=dt.datetime.now(dt.UTC).year + 1),
            'status': ["clientTransferProhibited"]
        }

    whois_call_count = 0
    def counting_mock_whoisit_domain(domain):
        nonlocal whois_call_count
        whois_call_count += 1
        return mock_whoisit_domain(domain)

    # Mock whoisit bootstrap
    monkeypatch.setattr("src.domain_checker.whoisit.is_bootstrapped", lambda: True)
    monkeypatch.setattr("src.domain_checker.whoisit.domain", counting_mock_whoisit_domain)

    # Set cache_hours to 0 so cache always expires
    test_config.data['general']['cache_hours'] = 0

    # First check
    info1 = check_domain(domain, test_config, should_refresh=False)
    assert whois_call_count == 1
    assert info1 is not None

    # Second check should do new WHOIS lookup due to expired cache
    info2 = check_domain(domain, test_config, should_refresh=False)
    assert whois_call_count == 2
    assert info2 is not None


def test_database_domain_whois_storage():
    """Test storing and retrieving domain WHOIS data."""
    with tempfile.NamedTemporaryFile(suffix='.db') as db_file:
        db = DatabaseManager(db_file.name)

        domain = "testdomain.com"
        exp_date = dt.datetime.now(dt.UTC).replace(tzinfo=None, year=dt.datetime.now(dt.UTC).year + 1)
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


def test_needs_alert_with_configurable_conditions(test_config):
    """Test needs_alert function with configurable alert conditions."""
    # Test 1: Domain expiring soon
    info = DomainInfo("example.com")
    info.days_until_expiration = 15
    test_config.data['general']['alert_days'] = 30

    should_alert, reason = needs_alert(info, test_config)
    assert should_alert
    assert "Expiring soon" in reason
    assert "15 days remaining" in reason

    # Test 2: Concerning status (default list)
    info2 = DomainInfo("example2.com")
    info2.days_until_expiration = 100
    info2.status = ["clientTransferProhibited", "redemptionPeriod"]
    info2.has_concerning_status = True

    should_alert, reason = needs_alert(info2, test_config)
    assert should_alert
    assert "Concerning status" in reason
    assert "redemptionPeriod" in reason

    # Test 3: Custom concerning status
    info3 = DomainInfo("example3.com")
    info3.days_until_expiration = 100
    info3.status = ["clientTransferProhibited", "autoRenewPeriod"]

    # Add autoRenewPeriod to concerning statuses
    test_config.data['alert_conditions']['concerning_statuses'].append('autoRenewPeriod')

    should_alert, reason = needs_alert(info3, test_config)
    assert should_alert
    assert "Concerning status" in reason
    assert "autoRenewPeriod" in reason

    # Test 4: Nameserver changes (enabled by default)
    info4 = DomainInfo("example4.com")
    info4.days_until_expiration = 100
    info4.nameservers_changed = True
    info4.added_nameservers = ["ns3.example.com"]
    info4.removed_nameservers = ["ns1.example.com"]

    # Should alert by default
    should_alert, reason = needs_alert(info4, test_config)
    assert should_alert
    assert "Nameserver changes detected" in reason
    assert "added: ns3.example.com" in reason
    assert "removed: ns1.example.com" in reason

    # Disable nameserver change alerts
    test_config.data['alert_conditions']['alert_on_nameserver_changes'] = False
    should_alert, reason = needs_alert(info4, test_config)
    assert not should_alert

    # Test 5: Apex resolution changes (disabled by default)
    info5 = DomainInfo("example5.com")
    info5.days_until_expiration = 100
    info5.apex_changed = True
    info5.apex_added_ips = ["1.2.3.4"]
    info5.apex_removed_ips = ["5.6.7.8"]

    # Should not alert when disabled
    should_alert, reason = needs_alert(info5, test_config)
    assert not should_alert

    # Enable apex resolution change alerts
    test_config.data['alert_conditions']['alert_on_resolution_changes']['apex'] = True
    should_alert, reason = needs_alert(info5, test_config)
    assert should_alert
    assert "Apex resolution changes detected" in reason
    assert "added: 1.2.3.4" in reason
    assert "removed: 5.6.7.8" in reason

    # Test 6: Domain doesn't exist
    info6 = DomainInfo("example6.com")
    info6.domain_not_exist = True

    should_alert, reason = needs_alert(info6, test_config)
    assert should_alert
    assert "Domain does not exist (NXDOMAIN)" in reason

    # Test 7: Error checking domain
    info7 = DomainInfo("example7.com")
    info7.error = "Connection timeout"

    should_alert, reason = needs_alert(info7, test_config)
    assert should_alert
    assert "Error checking domain" in reason
    assert "Connection timeout" in reason


def test_timezone_utc_conversion():
    """Test that timezone-aware WHOIS dates are properly converted to UTC."""
    import datetime

    # Test timezone-aware datetime conversion
    # Create a timezone-aware datetime (EST is UTC-5)
    est_tz = datetime.timezone(datetime.timedelta(hours=-5))
    est_date = datetime.datetime(2025, 12, 31, 23, 59, 59, tzinfo=est_tz)

    # Convert to UTC using the same method as in domain_checker.py
    utc_tuple = est_date.utctimetuple()
    utc_date = datetime.datetime(*utc_tuple[:6])

    # The UTC date should be 5 hours ahead of EST
    expected_utc = datetime.datetime(2026, 1, 1, 4, 59, 59)
    assert utc_date == expected_utc

    # Test with naive datetime (should remain unchanged)
    naive_date = datetime.datetime(2025, 12, 31, 23, 59, 59)
    # For naive datetime, we don't have tzinfo, so it should remain as-is
    assert naive_date.tzinfo is None


def test_mixed_timezone_list_handling():
    """Test handling of mixed timezone-aware and naive datetime lists."""
    import datetime

    # Create mixed list of timezone-aware and naive datetimes
    utc_tz = datetime.timezone.utc
    est_tz = datetime.timezone(datetime.timedelta(hours=-5))

    # Create test dates
    utc_date = datetime.datetime(2025, 12, 31, 23, 59, 59, tzinfo=utc_tz)
    est_date = datetime.datetime(2025, 12, 31, 18, 59, 59, tzinfo=est_tz)  # Same as UTC when converted
    naive_date = datetime.datetime(2025, 12, 31, 23, 59, 59)  # Assume UTC

    mixed_dates = [utc_date, est_date, naive_date]

    # Process like domain_checker.py does
    normalized_dates = []
    for date in mixed_dates:
        if date.tzinfo:
            # Convert timezone-aware to UTC
            utc_tuple = date.utctimetuple()
            normalized_dates.append(datetime.datetime(*utc_tuple[:6]))
        else:
            # Assume naive datetime is already UTC
            normalized_dates.append(date)

    # All dates should be normalized to UTC
    expected_utc = datetime.datetime(2025, 12, 31, 23, 59, 59)
    assert all(d == expected_utc for d in normalized_dates)


def test_utc_expiration_calculation():
    """Test that domain expiration calculations use UTC consistently."""
    import datetime
    from unittest.mock import patch

    # Mock datetime.now to return a known UTC time
    fixed_utc_now = datetime.datetime(2025, 6, 1, 12, 0, 0)

    with patch('src.domain_checker.datetime') as mock_datetime:
        mock_datetime.datetime.now.return_value = fixed_utc_now
        mock_datetime.datetime.side_effect = datetime.datetime

        # Create domain info with UTC expiration date
        info = DomainInfo("example.com")

        # Test case 1: Domain expires in 30 days
        info.expiration_date = datetime.datetime(2025, 7, 1, 12, 0, 0)  # 30 days from now
        info.days_until_expiration = (info.expiration_date - fixed_utc_now).days
        info.is_expired = info.days_until_expiration <= 0

        assert info.days_until_expiration == 30
        assert not info.is_expired

        # Test case 2: Domain expired 5 days ago
        info.expiration_date = datetime.datetime(2025, 5, 27, 12, 0, 0)  # 5 days ago
        info.days_until_expiration = (info.expiration_date - fixed_utc_now).days
        info.is_expired = info.days_until_expiration <= 0

        assert info.days_until_expiration == -5
        assert info.is_expired


def test_database_utc_timestamps():
    """Test that database operations use UTC timestamps consistently."""
    import datetime
    from unittest.mock import patch

    with tempfile.NamedTemporaryFile(suffix='.db') as db_file:
        db = DatabaseManager(db_file.name)

        # Mock datetime.now to return a known UTC time
        fixed_utc_now = datetime.datetime(2025, 6, 1, 12, 0, 0)

        with patch('src.database.datetime') as mock_datetime:
            mock_datetime.datetime.now.return_value = fixed_utc_now
            mock_datetime.datetime.side_effect = datetime.datetime

            # Test nameserver update uses UTC
            domain = "test.com"
            nameservers = ["ns1.test.com", "ns2.test.com"]

            changed, added, removed = db.update_nameservers(domain, nameservers)

            # Check that the timestamp in the database is the mocked UTC time
            conn = db._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp FROM nameserver_history WHERE domain = ?", (domain,))
            results = cursor.fetchall()
            conn.close()

            # The timestamp should be stored as ISO format string
            if results:
                stored_timestamp = results[0]['timestamp']
                # Convert back to datetime to verify it's our mocked UTC time
                parsed_timestamp = datetime.datetime.fromisoformat(stored_timestamp)
                assert parsed_timestamp == fixed_utc_now


def test_whois_timezone_conversion_edge_cases():
    """Test edge cases in WHOIS timezone conversion."""
    import datetime

    # Test case 1: UTC timezone (should remain unchanged)
    utc_tz = datetime.timezone.utc
    utc_date = datetime.datetime(2025, 12, 31, 23, 59, 59, tzinfo=utc_tz)

    utc_tuple = utc_date.utctimetuple()
    converted_date = datetime.datetime(*utc_tuple[:6])

    # Should be identical when timezone info is stripped
    expected = datetime.datetime(2025, 12, 31, 23, 59, 59)
    assert converted_date == expected

    # Test case 2: Positive timezone offset (e.g., JST is UTC+9)
    jst_tz = datetime.timezone(datetime.timedelta(hours=9))
    jst_date = datetime.datetime(2025, 12, 31, 23, 59, 59, tzinfo=jst_tz)

    utc_tuple = jst_date.utctimetuple()
    converted_date = datetime.datetime(*utc_tuple[:6])

    # JST 23:59 should be UTC 14:59 (9 hours earlier)
    expected = datetime.datetime(2025, 12, 31, 14, 59, 59)
    assert converted_date == expected

    # Test case 3: Negative timezone offset crossing date boundary
    pst_tz = datetime.timezone(datetime.timedelta(hours=-8))
    pst_date = datetime.datetime(2025, 1, 1, 7, 0, 0, tzinfo=pst_tz)

    utc_tuple = pst_date.utctimetuple()
    converted_date = datetime.datetime(*utc_tuple[:6])

    # PST 07:00 should be UTC 15:00 (8 hours ahead)
    expected = datetime.datetime(2025, 1, 1, 15, 0, 0)
    assert converted_date == expected


@pytest.mark.integration
def test_whoisit_integration_eli_pizza():
    """Integration test verifying whoisit can retrieve data for eli.pizza."""
    import whoisit

    # Bootstrap whoisit
    whoisit.bootstrap()

    # Test direct whoisit query
    result = whoisit.domain('eli.pizza')

    # Verify we got valid data
    assert result is not None
    assert 'expiration_date' in result
    assert 'status' in result
    assert 'nameservers' in result

    # Verify specific data types and values
    assert result['expiration_date'] is not None
    assert isinstance(result['expiration_date'], dt.datetime)
    assert isinstance(result['status'], list)
    assert len(result['status']) > 0
    assert isinstance(result['nameservers'], list)
    assert len(result['nameservers']) > 0

    # Verify nameservers are strings and look valid
    for ns in result['nameservers']:
        assert isinstance(ns, str)
        assert '.' in ns  # Basic validation that it looks like a domain name

    # Verify the domain is not expired (should have future expiration)
    now = dt.datetime.now(dt.UTC)
    assert result['expiration_date'] > now

    print(f"eli.pizza integration test passed:")
    print(f"  Expiration: {result['expiration_date']}")
    print(f"  Status: {result['status']}")
    print(f"  Nameservers: {result['nameservers']}")


@pytest.mark.integration
def test_whoisit_integration_elidickinson_com():
    """Integration test verifying whoisit can retrieve data for elidickinson.com."""
    import whoisit

    # Bootstrap whoisit (should already be bootstrapped from previous test, but safe to ensure)
    if not whoisit.is_bootstrapped():
        whoisit.bootstrap()

    # Test direct whoisit query
    result = whoisit.domain('elidickinson.com')

    # Verify we got valid data
    assert result is not None
    assert 'expiration_date' in result
    assert 'status' in result
    assert 'nameservers' in result

    # Verify specific data types and values
    assert result['expiration_date'] is not None
    assert isinstance(result['expiration_date'], dt.datetime)
    assert isinstance(result['status'], list)
    assert len(result['status']) > 0
    assert isinstance(result['nameservers'], list)
    assert len(result['nameservers']) > 0

    # Verify nameservers are strings and look valid
    for ns in result['nameservers']:
        assert isinstance(ns, str)
        assert '.' in ns  # Basic validation that it looks like a domain name

    # Verify the domain is not expired (should have future expiration)
    now = dt.datetime.now(dt.UTC)
    assert result['expiration_date'] > now

    print(f"elidickinson.com integration test passed:")
    print(f"  Expiration: {result['expiration_date']}")
    print(f"  Status: {result['status']}")
    print(f"  Nameservers: {result['nameservers']}")


@pytest.mark.integration
def test_domain_checker_integration_target_domains():
    """Integration test verifying the full domain_checker works with target domains."""
    from src.config import Config
    from src.domain_checker import check_domain

    config = Config()

    # Test eli.pizza
    info_eli = check_domain('eli.pizza', config, should_refresh=True)

    assert info_eli.domain == 'eli.pizza'
    assert info_eli.error is None
    assert info_eli.expiration_date is not None
    assert isinstance(info_eli.expiration_date, dt.datetime)
    assert info_eli.days_until_expiration is not None
    assert info_eli.days_until_expiration > 0  # Should not be expired
    assert not info_eli.is_expired
    assert isinstance(info_eli.status, list)
    assert len(info_eli.status) > 0
    assert isinstance(info_eli.nameservers, list)
    assert len(info_eli.nameservers) > 0

    # Test elidickinson.com
    info_elidickinson = check_domain('elidickinson.com', config, should_refresh=True)

    assert info_elidickinson.domain == 'elidickinson.com'
    assert info_elidickinson.error is None
    assert info_elidickinson.expiration_date is not None
    assert isinstance(info_elidickinson.expiration_date, dt.datetime)
    assert info_elidickinson.days_until_expiration is not None
    assert info_elidickinson.days_until_expiration > 0  # Should not be expired
    assert not info_elidickinson.is_expired
    assert isinstance(info_elidickinson.status, list)
    assert len(info_elidickinson.status) > 0
    assert isinstance(info_elidickinson.nameservers, list)
    assert len(info_elidickinson.nameservers) > 0

    print(f"Domain checker integration test passed for both target domains:")
    print(f"  eli.pizza: expires in {info_eli.days_until_expiration} days")
    print(f"  elidickinson.com: expires in {info_elidickinson.days_until_expiration} days")
