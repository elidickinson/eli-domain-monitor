"""Database operations for domain monitor."""

import sqlite3
import datetime
import logging
import json
from typing import List, Tuple, Dict, Any, Optional

logger = logging.getLogger('domain_monitor.database')


class DatabaseManager:
    """Manager for SQLite database operations."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the database schema if it doesn't exist."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Create nameservers table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS nameservers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            nameserver TEXT NOT NULL,
            first_seen TIMESTAMP NOT NULL,
            last_seen TIMESTAMP NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            UNIQUE(domain, nameserver)
        )
        ''')

        # Create nameserver_history table to track all changes
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS nameserver_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            event_type TEXT NOT NULL,  -- 'add', 'remove'
            nameserver TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL
        )
        ''')

        # Create domain_whois table to store domain status and expiration info
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_whois (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            expiration_date TIMESTAMP,
            status TEXT,  -- JSON array of status strings
            last_checked TIMESTAMP NOT NULL,
            has_concerning_status BOOLEAN NOT NULL DEFAULT 0,
            is_expired BOOLEAN NOT NULL DEFAULT 0,
            days_until_expiration INTEGER,
            error TEXT
        )
        ''')

        # Create domain_whois_history table to track status and expiration changes
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_whois_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            event_type TEXT NOT NULL,  -- 'status_change', 'expiration_change'
            old_value TEXT,
            new_value TEXT,
            timestamp TIMESTAMP NOT NULL
        )
        ''')

        # Create domain_resolution table to track where domains resolve
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_resolution (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            subdomain TEXT NOT NULL,  -- '' for apex, 'www' for www subdomain
            ip_address TEXT,
            last_checked TIMESTAMP NOT NULL,
            is_resolving BOOLEAN NOT NULL DEFAULT 1,
            UNIQUE(domain, subdomain, ip_address)
        )
        ''')

        # Create domain_resolution_history table to track resolution changes
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_resolution_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            event_type TEXT NOT NULL,  -- 'add', 'remove', 'nxdomain'
            ip_address TEXT,
            timestamp TIMESTAMP NOT NULL
        )
        ''')

        conn.commit()
        conn.close()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_current_nameservers(self, domain: str) -> List[str]:
        """Get the current active nameservers for a domain."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
        SELECT nameserver FROM nameservers
        WHERE domain = ? AND is_active = 1
        ORDER BY nameserver
        ''', (domain,))

        results = cursor.fetchall()
        conn.close()

        return [row['nameserver'] for row in results]

    def update_nameservers(self, domain: str, current_nameservers: List[str]) -> Tuple[bool, List[str], List[str]]:
        """
        Update nameservers for a domain and detect changes.

        Args:
            domain: The domain name
            current_nameservers: List of current nameservers from WHOIS/DNS

        Returns:
            Tuple containing:
                - Boolean indicating if nameservers changed
                - List of added nameservers
                - List of removed nameservers
        """
        # Make sure nameservers are sorted for easier comparison (order doesn't matter)
        if not current_nameservers:
            return False, [], []

        current_nameservers = sorted([ns.lower() for ns in current_nameservers])
        previous_nameservers = sorted([ns.lower() for ns in self.get_current_nameservers(domain)])

        # Early exit if identical
        if current_nameservers == previous_nameservers:
            # Just update the last_seen timestamp
            self._update_last_seen(domain, current_nameservers)
            return False, [], []

        # Get differences
        added = [ns for ns in current_nameservers if ns not in previous_nameservers]
        removed = [ns for ns in previous_nameservers if ns not in current_nameservers]

        # If there's no record yet (first time checking), don't report it as a change
        is_first_check = not previous_nameservers

        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.datetime.utcnow().isoformat()

        try:
            # Mark all previous nameservers as inactive
            if not is_first_check:
                cursor.execute('''
                UPDATE nameservers SET is_active = 0
                WHERE domain = ?
                ''', (domain,))

            # Insert or update current nameservers
            for ns in current_nameservers:
                cursor.execute('''
                INSERT INTO nameservers (domain, nameserver, first_seen, last_seen, is_active)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(domain, nameserver)
                DO UPDATE SET last_seen = ?, is_active = 1
                ''', (domain, ns, now, now, now))

            # Record history for added and removed nameservers (but not for first check)
            if not is_first_check:
                for ns in added:
                    cursor.execute('''
                    INSERT INTO nameserver_history (domain, event_type, nameserver, timestamp)
                    VALUES (?, 'add', ?, ?)
                    ''', (domain, ns, now))

                for ns in removed:
                    cursor.execute('''
                    INSERT INTO nameserver_history (domain, event_type, nameserver, timestamp)
                    VALUES (?, 'remove', ?, ?)
                    ''', (domain, ns, now))

            conn.commit()
        except Exception as e:
            logger.error(f"Database error updating nameservers for {domain}: {e}")
            conn.rollback()
            return False, [], []
        finally:
            conn.close()

        # Don't return added/removed for first check
        if is_first_check:
            return False, [], []
        else:
            return bool(added or removed), added, removed

    def _update_last_seen(self, domain: str, nameservers: List[str]) -> None:
        """Update the last_seen timestamp for nameservers."""
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.datetime.utcnow().isoformat()

        try:
            for ns in nameservers:
                cursor.execute('''
                UPDATE nameservers
                SET last_seen = ?
                WHERE domain = ? AND nameserver = ?
                ''', (now, domain, ns))

            conn.commit()
        except Exception as e:
            logger.error(f"Database error updating last_seen for {domain}: {e}")
            conn.rollback()
        finally:
            conn.close()

    def get_nameserver_history(self, domain: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent nameserver history for a domain."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
        SELECT event_type, nameserver, timestamp
        FROM nameserver_history
        WHERE domain = ?
        ORDER BY timestamp DESC
        LIMIT ?
        ''', (domain, limit))

        results = cursor.fetchall()
        conn.close()

        return [dict(row) for row in results]

    def should_check_domain(self, domain: str, cache_hours: int = 24) -> bool:
        """Check if domain should be re-checked based on cache age."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
        SELECT last_checked FROM domain_whois
        WHERE domain = ?
        ''', (domain,))

        result = cursor.fetchone()
        conn.close()

        if not result:
            # No record exists, should check
            return True

        last_checked = datetime.datetime.fromisoformat(result['last_checked'])
        cache_expiry = last_checked + datetime.timedelta(hours=cache_hours)

        # Ensure consistent timezone handling - use naive datetimes for cache comparison
        now = datetime.datetime.utcnow()
        if last_checked.tzinfo is not None:
            # Convert timezone-aware last_checked to naive UTC
            last_checked = last_checked.replace(tzinfo=None)
            cache_expiry = last_checked + datetime.timedelta(hours=cache_hours)

        return now >= cache_expiry

    def get_cached_domain_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get cached domain information if it exists."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
        SELECT * FROM domain_whois
        WHERE domain = ?
        ''', (domain,))

        result = cursor.fetchone()
        conn.close()

        if result:
            data = dict(result)
            # Parse JSON status array
            if data['status']:
                data['status'] = json.loads(data['status'])
            else:
                data['status'] = []

            # Convert expiration_date string back to datetime
            if data['expiration_date']:
                data['expiration_date'] = datetime.datetime.fromisoformat(data['expiration_date'])

            return data

        return None

    def update_domain_whois(self, domain: str, expiration_date: Optional[datetime.datetime],
                           status: List[str], has_concerning_status: bool, is_expired: bool,
                           days_until_expiration: Optional[int], error: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Update domain WHOIS information and detect changes.

        Returns:
            Tuple containing:
                - Boolean indicating if domain info changed
                - Dict with change details
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.datetime.utcnow().isoformat()

        # Get previous data
        previous_data = self.get_cached_domain_info(domain)

        # Prepare data for storage - ensure timezone-naive for consistent comparisons
        if expiration_date:
            # Convert timezone-aware datetime to naive UTC for consistent storage
            if expiration_date.tzinfo is not None:
                exp_date_str = expiration_date.replace(tzinfo=None).isoformat()
            else:
                exp_date_str = expiration_date.isoformat()
        else:
            exp_date_str = None
        status_json = json.dumps(status) if status else None

        changes = {}

        try:
            if previous_data:
                # Check for changes
                if previous_data['expiration_date'] != expiration_date:
                    changes['expiration_date'] = {
                        'old': previous_data['expiration_date'],
                        'new': expiration_date
                    }

                if previous_data['status'] != status:
                    changes['status'] = {
                        'old': previous_data['status'],
                        'new': status
                    }

                # Update existing record
                cursor.execute('''
                UPDATE domain_whois
                SET expiration_date = ?, status = ?, last_checked = ?,
                    has_concerning_status = ?, is_expired = ?,
                    days_until_expiration = ?, error = ?
                WHERE domain = ?
                ''', (exp_date_str, status_json, now, has_concerning_status,
                      is_expired, days_until_expiration, error, domain))
            else:
                # Insert new record
                cursor.execute('''
                INSERT INTO domain_whois
                (domain, expiration_date, status, last_checked, has_concerning_status,
                 is_expired, days_until_expiration, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (domain, exp_date_str, status_json, now, has_concerning_status,
                      is_expired, days_until_expiration, error))

            # Record history for significant changes
            for change_type, change_data in changes.items():
                old_val = str(change_data['old']) if change_data['old'] else None
                new_val = str(change_data['new']) if change_data['new'] else None

                cursor.execute('''
                INSERT INTO domain_whois_history
                (domain, event_type, old_value, new_value, timestamp)
                VALUES (?, ?, ?, ?, ?)
                ''', (domain, f"{change_type}_change", old_val, new_val, now))

            conn.commit()

        except Exception as e:
            logger.error(f"Database error updating domain WHOIS for {domain}: {e}")
            conn.rollback()
            return False, {}
        finally:
            conn.close()

        return bool(changes), changes

    def get_domain_whois_history(self, domain: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent domain WHOIS history for a domain."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
        SELECT event_type, old_value, new_value, timestamp
        FROM domain_whois_history
        WHERE domain = ?
        ORDER BY timestamp DESC
        LIMIT ?
        ''', (domain, limit))

        results = cursor.fetchall()
        conn.close()

        return [dict(row) for row in results]

    def get_current_resolution(self, domain: str, subdomain: str = '') -> List[str]:
        """Get the current IP addresses for a domain/subdomain."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
        SELECT ip_address FROM domain_resolution
        WHERE domain = ? AND subdomain = ? AND is_resolving = 1
        ORDER BY ip_address
        ''', (domain, subdomain))

        results = cursor.fetchall()
        conn.close()

        return [row['ip_address'] for row in results if row['ip_address']]

    def update_domain_resolution(self, domain: str, subdomain: str, current_ips: List[str], is_nxdomain: bool = False) -> Tuple[bool, List[str], List[str], bool]:
        """
        Update IP resolution for a domain/subdomain and detect changes.

        Args:
            domain: The domain name
            subdomain: The subdomain ('' for apex, 'www' for www)
            current_ips: List of current IP addresses
            is_nxdomain: True if domain doesn't exist (NXDOMAIN)

        Returns:
            Tuple containing:
                - Boolean indicating if resolution changed
                - List of added IP addresses
                - List of removed IP addresses
                - Boolean indicating if domain went from resolving to NXDOMAIN
        """
        current_ips = sorted(current_ips) if current_ips else []
        previous_ips = sorted(self.get_current_resolution(domain, subdomain))

        # Check for NXDOMAIN state change
        was_resolving = bool(previous_ips)
        became_nxdomain = was_resolving and is_nxdomain

        # Early exit if no change and not NXDOMAIN
        if current_ips == previous_ips and not became_nxdomain:
            # Just update the last_checked timestamp
            self._update_resolution_last_checked(domain, subdomain, current_ips)
            return False, [], [], False

        # Get differences
        added = [ip for ip in current_ips if ip not in previous_ips]
        removed = [ip for ip in previous_ips if ip not in current_ips]

        # If there's no record yet (first time checking), don't report it as a change
        is_first_check = not previous_ips and not is_nxdomain

        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.datetime.utcnow().isoformat()

        try:
            # Mark all previous IPs as inactive
            if not is_first_check:
                cursor.execute('''
                UPDATE domain_resolution SET is_resolving = 0
                WHERE domain = ? AND subdomain = ?
                ''', (domain, subdomain))

            # Insert or update current IPs
            for ip in current_ips:
                cursor.execute('''
                INSERT INTO domain_resolution (domain, subdomain, ip_address, last_checked, is_resolving)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(domain, subdomain, ip_address)
                DO UPDATE SET last_checked = ?, is_resolving = 1
                ''', (domain, subdomain, ip, now, now))

            # Record history for changes (but not for first check)
            if not is_first_check:
                if became_nxdomain:
                    cursor.execute('''
                    INSERT INTO domain_resolution_history (domain, subdomain, event_type, ip_address, timestamp)
                    VALUES (?, ?, 'nxdomain', NULL, ?)
                    ''', (domain, subdomain, now))

                for ip in added:
                    cursor.execute('''
                    INSERT INTO domain_resolution_history (domain, subdomain, event_type, ip_address, timestamp)
                    VALUES (?, ?, 'add', ?, ?)
                    ''', (domain, subdomain, ip, now))

                for ip in removed:
                    cursor.execute('''
                    INSERT INTO domain_resolution_history (domain, subdomain, event_type, ip_address, timestamp)
                    VALUES (?, ?, 'remove', ?, ?)
                    ''', (domain, subdomain, ip, now))

            conn.commit()
        except Exception as e:
            logger.error(f"Database error updating resolution for {domain}/{subdomain}: {e}")
            conn.rollback()
            return False, [], [], False
        finally:
            conn.close()

        # Don't return changes for first check
        if is_first_check:
            return False, [], [], False
        else:
            return bool(added or removed or became_nxdomain), added, removed, became_nxdomain

    def _update_resolution_last_checked(self, domain: str, subdomain: str, ips: List[str]) -> None:
        """Update the last_checked timestamp for domain resolution."""
        conn = self._get_connection()
        cursor = conn.cursor()
        now = datetime.datetime.utcnow().isoformat()

        try:
            for ip in ips:
                cursor.execute('''
                UPDATE domain_resolution
                SET last_checked = ?
                WHERE domain = ? AND subdomain = ? AND ip_address = ?
                ''', (now, domain, subdomain, ip))

            conn.commit()
        except Exception as e:
            logger.error(f"Database error updating resolution last_checked for {domain}/{subdomain}: {e}")
            conn.rollback()
        finally:
            conn.close()

    def get_resolution_history(self, domain: str, subdomain: str = '', limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent resolution history for a domain/subdomain."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
        SELECT event_type, ip_address, timestamp
        FROM domain_resolution_history
        WHERE domain = ? AND subdomain = ?
        ORDER BY timestamp DESC
        LIMIT ?
        ''', (domain, subdomain, limit))

        results = cursor.fetchall()
        conn.close()

        return [dict(row) for row in results]
