#!/usr/bin/env python3
"""
Domain Monitor - CLI tool to check domain expiration and status.

This script can monitor domains for expiration dates, status changes, and nameserver
information. It can process a single domain or a list from a file and send email
alerts for domains nearing expiration or with concerning statuses. It also tracks
nameserver changes over time and alerts when changes are detected.
"""

import sys
import logging
import click

from src.config import Config, DEFAULT_CONFIG_PATH
from src.domain_checker import check_domain, needs_alert
from src.email_sender import send_alert_email, send_test_email, print_alert_report
from src.database import DatabaseManager
from src.domain_extractor import extract_domain

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('domain_monitor')


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """Domain Monitor - Check domain expiration dates and status."""
    pass


@cli.command('check')
@click.option('--domain', '-d', help='Single domain to check')
@click.option('--file', '-f', help='File containing list of domains (overrides domains_file in config)')
@click.option('--config', '-c', default=DEFAULT_CONFIG_PATH, help='Path to config file')
@click.option('--alert-days', '-a', type=int, help='Days threshold for expiration alerts')
@click.option('--quiet', '-q', is_flag=True, help='Suppress output except for errors')
@click.option('--send-email/--no-email', default=None, help='Override config email setting')
@click.option('--delay', type=float, help='Delay between WHOIS queries (seconds)')
@click.option('--db-path', help='Override database path')
@click.option('--no-cache', is_flag=True, help='Force WHOIS lookup even if cached data is available')
@click.option('--limit', '-l', type=int, help='Limit number of domains to refresh (cached data doesn\'t count)')
def check_domains(domain, file, config, alert_days, quiet, send_email, delay, db_path, no_cache, limit):
    """Check domains for expiration dates and status."""
    # Load configuration
    cfg = Config(config)

    # Override alert days if specified
    if alert_days is not None:
        cfg.data['general']['alert_days'] = alert_days

    # Override email sending if specified
    if send_email is not None:
        cfg.data['email']['enabled'] = send_email

    # Override query delay if specified
    if delay is not None:
        cfg.data['general']['query_delay'] = delay

    # Override database path if specified
    if db_path is not None:
        cfg.data['general']['db_path'] = db_path
        # Reinitialize database with new path
        cfg.db = DatabaseManager(db_path)

    domains_to_check = []

    # Add single domain if specified
    if domain:
        extracted_domain = extract_domain(domain)
        if extracted_domain:
            domains_to_check.append(extracted_domain)
        else:
            logger.error(f"Could not extract domain from '{domain}'")
            return 1

    # Add domains from file if specified
    if file:
        try:
            with open(file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        extracted_domain = extract_domain(line)
                        if extracted_domain:
                            domains_to_check.append(extracted_domain)
                        else:
                            logger.warning(f"Could not extract domain from '{line}' in {file}")
        except Exception as e:
            logger.error(f"Failed to read domains file {file}: {e}")

    # If no domains specified via CLI, use config's domains_file
    if not domains_to_check:
        domains_to_check = cfg.get_domains()

    if not domains_to_check:
        logger.error("No domains found to check. Either:")
        logger.error("  1. Specify a domain with --domain")
        logger.error("  2. Specify a domains file with --file")
        logger.error("  3. Set domains_file in your config.yaml and ensure the file exists")
        return 1

    logger.info(f"Checking {len(domains_to_check)} domains...")

    def process_domain(domain: str) -> None:
        """Process a single domain and update results/alerts."""
        domain_info = check_domain(domain, cfg, should_refresh=True)
        if not domain_info:
            return
            
        results.append(domain_info)
        
        needs_alert_flag, reason = needs_alert(domain_info, cfg)
        if needs_alert_flag:
            domains_to_alert.append((domain_info, reason))
        
        if not quiet:
            if needs_alert_flag:
                logger.warning(f"{domain_info} - ALERT: {reason}")
            else:
                logger.info(str(domain_info))

    # Check all domains
    results = []
    domains_to_alert = []
    refreshed_count = 0
    cache_hours = cfg.data['general']['cache_hours']

    for domain in domains_to_check:
        # Determine if domain needs refresh (single DB check)
        needs_refresh = cfg.db.should_check_domain(domain, cache_hours)

        # Skip domains with fresh cache (already alerted when refreshed)
        if not no_cache and not needs_refresh:
            continue

        # Skip domains beyond limit (will be checked in future runs)
        if limit is not None and not no_cache and refreshed_count >= limit:
            continue

        # Process and refresh domain
        process_domain(domain)
        refreshed_count += 1

    # Summary
    if not quiet:
        summary = f"Domain check complete: {len(results)} checked"
        if limit is not None and not no_cache:
            summary += f", {refreshed_count} refreshed (limit: {limit})"
        summary += f", {len(domains_to_alert)} need attention"
        logger.info(summary)

    # Send email alerts or print report if needed
    if domains_to_alert:
        if cfg.is_email_enabled():
            send_alert_email(cfg, domains_to_alert)
        else:
            # When email is disabled (--no-email), print report to stdout
            print_alert_report(domains_to_alert)

    # Return non-zero exit code if any domains need attention (useful for cron jobs)
    return 0 if not domains_to_alert else 1


@cli.command('test-email')
@click.option('--config', '-c', default=DEFAULT_CONFIG_PATH, help='Path to config file')
@click.option('--recipient', '-r', help='Override recipient email address')
def test_email(config, recipient):
    """Send a test email to verify SMTP configuration."""
    # Load configuration
    cfg = Config(config)

    success = send_test_email(cfg, recipient)
    return 0 if success else 1


@cli.command('ns-history')
@click.argument('domain', required=True)
@click.option('--config', '-c', default=DEFAULT_CONFIG_PATH, help='Path to config file')
@click.option('--db-path', help='Override database path')
@click.option('--limit', '-l', type=int, default=20, help='Maximum number of history entries to show')
def nameserver_history(domain, config, db_path, limit):
    """View nameserver history for a specific domain."""
    # Load configuration
    cfg = Config(config)

    # Override database path if specified
    if db_path is not None:
        cfg.data['general']['db_path'] = db_path
        # Reinitialize database with new path
        cfg.db = DatabaseManager(db_path)

    # Check if domain exists in database
    current_ns = cfg.db.get_current_nameservers(domain)
    if not current_ns:
        logger.warning(f"No history found for domain: {domain}")
        return 1

    # Get history
    history = cfg.db.get_nameserver_history(domain, limit)

    # Print current nameservers
    logger.info(f"Current nameservers for {domain}:")
    for ns in current_ns:
        logger.info(f"  - {ns}")

    # Print history
    if history:
        logger.info(f"\nNameserver history (last {min(limit, len(history))} events):")
        for entry in history:
            event_type = "Added" if entry['event_type'] == 'add' else "Removed"
            timestamp = entry['timestamp']
            ns = entry['nameserver']
            logger.info(f"  {timestamp} | {event_type}: {ns}")
    else:
        logger.info(f"\nNo nameserver changes detected for {domain}")

    return 0


if __name__ == '__main__':
    sys.exit(cli())
