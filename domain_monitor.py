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
from src.email_sender import send_alert_email, send_test_email, print_alert_report, save_json_report
from src.database import DatabaseManager

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
def check_domains(domain, file, config, alert_days, quiet, send_email, delay, db_path, no_cache):
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
        domains_to_check.append(domain)

    # Add domains from file if specified
    if file:
        try:
            with open(file, 'r') as f:
                file_domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                domains_to_check.extend(file_domains)
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

    # Check all domains
    results = []
    domains_to_alert = []
    for domain in domains_to_check:
        domain_info = check_domain(domain, cfg, force_check=no_cache)
        results.append(domain_info)

        # Check if domain needs alert
        needs_alert_flag, reason = needs_alert(domain_info, cfg)
        if needs_alert_flag:
            domains_to_alert.append((domain_info, reason))

        if not quiet:
            if needs_alert_flag:
                logger.warning(f"{domain_info} - ALERT: {reason}")
            else:
                logger.info(str(domain_info))

    # Summary
    if not quiet:
        logger.info(f"Domain check complete: {len(results)} checked, {len(domains_to_alert)} need attention")

    # Send email alerts or print report if needed
    if domains_to_alert:
        if cfg.is_email_enabled():
            send_alert_email(cfg, domains_to_alert)
        else:
            # When email is disabled (--no-email), print report to stdout
            print_alert_report(domains_to_alert)
    
    # Always save JSON report if web display is enabled
    save_json_report(cfg, domains_to_alert)

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
