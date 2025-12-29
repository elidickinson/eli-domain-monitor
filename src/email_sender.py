"""Email notification functionality."""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from typing import List, Tuple
from .config import Config
from .domain_info import DomainInfo

logger = logging.getLogger('domain_monitor.email')


def generate_alert_report(domains_to_alert: List[Tuple[DomainInfo, str]]) -> str:
    """Generate alert report text for domains that need attention. Used for email or print() """
    if not domains_to_alert:
        return "No domains need attention at this time."

    body = "The following domains need immediate attention:\n\n"
    for domain_info, reason in domains_to_alert:
        expiry_date_str = (
            domain_info.expiration_date.strftime('%Y-%m-%d')
            if domain_info.expiration_date else 'Unknown'
        )
        # Add full hyperlink for the domain
        body += f"• {domain_info.domain} (https://{domain_info.domain}/)\n"
        body += f"  - Alert reason: {reason}\n"
        body += f"  - Expiration date: {expiry_date_str}\n"
        body += f"  - Days until expiration: {domain_info.days_until_expiration}\n"

        # Display statuses one per line instead of comma-separated
        body += f"  - Status:\n"
        for status in domain_info.status:
            body += f"    * {status}\n"

        body += f"  - Nameservers: {', '.join(domain_info.nameservers)}\n"

        # Add nameserver change details if applicable
        if domain_info.nameservers_changed:
            body += f"  - NAMESERVER CHANGES DETECTED:\n"
            if domain_info.added_nameservers:
                body += f"    * Added: {', '.join(domain_info.added_nameservers)}\n"
            if domain_info.removed_nameservers:
                body += f"    * Removed: {', '.join(domain_info.removed_nameservers)}\n"

        body += "\n"

    return body


def print_alert_report(domains_to_alert: List[Tuple[DomainInfo, str]]):
    """Print alert report to stdout."""
    if not domains_to_alert:
        print("No domains need attention at this time.")
        return

    print(f"DOMAIN ALERT REPORT: {len(domains_to_alert)} domains need attention")
    print("=" * 60)
    print()
    print(generate_alert_report(domains_to_alert))


def send_alert_email(config: Config, domains_to_alert: List[Tuple[DomainInfo, str]]) -> bool:
    """Send alert email for domains that need attention."""
    if not config.is_email_enabled():
        logger.warning("Email alerts are not properly configured")
        return False

    if not domains_to_alert:
        return True  # Nothing to alert about

    email_config = config.data['email']

    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = email_config['from_address']
        msg['To'] = ', '.join(email_config['to_addresses'])
        msg['Subject'] = f"{email_config['subject_prefix']} Domain Alert: {len(domains_to_alert)} domains need attention"
        msg["Message-ID"] = make_msgid()
        msg["Date"] = formatdate(localtime=True)
        
        # Use the shared report generation function
        body = generate_alert_report(domains_to_alert)
        msg.attach(MIMEText(body, 'plain'))

        # Connect to SMTP server
        with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
            if email_config['username'] and email_config['password']:
                server.starttls()
                server.login(email_config['username'], email_config['password'])

            server.send_message(msg)

        logger.info(f"Alert email sent to {', '.join(email_config['to_addresses'])}")
        return True

    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")
        return False


def send_test_email(config: Config, recipient: str) -> bool:
    """Send a test email to verify SMTP configuration."""
    if not config.is_email_enabled():
        logger.error("Email is not properly configured. Check your config file.")
        return False

    try:
        email_config = config.data['email']

        # Create message
        msg = MIMEMultipart()
        msg['From'] = email_config['from_address']
        msg["Message-ID"] = make_msgid()
        msg["Date"] = formatdate(localtime=True)

        # Use provided recipient or default to config recipients
        if recipient:
            to_address = recipient
        else:
            to_address = ', '.join(email_config['to_addresses'])

        msg['To'] = to_address
        msg['Subject'] = f"{email_config['subject_prefix']} Test Email"

        # Create email body
        body = "This is a test email from Domain Monitor.\n\n"
        body += "If you're receiving this, your SMTP configuration is working correctly.\n\n"
        body += "Email settings used:\n"
        body += f"  - SMTP Server: {email_config['smtp_server']}\n"
        body += f"  - SMTP Port: {email_config['smtp_port']}\n"
        body += f"  - From: {email_config['from_address']}\n"
        body += f"  - To: {to_address}\n"
        body += f"  - TLS: Enabled\n"

        msg.attach(MIMEText(body, 'plain'))

        # Connect to SMTP server
        logger.info(f"Connecting to {email_config['smtp_server']}:{email_config['smtp_port']}...")
        with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
            if email_config['username'] and email_config['password']:
                logger.info("Starting TLS...")
                server.starttls()
                logger.info(f"Logging in as {email_config['username']}...")
                server.login(email_config['username'], email_config['password'])

            logger.info(f"Sending test email to {to_address}...")
            server.send_message(msg)

        logger.info(f"Test email sent successfully to {to_address}")
        return True

    except Exception as e:
        logger.error(f"Failed to send test email: {e}")
        return False
