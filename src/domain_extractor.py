#!/usr/bin/env python3
import re
import sys
import os

def extract_domain(text):
    """
    Extract the domain name from text that contains a URL or domain.
    Only processes strings that actually look like URLs or domains.
    Converts https://www.example.com/ to example.com
    """
    if not text or not isinstance(text, str):
        return ""

    text = text.lower()  # todo

    # URL regex pattern - matches common URL formats
    url_pattern = re.compile(r'(https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(:\d+)?(/[^?\s]*)?(\?[^\s#]*)?(\#[^\s]*)?')

    # Domain-only regex pattern - matches domain names without protocol
    domain_pattern = re.compile(r'^([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)$')

    # Try URL pattern first
    url_match = url_pattern.search(text)
    if url_match:
        domain = url_match.group(2)  # This is the domain part from the URL pattern
        # Remove www. prefix if present
        domain = re.sub(r'^www\.', '', domain)
        return domain

    # Try domain-only pattern
    domain_match = domain_pattern.match(text)
    if domain_match:
        domain = domain_match.group(1)
        # Remove www. prefix if present
        domain = re.sub(r'^www\.', '', domain)
        return domain

    return ""

def process_text_file(file_path):
    """Process a text file with one potential URL or domain per line."""
    domains = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                text = line.strip()
                if text:
                    domain = extract_domain(text)
                    if domain:
                        domains.append(domain)
    except Exception as e:
        print(f"Error processing text file: {e}", file=sys.stderr)

    return domains

def process_delimited_file(file_path):
    """Process a file with comma or tab separated values and extract domains."""
    domains = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                # Split by common delimiters (comma and tab)
                # This also handles quoted values with regex
                items = re.findall(r'(?:[^\s,"\']|"[^"]*"|\'[^\']*\')+', line)

                for item in items:
                    # Remove surrounding quotes if present
                    cleaned_item = item.strip('\'"')

                    # Only process if it might be a domain or URL
                    domain = extract_domain(cleaned_item)
                    if domain:
                        domains.append(domain)
    except Exception as e:
        print(f"Error processing delimited file: {e}", file=sys.stderr)

    return domains

def save_domains(domains, output_file):
    """Save extracted domains to a file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            for domain in domains:
                file.write(f"{domain}\n")
        print(f"Successfully saved {len(domains)} domains to {output_file}")
    except Exception as e:
        print(f"Error saving domains: {e}", file=sys.stderr)

def main():
    if len(sys.argv) < 2:
        print("Usage: python domain_extractor.py <input_file> [output_file]")
        print("       The script processes text files with URLs and delimited files (CSV, TSV, etc.)")
        sys.exit(1)

    input_file = sys.argv[1]

    # Determine output file name
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    else:
        base_name = os.path.splitext(input_file)[0]
        output_file = f"{base_name}_domains.txt"

    # Check if input file exists
    if not os.path.isfile(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        sys.exit(1)

    # Process file based on extension
    file_ext = os.path.splitext(input_file)[1].lower()

    if file_ext in ['.csv', '.tsv']:
        domains = process_delimited_file(input_file)
    else:
        # Try both methods for text files, as they might contain delimited values
        domains_text = process_text_file(input_file)
        domains_delim = process_delimited_file(input_file)

        # Combine results from both methods
        domains = domains_text + domains_delim

    # Remove duplicates and sort
    unique_domains = sorted(set(domains))

    print(f"Found {len(unique_domains)} unique domains.")

    # Save to output file
    save_domains(unique_domains, output_file)

if __name__ == "__main__":
    main()
