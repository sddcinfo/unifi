#!/usr/bin/env python3
"""
UniFi DNS Management Tool
A comprehensive tool for managing DNS records in Ubiquiti UniFi Network controllers.
Supports both individual record operations and bulk verification/creation.
"""

import requests
import json
import argparse
import urllib3
import configparser
import os
import sys
import subprocess
from typing import Dict, List, Tuple

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class UnifiDNSManager:
    def __init__(self, host: str, site: str = 'default', username: str = None, password: str = None, api_key: str = None, port: int = 443, is_udm: bool = True):
        # UDM/UnifiOS uses port 443, standard controller uses 8443
        if is_udm or port == 443:
            self.base_url = f"https://{host}"
            self.is_udm = True
        else:
            self.base_url = f"https://{host}:{port}"
            self.is_udm = False
        self.site = site
        self.username = username
        self.password = password
        self.api_key = api_key
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Set API key header if provided
        if self.api_key:
            self.session.headers['X-API-KEY'] = self.api_key
            self.logged_in = True  # No need to login with API key
        else:
            self.logged_in = False
        
    def login(self) -> bool:
        """Login to Unifi Controller (only needed if not using API key)"""
        if self.api_key:
            return True  # Already authenticated with API key
            
        if not self.username or not self.password:
            print("Username and password required for non-API key authentication")
            return False
            
        login_url = f"{self.base_url}/api/auth/login"
        payload = {
            "username": self.username,
            "password": self.password,
            "remember": True
        }
        
        try:
            response = self.session.post(login_url, json=payload)
            if response.status_code == 200:
                self.logged_in = True
                print(f"Successfully logged in to Unifi Controller")
                return True
            else:
                print(f"Login failed with status code: {response.status_code}")
                print(f"Response: {response.text[:200]}")
        except Exception as e:
            print(f"Login failed: {e}")
        return False
    
    def logout(self):
        """Logout from Unifi Controller"""
        if self.logged_in and not self.api_key:
            self.session.post(f"{self.base_url}/api/logout")
            self.logged_in = False
    
    def get_dns_records(self) -> List[Dict]:
        """Get all static DNS records"""
        if not self.logged_in:
            return []
        
        # Use the correct API endpoint for DNS records
        if self.is_udm:
            url = f"{self.base_url}/proxy/network/v2/api/site/{self.site}/static-dns"
        else:
            url = f"{self.base_url}/v2/api/site/{self.site}/static-dns"
            
        response = self.session.get(url)
        
        if response.status_code == 200:
            data = response.json()
            # Format DNS records for consistency
            dns_records = []
            for item in data:
                dns_records.append({
                    'id': item.get('_id'),
                    'hostname': item.get('key'),
                    'ip': item.get('value'),
                    'record_type': item.get('record_type'),
                    'enabled': item.get('enabled'),
                    'ttl': item.get('ttl'),
                    'port': item.get('port'),
                    'priority': item.get('priority'),
                    'weight': item.get('weight')
                })
            return dns_records
        else:
            print(f"Failed to get DNS records: {response.status_code}")
            print(f"Response: {response.text[:200]}")
        return []
    
    def get_dns_records_dict(self) -> Dict[str, str]:
        """Get DNS records as hostname -> IP mapping for A records only"""
        records = self.get_dns_records()
        return {record['hostname']: record['ip'] for record in records 
                if record['record_type'] == 'A' and record['enabled']}
    
    def get_all_dns_records_dict(self) -> Dict[Tuple[str, str], str]:
        """Get all DNS records as (hostname, record_type) -> IP mapping"""
        records = self.get_dns_records()
        return {(record['hostname'], record['record_type']): record['ip'] 
                for record in records if record['enabled']}
    
    def add_dns_record(self, hostname: str, ip: str, record_type: str = "A") -> bool:
        """Add a static DNS record"""
        if not self.logged_in:
            return False
        
        if self.is_udm:
            url = f"{self.base_url}/proxy/network/v2/api/site/{self.site}/static-dns"
        else:
            url = f"{self.base_url}/v2/api/site/{self.site}/static-dns"
            
        payload = {
            "enabled": True,
            "key": hostname,
            "record_type": record_type,
            "value": ip,
            "ttl": 0,
            "port": 0,
            "priority": 0,
            "weight": 0
        }
        
        response = self.session.post(url, json=payload)
        if response.status_code == 200:
            return True
        else:
            print(f"Failed to add DNS record: {response.status_code}")
            print(f"Response: {response.text[:200]}")
        return False
    
    def update_dns_record(self, record_id: str, hostname: str = None, ip: str = None) -> bool:
        """Update an existing DNS record"""
        if not self.logged_in:
            return False
        
        if self.is_udm:
            url = f"{self.base_url}/proxy/network/v2/api/site/{self.site}/static-dns/{record_id}"
        else:
            url = f"{self.base_url}/v2/api/site/{self.site}/static-dns/{record_id}"
            
        payload = {}
        
        if hostname:
            payload['key'] = hostname
        if ip:
            payload['value'] = ip
            
        response = self.session.put(url, json=payload)
        if response.status_code == 200:
            return True
        else:
            print(f"Failed to update DNS record: {response.status_code}")
            print(f"Response: {response.text[:200]}")
        return False
    
    def delete_dns_record(self, record_id: str) -> bool:
        """Delete a DNS record"""
        if not self.logged_in:
            return False
        
        if self.is_udm:
            url = f"{self.base_url}/proxy/network/v2/api/site/{self.site}/static-dns/{record_id}"
        else:
            url = f"{self.base_url}/v2/api/site/{self.site}/static-dns/{record_id}"
            
        response = self.session.delete(url)
        if response.status_code == 200:
            return True
        else:
            print(f"Failed to delete DNS record: {response.status_code}")
            print(f"Response: {response.text[:200]}")
        return False

def load_config(config_file: str = None) -> configparser.ConfigParser:
    """Load configuration from file"""
    config = configparser.ConfigParser()
    
    # Try to find config file in order of preference
    config_paths = []
    if config_file:
        config_paths.append(config_file)
    
    # Look for config.ini in same directory as script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_paths.extend([
        os.path.join(script_dir, 'config.ini'),
        os.path.join(script_dir, 'config.ini.example'),
        os.path.join(os.getcwd(), 'config.ini'),
        os.path.expanduser('~/.unifi-dns.ini')
    ])
    
    for path in config_paths:
        if os.path.exists(path):
            print(f"Loading configuration from: {path}")
            config.read(path)
            return config
    
    print("Warning: No configuration file found. Using CLI arguments only.")
    return config

def load_expected_records_from_config(config: configparser.ConfigParser) -> List[Tuple[str, str, str, str]]:
    """Load expected DNS records from configuration file"""
    records = []
    
    if 'dns_records' in config:
        for ip, hostname_alias_type in config['dns_records'].items():
            parts = hostname_alias_type.split(',')
            
            if len(parts) >= 2:
                hostname = parts[0].strip()
                alias = parts[1].strip()
                record_type = parts[2].strip() if len(parts) >= 3 else 'A'
            else:
                hostname = parts[0].strip()
                alias = hostname.split('.')[0]  # Use first part of hostname as alias
                record_type = 'A'
            
            records.append((ip, hostname, alias, record_type))
    
    return records

def verify_records(manager: UnifiDNSManager, expected_records: List[Tuple[str, str, str, str]], config: configparser.ConfigParser) -> Tuple[int, int, int]:
    """Verify DNS records against expected values. Returns (correct, missing, incorrect)"""
    print("Verifying DNS Records...")
    print("=" * 80)
    
    # Get current DNS records (all types)
    current_records = manager.get_all_dns_records_dict()
    
    # Track statistics
    correct = 0
    missing = 0
    incorrect = 0
    
    for expected_ip, hostname, alias, record_type in expected_records:
        record_key = (hostname, record_type)
        if record_key in current_records:
            current_ip = current_records[record_key]
            if current_ip == expected_ip:
                print(f"✓ CORRECT: {hostname} ({record_type}) -> {current_ip}")
                correct += 1
            else:
                print(f"✗ INCORRECT: {hostname} ({record_type}) -> {current_ip} (expected: {expected_ip})")
                incorrect += 1
        else:
            print(f"✗ MISSING: {hostname} ({record_type}) (expected: {expected_ip})")
            missing += 1
    
    # Check for extra records (records that exist but aren't in our expected list)
    expected_hostnames = {hostname for _, hostname, _, _ in expected_records}
    extra_records = []
    
    # Get skip list from config or use defaults
    skip_hostnames = []
    if config and 'verification' in config and 'skip_hostnames' in config['verification']:
        skip_hostnames = [s.strip() for s in config['verification']['skip_hostnames'].split(',')]
    else:
        skip_hostnames = []  # No default skips - let user configure as needed
    
    show_extra = True
    if config and 'verification' in config:
        show_extra = config.getboolean('verification', 'show_extra_records', fallback=True)
    
    for (hostname, record_type), ip in current_records.items():
        if hostname not in expected_hostnames:
            if not any(skip in hostname.lower() for skip in skip_hostnames):
                extra_records.append((hostname, record_type, ip))
    
    print("\n" + "=" * 80)
    print("SUMMARY:")
    print(f"  ✓ Correct records: {correct}")
    print(f"  ✗ Missing records: {missing}")
    print(f"  ✗ Incorrect records: {incorrect}")
    
    if extra_records and show_extra:
        print(f"  ? Extra records: {len(extra_records)}")
        print("\nExtra records found:")
        for hostname, record_type, ip in extra_records:
            print(f"    {hostname} ({record_type}) -> {ip}")
    
    print(f"\nTotal expected records: {len(expected_records)}")
    print(f"Success rate: {(correct / len(expected_records)) * 100:.1f}%")
    
    return correct, missing, incorrect

def create_missing_records(manager: UnifiDNSManager, expected_records: List[Tuple[str, str, str, str]]) -> int:
    """Create missing DNS records. Returns number created."""
    print("\nCreating missing DNS records...")
    
    current_records = manager.get_all_dns_records_dict()
    created = 0
    
    for expected_ip, hostname, alias, record_type in expected_records:
        record_key = (hostname, record_type)
        if record_key not in current_records:
            if manager.add_dns_record(hostname, expected_ip, record_type):
                print(f"✓ Created: {hostname} ({record_type}) -> {expected_ip}")
                created += 1
            else:
                print(f"✗ Failed to create: {hostname} ({record_type}) -> {expected_ip}")
    
    print(f"\nCreated {created} new DNS records")
    return created

def generate_config_file():
    """Generate example configuration file"""
    config_content = """# UniFi DNS Management Configuration
# Copy this to config.ini and update with your values

[unifi]
hostname = 192.168.1.1
api_key = YOUR_API_KEY_HERE
site = default
port = 443
is_udm = true

[dns_records]
# Format: IP_ADDRESS = hostname,alias,record_type
# record_type is optional and defaults to 'A'
# Common types: A (host record), NS (forward domain), CNAME, AAAA

# Host (A) records
192.168.1.10 = server.example.com,server,A
192.168.1.20 = nas.example.com,nas

# Forward domain (NS) records - delegate DNS queries to another server
10.1.1.1 = internal.example.com,internal-dns,NS

# Ad-blocking records
10.0.0.1 = tracker.example.com,tracker-block

[verification]
# Skip hostnames that should be ignored during extra record detection
skip_hostnames = 
show_extra_records = true
"""
    with open('config.ini.example', 'w') as f:
        f.write(config_content)
    print("Generated config.ini.example - copy to config.ini and update with your values")

def main():
    parser = argparse.ArgumentParser(
        description='UniFi DNS Management Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all DNS records
  python3 unifi-dns.py list
  
  # Verify expected records from config
  python3 unifi-dns.py verify
  
  # Create missing records
  python3 unifi-dns.py verify --create-missing
  
  # Add single record
  python3 unifi-dns.py add --hostname test.local --ip 192.168.1.100
  
  # Generate config file
  python3 unifi-dns.py --generate-config
"""
    )
    
    # Global options
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--host', help='UniFi Controller hostname/IP')
    parser.add_argument('--api-key', help='UniFi API Key')
    parser.add_argument('--username', help='Username (if no API key)')
    parser.add_argument('--password', help='Password (if no API key)')
    parser.add_argument('--site', help='UniFi site name')
    parser.add_argument('--port', type=int, help='UniFi Controller port')
    parser.add_argument('--udm', action='store_true', help='Use UDM/UniFi OS mode')
    parser.add_argument('--generate-config', action='store_true', help='Generate example configuration file')
    
    subparsers = parser.add_subparsers(dest='action', help='Action to perform')
    
    # List records
    subparsers.add_parser('list', help='List all DNS records')
    
    # Verify records
    verify_parser = subparsers.add_parser('verify', help='Verify expected DNS records')
    verify_parser.add_argument('--create-missing', action='store_true', help='Create missing DNS records')
    
    # Add record
    add_parser = subparsers.add_parser('add', help='Add DNS record')
    add_parser.add_argument('--hostname', required=True, help='Hostname')
    add_parser.add_argument('--ip', required=True, help='IP address')
    add_parser.add_argument('--record-type', default='A', help='Record type (A, AAAA, CNAME, etc.)')
    
    # Update record
    update_parser = subparsers.add_parser('update', help='Update DNS record')
    update_parser.add_argument('--id', required=True, help='Record ID')
    update_parser.add_argument('--hostname', help='New hostname')
    update_parser.add_argument('--ip', help='New IP address')
    
    # Delete record
    delete_parser = subparsers.add_parser('delete', help='Delete DNS record')
    delete_parser.add_argument('--id', required=True, help='Record ID')
    
    args = parser.parse_args()
    
    # Generate config file and exit
    if args.generate_config:
        generate_config_file()
        return
    
    if not args.action:
        parser.print_help()
        return
    
    # Load configuration
    config = load_config(args.config)
    
    # Get settings from config file first, then CLI args, then defaults
    host = args.host or (config.get('unifi', 'hostname', fallback=None) if config else None) or '192.168.1.1'
    api_key = args.api_key or (config.get('unifi', 'api_key', fallback=None) if config else None)
    username = args.username or (config.get('unifi', 'username', fallback=None) if config else None)
    password = args.password or (config.get('unifi', 'password', fallback=None) if config else None)
    site = args.site or (config.get('unifi', 'site', fallback=None) if config else None) or 'default'
    port = args.port or (config.getint('unifi', 'port', fallback=None) if config else None) or 443
    is_udm = args.udm or (config.getboolean('unifi', 'is_udm', fallback=None) if config else None) or True
    
    # Check if we have required settings
    if not api_key and (not username or not password):
        print("Error: API key or username/password required. Set in config file or use CLI options")
        print("Use --generate-config to create an example configuration file")
        sys.exit(1)
    
    # Initialize manager
    manager = UnifiDNSManager(
        host=host,
        api_key=api_key,
        username=username,
        password=password,
        site=site,
        port=port,
        is_udm=is_udm
    )
    
    # Login
    if not manager.login():
        print("Failed to login to Unifi Controller")
        return
    
    try:
        if args.action == 'list':
            records = manager.get_dns_records()
            if records:
                print(f"\nDNS Records ({len(records)} total):")
                print("-" * 80)
                for record in records:
                    print(f"ID: {record['id']}")
                    print(f"  Hostname: {record['hostname']}")
                    print(f"  IP: {record['ip']}")
                    print(f"  Type: {record['record_type']}")
                    print(f"  Enabled: {record['enabled']}")
                    print(f"  TTL: {record['ttl']}")
                    print("-" * 80)
            else:
                print("No DNS records found")
                
        elif args.action == 'verify':
            # Load expected records from config or use fallback
            if config and config.has_section('dns_records'):
                expected_records = load_expected_records_from_config(config)
                if not expected_records:
                    print("Warning: No DNS records found in configuration file")
                    return
            else:
                print("Error: No DNS records configuration found. Use --generate-config to create one.")
                return
            
            print(f"Loaded {len(expected_records)} expected DNS records")
            
            # Verify records
            correct, missing, incorrect = verify_records(manager, expected_records, config)
            
            # Create missing records if requested
            if args.create_missing and missing > 0:
                created = create_missing_records(manager, expected_records)
                if created > 0:
                    print(f"\nRe-running verification after creating {created} records...")
                    verify_records(manager, expected_records, config)
                
        elif args.action == 'add':
            if manager.add_dns_record(args.hostname, args.ip, getattr(args, 'record_type', 'A')):
                print(f"Added DNS record: {args.hostname} -> {args.ip}")
            else:
                print("Failed to add DNS record")
                
        elif args.action == 'update':
            if manager.update_dns_record(args.id, args.hostname, args.ip):
                print("DNS record updated")
            else:
                print("Failed to update DNS record")
                
        elif args.action == 'delete':
            if manager.delete_dns_record(args.id):
                print("DNS record deleted")
            else:
                print("Failed to delete DNS record")
                
    finally:
        manager.logout()

if __name__ == "__main__":
    main()