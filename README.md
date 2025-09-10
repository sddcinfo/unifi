# UniFi DNS Management Tool

A comprehensive Python tool for managing DNS records in Ubiquiti UniFi Network controllers. Supports individual record operations and bulk verification/creation of DNS records including Host (A) records and Forward Domains (NS records).

## Features

- **DNS Record Management**: Create, read, update, and delete DNS records via UniFi Network API
- **Multiple Record Types**: Support for A (host), NS (forward domain), CNAME, and AAAA records
- **DNS Record Verification**: Verify expected DNS records exist and have correct IP addresses
- **Bulk Operations**: Create missing DNS records in bulk
- **API Key Authentication**: Secure authentication using UniFi API keys (no more rate limiting!)
- **Configuration File Support**: Store settings in configuration files for easy deployment
- **Multiple UniFi Controller Support**: Works with UDM, UDM Pro, and traditional controllers
- **Unified Interface**: Single script handles all DNS management tasks

## Prerequisites

- Python 3.6+
- `requests` library (`pip install requests`)
- UniFi Network Controller with API key access
- Network access to your UniFi controller

## Quick Start

### 1. Generate Configuration File

```bash
python3 unifi-dns.py --generate-config
```

### 2. Edit Configuration

Copy `config.ini.example` to `config.ini` and update with your values:

```ini
[unifi]
hostname = 192.168.1.1
api_key = YOUR_API_KEY_HERE
site = default

[dns_records]
# Format: IP = hostname,alias,record_type (record_type optional, defaults to A)
192.168.1.10 = server.example.com,server,A
192.168.1.20 = nas.example.com,nas
```

### 3. Run Verification

```bash
python3 unifi-dns.py verify
```

### 4. Create Missing Records

```bash
python3 unifi-dns.py verify --create-missing
```

## Forward Domains (NS Records)

Forward domains allow you to delegate DNS queries for specific domains to another DNS server. This is useful for:

- **Internal domains**: Delegate `internal.company.com` to your internal DNS server
- **Lab environments**: Delegate `lab.local` to a lab DNS server  
- **Subdomain delegation**: Forward specific subdomains to other DNS servers

### Example Forward Domain Setup

```ini
[dns_records]
# Delegate all queries for "lab.local" to DNS server at 192.168.10.2
192.168.10.2 = lab.local,lab-dns,NS

# Delegate "internal.company.com" to internal DNS at 10.1.1.1
10.1.1.1 = internal.company.com,internal-dns,NS
```

When a client queries `server.lab.local`, the UniFi controller will:
1. See it has an NS record for `lab.local` pointing to `192.168.10.2`
2. Forward the query to the DNS server at `192.168.10.2`
3. Return the response from that server

## Getting Your UniFi API Key

### Method 1: UniFi Network Application (Recommended)
1. Log into your UniFi Network Application
2. Go to **Settings** → **System** → **API**
3. Click **Create New API Token**
4. Give it a name and copy the generated key

### Method 2: UniFi OS Console
1. Access your UDM/controller web interface
2. Navigate to **System Settings** → **Admins & Users**
3. Create or edit a user account
4. Enable **API Access** and generate an API key

## Configuration File

The configuration file uses INI format with three main sections:

### `[unifi]` Section
```ini
[unifi]
hostname = 192.168.1.1          # UniFi controller IP/hostname
api_key = YOUR_API_KEY_HERE     # API key from UniFi controller
site = default                  # Site name (usually 'default')
port = 443                      # Controller port (443 for UDM, 8443 for traditional)
is_udm = true                   # Set to true for UDM/UniFi OS controllers
```

### `[dns_records]` Section
```ini
[dns_records]
# Format: IP_ADDRESS = hostname,alias,record_type
# record_type is optional and defaults to 'A'

# Host (A) records - direct IP resolution
192.168.1.10 = server.example.com,server,A
192.168.1.20 = nas.example.com,nas

# Forward domain (NS) records - delegate DNS queries to another server
10.1.1.1 = internal.example.com,internal-dns,NS

# Ad-blocking records
10.0.0.1 = tracker.example.com,tracker-block,A
```

**Record Types Supported:**
- **A**: Host record (default) - maps hostname to IPv4 address
- **NS**: Name Server (forward domain) - delegates DNS queries to another DNS server
- **CNAME**: Alias record (if supported by UniFi)
- **AAAA**: IPv6 host record (if supported by UniFi)

### `[verification]` Section
```ini
[verification]
skip_hostnames = trace.svc,cloudsync.cs     # Hostnames to skip when checking for extra records
show_extra_records = true                   # Show records that exist but aren't expected
colored_output = true                       # Enable colored output (future feature)
```

## Configuration File Locations

The script looks for configuration files in this order:
1. File specified with `--config` parameter
2. `config.ini` in the script directory
3. `config.ini.example` in the script directory (for testing)
4. `config.ini` in the current working directory
5. `~/.unifi-dns.ini` in user's home directory

## Usage Examples

### Basic Verification
```bash
# Uses config.ini file
python3 unifi-dns.py verify

# Use specific config file
python3 unifi-dns.py --config /path/to/config.ini verify

# Override config with CLI parameters
python3 unifi-dns.py --api-key YOUR_KEY --host 192.168.1.1 verify
```

### DNS Record Management
```bash
# List all DNS records
python3 unifi-dns.py list

# Add a new A record
python3 unifi-dns.py add --hostname test.local --ip 192.168.1.100

# Add a forward domain (NS) record
python3 unifi-dns.py add --hostname internal.local --ip 192.168.1.1 --record-type NS

# Update existing record
python3 unifi-dns.py update --id RECORD_ID --ip 192.168.1.101

# Delete a record
python3 unifi-dns.py delete --id RECORD_ID
```

### Bulk Operations
```bash
# Verify all expected records and create missing ones
python3 unifi-dns.py verify --create-missing

# Verify only (no changes)
python3 unifi-dns.py verify
```

## Command Line Options

### Global Options
```
--config, -c          Specify configuration file path
--host                UniFi controller hostname/IP
--api-key             UniFi API key (recommended)
--username            Username for login (if no API key)
--password            Password for login (if no API key)  
--site                UniFi site name (default: default)
--port                Controller port (default: 443)
--udm                 Use UDM/UniFi OS mode (default: true)
--generate-config     Generate example configuration file
```

### Commands
```
list                  List all DNS records
verify                Verify expected DNS records from config
  --create-missing    Create missing DNS records during verification
add                   Add new DNS record
  --hostname          Hostname for the record (required)
  --ip                IP address or DNS server for the record (required)
  --record-type       Record type: A (default), NS, CNAME, AAAA
update                Update existing DNS record  
  --id                Record ID to update (required)
  --hostname          New hostname
  --ip                New IP address
delete                Delete DNS record
  --id                Record ID to delete (required)
```

## Troubleshooting

### Common Issues

**Authentication Errors**
- Verify your API key is correct and has sufficient permissions
- Ensure your UniFi controller allows API access
- Check if your user account has the necessary privileges

**Rate Limiting**
- Use API keys instead of username/password authentication
- API keys don't have the same rate limiting as username/password login

**Connection Errors**
- Verify the controller hostname/IP is correct
- Check if you're using the right port (443 for UDM, 8443 for traditional controllers)
- Ensure SSL certificates are accepted (script disables SSL verification for self-signed certs)

**Record Creation Failures**
- Verify the hostname format is correct
- Ensure IP addresses are valid
- Check for duplicate records

## Security Considerations

- Store API keys securely and never commit them to version control
- Use separate API keys for different environments (dev/prod)
- Consider using environment variables for sensitive data
- The script disables SSL certificate verification for self-signed certificates

## API Endpoints Used

The scripts interact with these UniFi Network API endpoints:
- `GET /proxy/network/v2/api/site/{site}/static-dns` - List DNS records
- `POST /proxy/network/v2/api/site/{site}/static-dns` - Create DNS record
- `PUT /proxy/network/v2/api/site/{site}/static-dns/{id}` - Update DNS record
- `DELETE /proxy/network/v2/api/site/{site}/static-dns/{id}` - Delete DNS record

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is provided as-is for educational and administrative purposes. Use at your own risk.

## Version History

- **v2.0** - Added configuration file support, API key authentication
- **v1.0** - Initial release with basic DNS management

## Support

- Check UniFi Network documentation for API details
- Verify your controller firmware supports the required API endpoints
- Test in a non-production environment first