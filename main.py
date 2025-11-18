#!/usr/bin/env python3
"""
Cisco Device Scanner
Scans Cisco routers and switches to retrieve interface information including
IP addresses and descriptions.
"""

import getpass
import re
import csv
from datetime import datetime
from typing import Dict, Optional, Any
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# Constants
UNASSIGNED_IP = 'unassigned'
HEADER_KEYWORD = 'Interface'
COLUMN_WIDTHS = {'interface': 20, 'ip': 15, 'status': 10, 'desc': 30}
DEFAULT_DEVICE_TYPE = 'cisco_ios'
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_SESSION_TIMEOUT = 60

# Pre-compiled regex patterns for better performance
INTERFACE_PATTERN = re.compile(r'(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)')
DESC_PATTERN = re.compile(r'\S+\s+\S+\s+\S+\s+(.*)')


def normalize_ip_address(ip_address: str) -> str:
    """Convert 'unassigned' IP address to 'N/A' for display purposes.

    Args:
        ip_address: The IP address string to normalize

    Returns:
        'N/A' if IP is unassigned, otherwise the original IP address
    """
    return 'N/A' if ip_address == UNASSIGNED_IP else ip_address


def get_device_info(enable_session_log: bool = False) -> Dict[str, Any]:
    """Prompt user for device connection information.

    Args:
        enable_session_log: Whether to enable session logging

    Returns:
        Dictionary containing device connection parameters
    """
    print("\n=== Cisco Device Scanner ===\n")
    ip_address = input("Enter device IP address: ").strip()
    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password: ")

    device_params = {
        'device_type': DEFAULT_DEVICE_TYPE,
        'host': ip_address,
        'username': username,
        'password': password,
        'timeout': DEFAULT_CONNECT_TIMEOUT,
        'session_timeout': DEFAULT_SESSION_TIMEOUT,
    }

    # Only add session log if enabled
    if enable_session_log:
        device_params['session_log'] = 'netmiko_session.log'

    return device_params


def parse_interface_info(show_ip_int_output: str, show_int_desc_output: str) -> Dict[str, Dict[str, str]]:
    """Parse interface information from command outputs.

    Args:
        show_ip_int_output: Output from 'show ip interface brief' command
        show_int_desc_output: Output from 'show interfaces description' command

    Returns:
        Dictionary mapping interface names to their properties (ip_address, status, protocol, description)
    """
    interfaces: Dict[str, Dict[str, str]] = {}

    # Parse IP addresses from 'show ip interface brief'
    for line in show_ip_int_output.split('\n'):
        # Skip header and empty lines
        if not line.strip() or HEADER_KEYWORD in line:
            continue

        # Match interface lines using pre-compiled pattern
        match = INTERFACE_PATTERN.match(line)
        if match:
            interface = match.group(1)
            ip_address = match.group(2)
            status = match.group(3)
            protocol = match.group(4)

            interfaces[interface] = {
                'ip_address': ip_address,
                'status': status,
                'protocol': protocol,
                'description': ''
            }

    # Parse descriptions from 'show interfaces description'
    for line in show_int_desc_output.split('\n'):
        # Skip header and empty lines
        if not line.strip() or HEADER_KEYWORD in line:
            continue

        # Match interface description lines
        parts = line.split()
        if len(parts) >= 2:
            interface = parts[0]
            # Find where description starts (after status fields) using pre-compiled pattern
            desc_match = DESC_PATTERN.search(line)
            description = desc_match.group(1).strip() if desc_match else ''

            if interface in interfaces:
                interfaces[interface]['description'] = description

    return interfaces


def display_results(interfaces: Dict[str, Dict[str, str]], device_ip: str) -> None:
    """Display formatted interface information.

    Args:
        interfaces: Dictionary of interface information
        device_ip: IP address of the device
    """
    separator = '=' * 80
    print(f"\n{separator}")
    print(f"Interface Report for Device: {device_ip}")
    print(f"{separator}\n")

    if not interfaces:
        print("No interfaces found or device returned no data.")
        return

    # Extract column widths from constants
    col_int = COLUMN_WIDTHS['interface']
    col_ip = COLUMN_WIDTHS['ip']
    col_status = COLUMN_WIDTHS['status']
    col_desc = COLUMN_WIDTHS['desc']

    # Build header
    header = f"{'Interface':<{col_int}} {'IP Address':<{col_ip}} {'Status':<{col_status}} {'Description':<{col_desc}}"
    print(header)
    print('-' * 80)

    # Sort once and iterate
    sorted_interfaces = sorted(interfaces.items())
    for interface, info in sorted_interfaces:
        ip_addr = normalize_ip_address(info['ip_address'])
        status = f"{info['status']}/{info['protocol']}"
        # Simplified description truncation
        description = info['description'][:28] + '..' if len(info['description']) > 30 else info['description']

        print(f"{interface:<{col_int}} {ip_addr:<{col_ip}} {status:<{col_status}} {description:<{col_desc}}")

    print(f"\n{separator}")
    print(f"Total interfaces: {len(interfaces)}")
    print(f"{separator}\n")


def export_to_csv(interfaces: Dict[str, Dict[str, str]], device_ip: str, filename: Optional[str] = None) -> Optional[str]:
    """Export interface information to a CSV file.

    Args:
        interfaces: Dictionary of interface information
        device_ip: IP address of the device
        filename: Optional custom filename for the CSV export

    Returns:
        Filename if export successful, None otherwise
    """
    if not interfaces:
        print("No data to export.")
        return None

    # Generate filename if not provided
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Sanitize IP address for filename (replace dots with underscores)
        safe_ip = device_ip.replace('.', '_')
        filename = f"cisco_scan_{safe_ip}_{timestamp}.csv"

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Device_IP', 'Interface', 'IP_Address', 'Status', 'Protocol', 'Description']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write header
            writer.writeheader()

            # Sort once and iterate - reuse sorting
            sorted_interfaces = sorted(interfaces.items())
            # Write interface data
            for interface, info in sorted_interfaces:
                ip_addr = normalize_ip_address(info['ip_address'])
                writer.writerow({
                    'Device_IP': device_ip,
                    'Interface': interface,
                    'IP_Address': ip_addr,
                    'Status': info['status'],
                    'Protocol': info['protocol'],
                    'Description': info['description']
                })

        print(f"Results exported to: {filename}")
        return filename

    except Exception as e:
        print(f"ERROR: Failed to export to CSV: {str(e)}")
        return None


def scan_cisco_device(device_info: Dict[str, Any]) -> bool:
    """Connect to Cisco device and retrieve interface information.

    Args:
        device_info: Dictionary containing device connection parameters

    Returns:
        True if scan successful, False otherwise
    """
    try:
        print(f"\nConnecting to {device_info['host']}...")

        # Establish SSH connection using context manager for proper resource management
        with ConnectHandler(**device_info) as connection:
            print("Connected successfully!\n")

            # Retrieve interface information
            print("Retrieving interface information...")
            show_ip_int_brief = connection.send_command('show ip interface brief')
            show_int_desc = connection.send_command('show interfaces description')

            # Parse the information
            interfaces = parse_interface_info(show_ip_int_brief, show_int_desc)

            # Display results
            display_results(interfaces, device_info['host'])

            # Export to CSV
            export_to_csv(interfaces, device_info['host'])

        # Connection automatically closed by context manager
        print("Disconnected from device.\n")

        return True

    except NetmikoTimeoutException:
        print(f"\nERROR: Connection timeout to {device_info['host']}")
        print("Please verify the IP address and network connectivity.\n")
        return False

    except NetmikoAuthenticationException:
        print(f"\nERROR: Authentication failed for {device_info['host']}")
        print("Please verify username and password.\n")
        return False

    except Exception as e:
        print(f"\nERROR: An unexpected error occurred: {str(e)}\n")
        return False


def main() -> None:
    """Main function to run the Cisco device scanner."""
    try:
        while True:
            # Session logging disabled by default to avoid filling disk
            device_info = get_device_info(enable_session_log=False)
            scan_cisco_device(device_info)

            # Ask if user wants to scan another device
            another = input("Scan another device? (y/n): ").strip().lower()
            if another != 'y':
                print("\nThank you for using Cisco Device Scanner!")
                break

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.\n")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {str(e)}\n")


if __name__ == "__main__":
    main()
