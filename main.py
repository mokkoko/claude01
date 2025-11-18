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
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


def get_device_info():
    """Prompt user for device connection information."""
    print("\n=== Cisco Device Scanner ===\n")
    ip_address = input("Enter device IP address: ").strip()
    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password: ")

    return {
        'device_type': 'cisco_ios',
        'host': ip_address,
        'username': username,
        'password': password,
        'session_log': 'netmiko_session.log'
    }


def parse_interface_info(show_ip_int_output, show_int_desc_output):
    """Parse interface information from command outputs."""
    interfaces = {}

    # Parse IP addresses from 'show ip interface brief'
    for line in show_ip_int_output.split('\n'):
        # Skip header and empty lines
        if 'Interface' in line or not line.strip():
            continue

        # Match interface lines
        match = re.match(r'(\S+)\s+(\S+)\s+\S+\s+\S+\s+(\S+)\s+(\S+)', line)
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
        if 'Interface' in line or not line.strip():
            continue

        # Match interface description lines
        parts = line.split()
        if len(parts) >= 2:
            interface = parts[0]
            # Find where description starts (after status fields)
            desc_match = re.search(r'\S+\s+\S+\s+\S+\s+(.*)', line)
            description = desc_match.group(1).strip() if desc_match else ''

            if interface in interfaces:
                interfaces[interface]['description'] = description

    return interfaces


def display_results(interfaces, device_ip):
    """Display formatted interface information."""
    print(f"\n{'='*80}")
    print(f"Interface Report for Device: {device_ip}")
    print(f"{'='*80}\n")

    if not interfaces:
        print("No interfaces found or device returned no data.")
        return

    print(f"{'Interface':<20} {'IP Address':<15} {'Status':<10} {'Description':<30}")
    print(f"{'-'*80}")

    for interface, info in sorted(interfaces.items()):
        ip_addr = info['ip_address'] if info['ip_address'] != 'unassigned' else 'N/A'
        status = f"{info['status']}/{info['protocol']}"
        description = info['description'][:28] + '..' if len(info['description']) > 30 else info['description']

        print(f"{interface:<20} {ip_addr:<15} {status:<10} {description:<30}")

    print(f"\n{'='*80}")
    print(f"Total interfaces: {len(interfaces)}")
    print(f"{'='*80}\n")


def export_to_csv(interfaces, device_ip, filename=None):
    """Export interface information to a CSV file."""
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

            # Write interface data
            for interface, info in sorted(interfaces.items()):
                ip_addr = info['ip_address'] if info['ip_address'] != 'unassigned' else 'N/A'
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


def scan_cisco_device(device_info):
    """Connect to Cisco device and retrieve interface information."""
    try:
        print(f"\nConnecting to {device_info['host']}...")

        # Establish SSH connection
        connection = ConnectHandler(**device_info)
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

        # Disconnect
        connection.disconnect()
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


def main():
    """Main function to run the Cisco device scanner."""
    try:
        while True:
            device_info = get_device_info()
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
