#!/usr/bin/env python3
# Combined CSV address expansion and PPSM mapping pipeline - Multi-file version
# 1. Matches setconf and conf file pairs from two directories
# 2. Expands address-sets to hostnames and IPs
# 3. Maps to PPSM format with character limit enforcement


#CHANGE NOTES 

# Added function that compares the two files within the two folders 
# and then if the hostnames are equal it runs the original address expander,
# all other functional logic stays the same. 
# Added application port parsing to extract port numbers from application definitions


import argparse
import csv
import os
import re
import sys
from pathlib import Path
from collections import defaultdict


def build_address_book(conf_lines):
    addr2cidr = defaultdict(list)
    set2members = defaultdict(list)
    hostname2ip = {}

    # patterns for the two possible syntaxes
    addr_pat   = re.compile(r'set security address-book \S+ address (\S+) (\S+)')
    simple_addr_pat = re.compile(r'address\s+(\S+)\s+([\d\./]+);')
    set_start  = re.compile(r'address-set\s+(\S+)\s*\{')
    addr_item  = re.compile(r'address\s+(\S+);')

    current_set = None

    for raw in conf_lines:
        line = raw.strip()

        m = addr_pat.search(line)
        if m:
            name, cidr = m.groups()
            addr2cidr[name].append(cidr)
            continue

        m = simple_addr_pat.search(line)
        if m:
            hostname, ip = m.groups()
            hostname2ip[hostname] = ip
            continue

        if current_set is None:
            m = set_start.match(line)
            if m:
                current_set = m.group(1)
                continue
        else:
            if line == '}':
                current_set = None
                continue
            m = addr_item.match(line)
            if m:
                member = m.group(1)
                set2members[current_set].append(member)

    return addr2cidr, set2members, hostname2ip

    
# Parse application definitions and extract port mappings.
# Returns: dict where key=application name, value=list of ports
    
def build_application_ports(conf_lines):
    
    app2ports = defaultdict(list)
    app_set2members = defaultdict(list)
    current_app = None
    current_set = None
    
    # Regex patterns
    app_start = re.compile(r'application\s+(\S+)\s*\{')
    app_set_start = re.compile(r'application-set\s+(\S+)\s*\{')
    app_set_member = re.compile(r'application\s+(\S+);')
    
    # Format 1: term lines
    term_port = re.compile(r'term\s+\S+\s+protocol\s+\S+\s+destination-port\s+(\S+).*;',re.IGNORECASE)

    # Format 2: direct destination-port lines
    direct_port = re.compile(r'destination-port\s+(\S+);', re.IGNORECASE)
    
    for raw in conf_lines:
        line = raw.strip()
        
        # Check if starting a new application block
        if current_app is None and current_set is None:
            m = app_start.match(line)
            if m:
                current_app = m.group(1)
                continue
            
            m = app_set_start.match(line)
            if m:
                current_set = m.group(1)
                continue
        
        # Inside an application block
        elif current_app is not None:
            if line == '}':
                current_app = None
                continue
            
            # Try format 1 (with term)
            m = term_port.match(line)
            if m:
                port = m.group(1)
                if port not in app2ports[current_app]:
                    app2ports[current_app].append(port)
                continue
            
            # Try format 2 (without term)
            m = direct_port.match(line)
            if m:
                port = m.group(1)
                if port not in app2ports[current_app]:
                    app2ports[current_app].append(port)
        
        # Inside an application-set block
        elif current_set is not None:
            if line == '}':
                current_set = None
                continue
            
            m = app_set_member.match(line)
            if m:
                member = m.group(1)
                app_set2members[current_set].append(member)
    
    # Recursively resolve application-sets
    resolved_sets = {}
    
    def resolve_app_set(set_name):
        if set_name in resolved_sets:
            return resolved_sets[set_name]
        
        members = set()
        for member in app_set2members.get(set_name, []):
            if member in app_set2members:
                # Member is also a set, recurse
                members.update(resolve_app_set(member))
            else:
                # Member is an application
                members.add(member)
        
        resolved_sets[set_name] = members
        return members
    
    # Resolve all application-sets
    for app_set in app_set2members:
        resolve_app_set(app_set)
    combined_ports = {}
    
    for app, ports in app2ports.items():
        combined_ports[app] = ports
    
    for app_set, members in resolved_sets.items():
        all_ports = []
        for member in members:
            if member in app2ports:
                all_ports.extend(app2ports[member])
                
        # Duplicate handling in terms of ports.        
        seen = set()
        unique_ports = []
        for port in all_ports:
            if port not in seen:
                seen.add(port)
                unique_ports.append(port)
        combined_ports[app_set] = unique_ports
    
    return combined_ports, resolved_sets


# Address mapping similar to how juniper policy works. 
def resolve_set(set_name, set2members, cache=None):
    if cache is None:
        cache = {}
    if set_name in cache:
        return cache[set_name]
    members = set()
    for member in set2members.get(set_name, []):
        if member in set2members:
            members.update(resolve_set(member, set2members, cache))
        else:
            members.add(member)
    cache[set_name] = members
    return members

# Parse a cell that looks like ['item1','item2'] and return list of items.
def parse_list_cell(cell_value):
    cell_value = cell_value.strip()
    if cell_value.startswith('[') and cell_value.endswith(']'):
        inner = cell_value[1:-1]
        if not inner:
            return []
        items = [item.strip().strip("'\"") for item in inner.split(',')]
        return items
    return [cell_value]

# Expand address-sets to hostnames.
def expand_cell(cell_value, set2members):
    items = parse_list_cell(cell_value)
    expanded = []
    
    for item in items:
        if item in set2members:
            members = resolve_set(item, set2members)
            expanded.extend(members)
        else:
            matching_set = None
            for set_name in set2members.keys():
                if set_name.lower() == item.lower():
                    matching_set = set_name
                    break
            if matching_set:
                members = resolve_set(matching_set, set2members)
                expanded.extend(members)
            else:
                expanded.append(item)
    
    return ", ".join(expanded)

def expand_with_ips(cell_value, set2members, hostname2ip):
    items = parse_list_cell(cell_value)
    expanded = []
    
    for item in items:
        if item in set2members:
            members = resolve_set(item, set2members)
            for member in members:
                ip = hostname2ip.get(member, member)
                expanded.append(ip)
        else:
            matching_set = None
            for set_name in set2members.keys():
                if set_name.lower() == item.lower():
                    matching_set = set_name
                    break
            if matching_set:
                members = resolve_set(matching_set, set2members)
                for member in members:
                    ip = hostname2ip.get(member, member)
                    expanded.append(ip)
            else:
                ip = hostname2ip.get(item, item)
                expanded.append(ip)
    
    return ", ".join(expanded)


    # Extract the base name from a filename, removing -setconf or -conf and numbers.
    # Example: 'hostname-setconf12345.txt' -> 'hostname'
    # Example: 'hostname-conf12345.txt' -> 'hostname'
    

def extract_base_name(filename):
    name = os.path.splitext(filename)[0] 
    
    # Only potential issue is that there is a date at the end of 
    # each file so there could be a conflict of it pulling the same hostname
    # at different dates. 
    # If this becomes an issue there will be a need to grab the date after the 
    # setconf and conf split. 
    
    if '-setconf' in name: 
        hostname = name.split('setconf')[0] # Remove setconf from filename
    elif '-conf' in name: 
        hostname = name.split('conf')[0]  # Remove conf from filename 
    else: 
        hostname = name
        
    return hostname

    # Find matching pairs of setconf CSV files and conf files.
    # Returns list of tuples: (csv_path, conf_path, output_base_name)

def find_file_pairs(setconf_dir, conf_dir):
    
    setconf_path = Path(setconf_dir)
    conf_path = Path(conf_dir)
    
    # Find all CSV files in setconf directory, must ignore the dates. 
    csv_files = list(setconf_path.glob("*-setconf*.txt.csv"))
    
    # Find all conf files in conf directory, must ignore the dates.
    conf_files = list(conf_path.glob("*-conf*.txt"))
    
    # Build a mapping of base names to conf files
    conf_map = {}
    for conf_file in conf_files:
        base_name = extract_base_name(conf_file.name) # Base name extraction 
        conf_map[base_name] = conf_file
    
    # Match CSV files to conf files
    pairs = []
    unmatched = []
    
    for csv_file in csv_files:
        # Extract base name from CSV filename (remove .csv extension first)
        csv_name = csv_file.name.replace('.csv', '')
        base_name = extract_base_name(csv_name)
        
        if base_name in conf_map:
            conf_file = conf_map[base_name]
            output_name = f"{base_name}_ppsm.csv"
            pairs.append((str(csv_file), str(conf_file), output_name))
        else:
            unmatched.append(csv_file.name)
    
    return pairs, unmatched


def process_file_pair(csv_path, conf_path, output_path, verbose=False):
    
    if verbose:
        print(f"\nProcessing pair:")
        print(f"    CSV:  {csv_path}")
        print(f"    Conf: {conf_path}")
    
    # Parse the Juniper config
    with open(conf_path, "r", encoding="utf8") as fh:
        conf_lines = fh.readlines()

    _, set2members, hostname2ip = build_address_book(conf_lines)
    app2ports, app_set_members = build_application_ports(conf_lines)
    
    if verbose:
        print(f"Loaded {len(hostname2ip)} hostname-to-IP mappings")
        print(f"Loaded {len(set2members)} address-sets")
        print(f"Loaded {len(app2ports)} application port mappings")

    # Process the CSV with semicolon delimiter
    with open(csv_path, "r", encoding="utf8") as infile:
        reader = csv.reader(infile, delimiter=';')
        rows = list(reader)

    if not rows:
        print(f"Warning: CSV file is empty: {csv_path}")
        return 0

    headers = rows[0]
    try:
        src_addr_idx = headers.index('source-address')
        dst_addr_idx = headers.index('destination-address')
        src_ip_idx = headers.index('source-ip')
        dst_ip_idx = headers.index('destination-ip')
    except ValueError as e:
        print(f"Error: Could not find required columns in {csv_path}: {e}")
        return 0

    expanded_rows = []
    for i, row in enumerate(rows):
        expanded_row = row.copy()
        
        if len(expanded_row) > src_addr_idx:
            expanded_row[src_addr_idx] = expand_cell(row[src_addr_idx], set2members)
        
        if len(expanded_row) > dst_addr_idx:
            expanded_row[dst_addr_idx] = expand_cell(row[dst_addr_idx], set2members)
        
        if len(expanded_row) > src_ip_idx:
            expanded_row[src_ip_idx] = expand_with_ips(row[src_ip_idx], set2members, hostname2ip)
        
        if len(expanded_row) > dst_ip_idx:
            expanded_row[dst_ip_idx] = expand_with_ips(row[dst_ip_idx], set2members, hostname2ip)
        
        expanded_rows.append(expanded_row)

    if verbose:
        print(f"Expanded address-sets in CSV")

    # PPSM Format 
    dict_rows = []
    for row in expanded_rows[1:]:  # Skip header row
        row_dict = {headers[i]: row[i] for i in range(len(headers))}
        dict_rows.append(row_dict)

    mapping = {
        'from-zone': 'Boundary',
        'to-zone': 'Boundary',
        'policy-name': 'Purpose',
        'source-address': 'Source Device or Server Name',
        'destination-address': 'Destination Device or Server Name',
        'application': 'Application/Software Record Name',
        'source-ip': 'Source IP Address',
        'destination-ip': 'Destination IP Address'
    }

    # full ppsm headers 
    output_headers = [
        '#', 'Type', 'Application/Software Record Name', 'Protocol', 'Data Service',
        'Port', 'Boundary', 'Source Device or Server Name', 'Source Physical Location or Cloud Service Provider',
        'Source IP Address', 'Source FQDN', 'Connection Logical Tunnel Type', 'Destination Device or Server Name',
        'Destination Physical Location or Cloud Service Provider', 'Destination IP Address', 'Destination FQDN',
        'Connection Logical Tunnel Type', 'VPN / Encrypted Tunnel Traffic', 'VPN Tunnel Type', 'Purpose'
    ]

    # Define character limits per field per ppsm rules 
    char_limits = {
        'Application/Software Record Name': 40,
        'Source Device or Server Name': 200,
        'Destination Device or Server Name': 200,
        'Source FQDN': 1000,
        'Destination IP': 1000,
        'Source IP Address': 1000,
        'Destination IP Address': 1000,
        'Purpose': 750
    }

    csv_filename = os.path.basename(csv_path)
    csv_pointer = f"See {csv_filename}"

    # Process rows for PPSM format (character-limited version)
    output_rows = []
    for row_idx, csv_row in enumerate(dict_rows, start=1):
        output_row = {header: '' for header in output_headers}
        
        # Boundary mapping
        from_zone = csv_row.get('from-zone', '')
        to_zone = csv_row.get('to-zone', '')
        boundary = f"{from_zone} : {to_zone}"
        output_row['Boundary'] = boundary

        # Port lookup 
        app_name = csv_row.get('application', '')
        
       
        
        
        if app_name and app_name in app2ports:
            ports = app2ports[app_name]
            output_row['Port'] = ', '.join(ports)
        else:
            output_row['Port'] = ''

        
        
        for csv_col, output_col in mapping.items():
            if csv_col in ['from-zone', 'to-zone']:
                continue

            value = csv_row.get(csv_col, '')
            # ====================================================
            # if csv_col == 'application' and value in app_set_members: 
            #     members = app_set_members[value] 
            #     value = ', '.join(members)
            
            # Character limit
            limit = char_limits.get(output_col, None)
            if limit and value and len(str(value)) > limit:
                if verbose:
                    print(f"Row {row_idx}, '{output_col}': {len(str(value))} chars (limit {limit}) → using pointer")
                value = csv_pointer

            output_row[output_col] = value
        
        
        
        output_rows.append(output_row)

    # Write character-limited output CSV file
    with open(output_path, "w", encoding="utf8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=output_headers, delimiter=';')
        writer.writeheader()
        writer.writerows(output_rows)

    # Create full version (no character limits) for emass artifact
    full_rows = []
    for row_idx, csv_row in enumerate(dict_rows, start=1):
        full_row = {header: '' for header in output_headers}
        
        from_zone = csv_row.get('from-zone', '')
        to_zone = csv_row.get('to-zone', '')
        boundary = f"{from_zone} : {to_zone}"
        full_row['Boundary'] = boundary
        
        
        # Handle Port lookup from application name.
        app_name = csv_row.get('application', '')
        
        
        #debug apps in app sets 
        print(f"DEBUG: app_name = '{app_name}'")
        print(f"DEBUG: app_name in app_set_members? {app_name in app_set_members}")
        print(f"DEBUG: Available app sets: {list(app_set_members.keys())}")
        
        
        if app_name and app_name in app_set_members:
            members = app_set_members[app_name] 
            full_row['Application/Software Record Name']=', '.join(members)
        
            if app_name and app_name in app2ports:
                ports = app2ports[app_name]
                full_row['Port'] = ', '.join(ports)
            else:
                full_row['Port'] = ''

        else: 
            full_row['Application/Software Record Name'] = app_name
            
            if app_name and app_name in app2ports:
                ports = app2ports[app_name]
                full_row['Port'] = ', '.join(ports)
            else:
                full_row['Port'] = ''
        
        
        # ====================
        for csv_col, output_col in mapping.items():
            if csv_col in ['from-zone', 'to-zone']:
                continue
            
            
            
            full_row[output_col] = csv_row.get(csv_col, '')
            
        full_rows.append(full_row)
    
    # Write full version
    full_path = output_path.replace(".csv", "_full.csv")
    with open(full_path, "w", encoding="utf8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=output_headers, delimiter=';')
        writer.writeheader()
        writer.writerows(full_rows)

    if verbose:
        print(f"Wrote {len(output_rows)} rows to: {output_path}")
        print(f"Wrote full version to: {full_path}")

    return len(output_rows)



def main():
    parser = argparse.ArgumentParser(
        description="Expand Juniper address-sets and map to PPSM format for multiple files."
    )
    parser.add_argument("-s", "--setconf-dir", required=True,
                        help="Directory containing setconf CSV files (output from parser)")
    parser.add_argument("-c", "--conf-dir", required=True,
                        help="Directory containing conf files")
    parser.add_argument("-o", "--output-dir", required=True,
                        help="Directory for PPSM output files")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print detailed progress information")
    args = parser.parse_args()

    # Directory handling
    if not os.path.isdir(args.setconf_dir):
        sys.stderr.write(f"Error: setconf directory not found: {args.setconf_dir}\n")
        sys.exit(1)

    if not os.path.isdir(args.conf_dir):
        sys.stderr.write(f"Error: conf directory not found: {args.conf_dir}\n")
        sys.exit(1)

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Find matching file pairs
    pairs, unmatched = find_file_pairs(args.setconf_dir, args.conf_dir)

    if not pairs:
        print("Error: No matching file pairs found!")
        sys.exit(1)

    print(f"Found {len(pairs)} matching file pair(s)")
    
    if unmatched:
        print(f"Warning: {len(unmatched)} CSV file(s) have no matching conf file:")
        for um in unmatched:
            print(f"    - {um}")

    # Process each pair
    total_rows = 0
    processed = 0

    for csv_path, conf_path, output_name in pairs:
        output_path = os.path.join(args.output_dir, output_name)
        try:
            rows = process_file_pair(csv_path, conf_path, output_path, verbose=args.verbose)
            total_rows += rows
            processed += 1
            if not args.verbose:
                print(f"Processed: {os.path.basename(csv_path)} → {output_name} ({rows} rows)")
        except Exception as e:
            print(f"Error processing {csv_path}: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()

    print(f"\n{'='*45}")
    print(f"Processed {processed}/{len(pairs)} file pair(s)")
    print(f"Total rows exported: {total_rows}")
    print(f"Output directory: {args.output_dir}")
    print(f"{'='*45}")


if __name__ == "__main__":
    main()