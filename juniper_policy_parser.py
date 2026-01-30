#!/usr/bin/env python3
import sys, os, csv, argparse, copy, re, traceback
from collections import defaultdict
from pathlib import Path

# Change notes

# Added logical-systems policy support as it previously ignored it 
# 
# Only parsed set security policies 
# Separated extraction within 3 different parsing areas 
# Set logical systems from zone to zone 
# Global from zone to zone 
# Global to global 

# Adjusted the pattern to not have hard referenced tokens in data[x], now it matches a pattern 
# Avoids indexing errors and malformed lines. 
# Attempted to address some duplication. 


# 
# Address dictionary and address-set builder 
# 
def build_address_book(conf_lines):

    addr2cidr   = defaultdict(list)
    set2members = defaultdict(list)

    for raw in conf_lines:
        line = raw.strip()

        # Address objects
        m = re.search(r'set security address-book \S+ address (\S+) (\S+)', line)
        if m:
            name, cidr = m.group(1), m.group(2)
            addr2cidr[name].append(cidr)
            continue

        # Address-set members
        m = re.search(r'set security address-book \S+ address-set (\S+) address (\S+)', line)
        if m:
            set_name, member = m.group(1), m.group(2)
            set2members[set_name].append(member)
            continue
 

    resolved_sets = {}

    def resolve_set(s):
        if s in resolved_sets:
            return resolved_sets[s]
        members = set()
        for mem in set2members.get(s, []):
            if mem in set2members:
                members.update(resolve_set(mem))
            else:
                members.add(mem)
        resolved_sets[s] = list(members)
        return resolved_sets[s]

    for s in set2members:
        resolve_set(s)

    return addr2cidr, resolved_sets


# 
# Address / hostname expansion 
# 
def expand_address_names(names, addr2cidr, set2members):
    if not names:
        return []
    if names == ['any']:
        return ['any']

    ip_list = []
    seen = set()

    for n in names:
        if n in addr2cidr and n not in seen:
            ip_list.extend(addr2cidr[n])
            seen.add(n)
        elif n in set2members and n not in seen:
            for member in set2members[n]:
                if member not in seen:
                    ip_list.extend(addr2cidr.get(member, []))
                    seen.add(member)
        elif n not in seen:
            ip_list.append(n)
            seen.add(n)

    return ip_list


def expand_address_hostnames(names, set2members):
    if not names:
        return []
    if names == ['any']:
        return ['any']

    hostname_list = []
    seen = set()

    for n in names:
        if n in set2members and n not in seen:
            for member in set2members[n]:
                if member not in seen:
                    hostname_list.append(member)
                    seen.add(member)
        elif n not in seen:
            hostname_list.append(n)
            seen.add(n)

    return hostname_list


# Expand applications to individual policies and rows

def expand_policies_by_application(policies_set):
    expanded = []
    for p in policies_set:
        apps = p["application"]
        if not apps:
            expanded.append(p)
        else:
            for app in apps:
                row = copy.deepcopy(p)
                row["application"] = app
                expanded.append(row)
    return expanded


def process_single_file(filepath, output_dir=None, verbose=False):

    if verbose:
        print(f"\nProcessing: {filepath}")

    with open(filepath, "r", encoding="utf8") as f:
        raw_lines = f.readlines()

    addr2cidr, set2members = build_address_book(raw_lines)

    if verbose:
        print(f"Address objects : {len(addr2cidr)}")
        print(f"Address sets    : {len(set2members)}")

    # POLICY DATA STRUCTURE
    policies_set = []
    policy_template = {
        "VSYS": "GLOBAL",
        "from-zone": "",
        "to-zone": "",
        "policy-name": "",
        "source-address": [],
        "destination-address": [],
        "application": [],
        "source-identity": [],
        "global-from-zone": [],
        "global-to-zone": [],
        "action": [],
        "source-ip": [],
        "destination-ip": []
    }

    def find_policy(vsys, fz, tz, pname):
        for i, p in enumerate(policies_set):
            if (p["VSYS"] == vsys and p["from-zone"] == fz and
                p["to-zone"] == tz and p["policy-name"] == pname):
                return i
        return -1

    # 
    # Fixed policy parser to handle 3 types of policies
    # 
    for raw in raw_lines:
        line = raw.strip()
        if not line.startswith("set "):
            continue

        data = line.split()

        
        # Logical systems policies implementation
        
        if len(data) >= 12 and data[1] == "logical-systems" and data[3] == "security":
            vsys = data[2]
            from_zone = data[6]
            to_zone   = data[8]
            policy_name = data[10]
            prop_type = data[11]

            if prop_type == "match":
                field = data[12]
                value = data[13]
                idx = find_policy(vsys, from_zone, to_zone, policy_name)

                if idx == -1:
                    tmp = copy.deepcopy(policy_template)
                    tmp["VSYS"] = vsys
                    tmp["from-zone"] = from_zone
                    tmp["to-zone"] = to_zone
                    tmp["policy-name"] = policy_name
                    tmp[field].append(value)
                    policies_set.append(tmp)
                else:
                    policies_set[idx][field].append(value)

            elif prop_type == "then":
                action_val = data[12]
                idx = find_policy(vsys, from_zone, to_zone, policy_name)

                if idx == -1:
                    tmp = copy.deepcopy(policy_template)
                    tmp["VSYS"] = vsys
                    tmp["from-zone"] = from_zone
                    tmp["to-zone"] = to_zone
                    tmp["policy-name"] = policy_name
                    tmp["action"].append(action_val)
                    policies_set.append(tmp)
                else:
                    policies_set[idx]["action"].append(action_val)

            continue

        
        # Global policies
        
        if len(data) >= 10 and data[1] == "security" and data[2] == "policies" and data[3] == "from-zone":

            vsys = "GLOBAL"
            from_zone = data[4]
            to_zone   = data[6]
            policy_name = data[8]
            prop_type = data[9]

            if prop_type == "match":
                field = data[10]
                value = data[11]

                idx = find_policy(vsys, from_zone, to_zone, policy_name)
                if idx == -1:
                    tmp = copy.deepcopy(policy_template)
                    tmp["VSYS"] = vsys
                    tmp["from-zone"] = from_zone
                    tmp["to-zone"] = to_zone
                    tmp["policy-name"] = policy_name
                    tmp[field].append(value)
                    policies_set.append(tmp)
                else:
                    policies_set[idx][field].append(value)

            elif prop_type == "then":
                action_val = data[10]
                idx = find_policy(vsys, from_zone, to_zone, policy_name)
                if idx != -1:
                    policies_set[idx]["action"].append(action_val)
            continue

        
        # Global to global 
        
        if len(data) >= 7 and data[1] == "security" and data[2] == "policies" and data[3] == "global":
            vsys = "GLOBAL"
            from_zone = "GLOBAL"
            to_zone   = "GLOBAL"
            policy_name = data[5]
            prop_type = data[6]

            if prop_type == "match":
                field = data[7]
                value = data[8]

                idx = find_policy(vsys, from_zone, to_zone, policy_name)
                if idx == -1:
                    tmp = copy.deepcopy(policy_template)
                    tmp["VSYS"] = vsys
                    tmp["from-zone"] = from_zone
                    tmp["to-zone"] = to_zone
                    tmp["policy-name"] = policy_name

                    if field == "from-zone":
                        tmp["global-from-zone"].append(value)
                    elif field == "to-zone":
                        tmp["global-to-zone"].append(value)
                    else:
                        tmp[field].append(value)

                    policies_set.append(tmp)
                else:
                    if field == "from-zone":
                        policies_set[idx]["global-from-zone"].append(value)
                    elif field == "to-zone":
                        policies_set[idx]["global-to-zone"].append(value)
                    else:
                        policies_set[idx][field].append(value)

            elif prop_type == "then":
                action_val = data[7]
                idx = find_policy(vsys, from_zone, to_zone, policy_name)
                if idx != -1:
                    policies_set[idx]["action"].append(action_val)

            continue

    # 
    # Post process expansion  
    # 
    for p in policies_set:
        p["source-address"] = expand_address_hostnames(p["source-address"], set2members)
        p["destination-address"] = expand_address_hostnames(p["destination-address"], set2members)

        p["source-ip"] = expand_address_names(p["source-address"], addr2cidr, set2members)
        p["destination-ip"] = expand_address_names(p["destination-address"], addr2cidr, set2members)

    policies_set = expand_policies_by_application(policies_set)

    # 
    # CSV OUTPUT
    # 
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        base_filename = os.path.basename(filepath)
        out_file = os.path.join(output_dir, base_filename + ".csv")
    else:
        out_file = filepath + ".csv"

    headers = [
        'VSYS', 'from-zone', 'to-zone', 'policy-name',
        'source-address', 'destination-address', 'application',
        'source-identity', 'global-from-zone', 'global-to-zone',
        'action', 'source-ip', 'destination-ip'
    ]

    with open(out_file, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers, delimiter=';')
        writer.writeheader()
        writer.writerows(policies_set)

    if verbose:
        print(f"CSV written to {out_file}")

    return len(policies_set), out_file


# 
# MAIN
# 
def main():
    parser = argparse.ArgumentParser(
        prog='juniper-policy-parser',
        description='Parse Juniper set-style config and output CSV with resolved IPs.',
        epilog='by Neko Ferrara'
    )

    parser.add_argument('-s', '--directory', required=True,
                        help='Directory containing *-setconf* files')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('-o', '--output', required=True,
                        help='Output directory for CSV files')

    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print("Directory not found!")
        sys.exit(1)

    dir_path = Path(args.directory)

    txt_files = list(dir_path.glob("*-setconf*.txt"))
    docx_files = list(dir_path.glob("*-setconf*.docx"))
    files_to_process = txt_files + docx_files

    if not files_to_process:
        print(f"No *-setconf*.txt or *-setconf*.docx files found in {args.directory}")
        sys.exit(1)

    files_to_process = [str(f) for f in files_to_process]

    if args.verbose:
        print(f"Found {len(files_to_process)} files:")
        for f in files_to_process:
            print(f" - {f}")

    total_policies = 0

    for filepath in files_to_process:
        try:
            count, out = process_single_file(filepath, output_dir=args.output, verbose=args.verbose)
            total_policies += count
            if not args.verbose:
                print(f"Processed {filepath} -> {out} ({count} policies)")
        except Exception as e:
            print(f"Error processing {filepath}: {e}")
            if args.verbose:
                traceback.print_exc()

    print(f"Success — Total policies exported: {total_policies}")


if __name__ == "__main__":
    main()
