import json
import math
import ipaddress
import requests
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(SCRIPT_DIR, '..', 'config')
DATA_DIR = os.path.join(SCRIPT_DIR, '..', 'data')

ASN_FILE = os.path.join(CONFIG_DIR, 'asn.txt')
BLACKLIST_FILE = os.path.join(CONFIG_DIR, 'blacklisted.txt')

def load_blacklisted_subnets():
    blacklisted = []
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.split('#')[0].strip()
                if line:
                    blacklisted.append(line)
    return blacklisted

def is_blacklisted(prefix_str, blacklisted_subnets):
    try:
        if '-' in prefix_str:
            start_str = prefix_str.split('-')[0].strip()
            net = ipaddress.ip_network(f"{start_str}/32")
        else:
            net = ipaddress.ip_network(prefix_str, strict=False)
            
        for black_str in blacklisted_subnets:
            black_net = ipaddress.ip_network(black_str, strict=False)
            if net.overlaps(black_net):
                return True
    except Exception:
        pass
    return False

def load_asn_mapping():
    asn_mapping = {}
    if os.path.exists(ASN_FILE):
        with open(ASN_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.split('#')[0].strip()
                if not line or ':' not in line:
                    continue
                cat, asns = line.split(':', 1)
                cat = cat.strip()
                for asn_str in asns.split(','):
                    asn_str = asn_str.strip().upper().replace('AS', '')
                    if asn_str.isdigit():
                        asn_mapping[int(asn_str)] = cat
    return asn_mapping

def get_asn_prefixes(asn):
    print(f"Fetching prefixes for AS{asn} from RIPEstat...")
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        prefixes = []
        for p_info in data.get("data", {}).get("prefixes", []):
            prefix = p_info.get("prefix")
            if prefix and ":" not in prefix:
                prefixes.append(prefix)
        return prefixes
    except Exception as e:
        print(f"Error getting prefixes for AS{asn} from RIPEstat: {e}")
        return []

def get_aws_jp_ranges(dbip_data):
    print("Downloading AWS IP ranges...")
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    data = r.json()
    aws_jp = []
    for prefix in data.get("prefixes", []):
        ip_prefix = prefix.get("ip_prefix")
        region = prefix.get("region")
        if not ip_prefix:
            continue
            
        if region in ["ap-northeast-1", "ap-northeast-3"]:
            aws_jp.append(ip_prefix)
            continue
            
        try:
            net = ipaddress.ip_network(ip_prefix, strict=False)
            ip_int = int(net.network_address)
            country = find_country(dbip_data, ip_int)
            if country == "JP":
                aws_jp.append(ip_prefix)
        except Exception:
            pass
            
    print(f"Found {len(aws_jp)} AWS Japan prefixes (regional + geolocated).")
    return aws_jp


def download_dbip_database():
    print("Downloading DB-IP country database...")
    dbip_url = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv"
    r = requests.get(dbip_url, timeout=20)
    r.raise_for_status()
    dbip_data = []
    import csv
    import io
    dbip_reader = csv.reader(io.StringIO(r.text))
    for row in dbip_reader:
        if len(row) < 3:
            continue
        dbip_data.append((
            int(ipaddress.ip_address(row[0])),
            int(ipaddress.ip_address(row[1])),
            row[2]
        ))
    print(f"Loaded {len(dbip_data)} GeoIP ranges.")
    return dbip_data

def find_country(dbip_data, ip_int):
    low = 0
    high = len(dbip_data) - 1
    while low <= high:
        mid = (low + high) // 2
        start, end, country = dbip_data[mid]
        if start <= ip_int <= end:
            return country
        elif ip_int < start:
            high = mid - 1
        else:
            low = mid + 1
    return "UNKNOWN"


def download_dbip_asn_database():
    print("Downloading DB-IP ASN database...")
    asn_url = "https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-asn/dbip-asn-ipv4.csv"
    r = requests.get(asn_url, timeout=20)
    r.raise_for_status()
    asn_data = []
    import csv, io
    reader = csv.reader(io.StringIO(r.text))
    for row in reader:
        if len(row) < 3: continue
        try:
            asn_data.append((
                int(ipaddress.ip_address(row[0])),
                int(ipaddress.ip_address(row[1])),
                row[2]
            ))
        except Exception:
            pass
    print(f"Loaded {len(asn_data)} ASN ranges.")
    return asn_data

def find_asn(dbip_asn_data, ip_int):
    low = 0
    high = len(dbip_asn_data) - 1
    while low <= high:
        mid = (low + high) // 2
        start, end, asn = dbip_asn_data[mid]
        if start <= ip_int <= end:
            return asn
        elif ip_int < start:
            high = mid - 1
        else:
            low = mid + 1
    return "NA"

def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    
    try:
        dbip_data = download_dbip_database()
        dbip_asn_data = download_dbip_asn_database()
    except Exception as e:
        print(f"Failed to download DBIP database: {e}")
        sys.exit(1)

    blacklisted_subnets = load_blacklisted_subnets()
    asn_mapping = load_asn_mapping()
    
    categories = { cat: set() for cat in asn_mapping.values() }
    categories["resolved"] = set()
    if "aws" not in categories: categories["aws"] = set()
    if "dmm" not in categories: categories["dmm"] = set()

    target_asns = list(asn_mapping.keys())
    print(f"Loaded {len(target_asns)} target ASNs to query from config.")

    print("\nFetching prefixes for target ASNs...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_asn = {executor.submit(get_asn_prefixes, asn): asn for asn in target_asns}
        for future in as_completed(future_to_asn):
            asn = future_to_asn[future]
            category = asn_mapping.get(asn, "unknown")
            if category not in categories:
                categories[category] = set()
            try:
                prefixes = future.result()
                if prefixes:
                    print(f"  AS{asn} ({category}): Found {len(prefixes)} prefixes.")
                    categories[category].update(prefixes)
            except Exception as e:
                print(f"  Error getting prefixes for AS{asn}: {e}")

    print("\nFetching AWS IP ranges...")
    aws_jp_prefixes = get_aws_jp_ranges(dbip_data)
    categories["aws"].update(aws_jp_prefixes)

    filtered_categories = {k: [] for k in categories.keys()}
    total_removed = 0

    for cat_name, prefixes in categories.items():
        print(f"Processing category '{cat_name}' ({len(prefixes)} raw prefixes)...")
        for prefix_str in sorted(prefixes):
            if is_blacklisted(prefix_str, blacklisted_subnets):
                print(f"  [{cat_name}] Removing blacklisted range: {prefix_str}")
                total_removed += 1
                continue

            try:
                if '-' in prefix_str:
                    start_str = prefix_str.split('-')[0].strip()
                    net_ip = ipaddress.ip_address(start_str)
                else:
                    net = ipaddress.ip_network(prefix_str, strict=False)
                    net_ip = net.network_address

                ip_int = int(net_ip)
                country = find_country(dbip_data, ip_int)

                if country == "JP":
                    filtered_categories[cat_name].append(prefix_str)
                else:
                    print(f"  [{cat_name}] Removing non-JP range: {prefix_str} ({country})")
                    total_removed += 1
            except Exception:
                filtered_categories[cat_name].append(prefix_str)

    print("\nVerifying ASNs using offline DB-IP ASN database...")
    verified_categories = {cat: set() for cat in categories.keys()}
    
    for cat_name, prefixes in filtered_categories.items():
        expected_asns = [str(asn) for asn, cat in asn_mapping.items() if cat == cat_name]
        
        for p in prefixes:
            if '-' in p:
                start_ip = p.split('-')[0].strip()
            else:
                net = ipaddress.ip_network(p, strict=False)
                start_ip = str(net.network_address)
            
            ip_int = int(ipaddress.ip_address(start_ip))
            found_asn = find_asn(dbip_asn_data, ip_int)
            
            if not expected_asns:
                verified_categories[cat_name].add(p)
            elif found_asn in expected_asns:
                verified_categories[cat_name].add(p)
            else:
                print(f"  [{cat_name}] ASN Verification Failed: {p} (Found: {found_asn}, Expected: {expected_asns})")
                total_removed += 1

    def sort_key(net_str):
        try:
            if '-' in net_str:
                start_ip = net_str.split('-')[0].strip()
                ip = ipaddress.ip_address(start_ip)
                return (ip.version, int(ip), 32)
            else:
                net = ipaddress.ip_network(net_str, strict=False)
                return (net.version, int(net.network_address), net.prefixlen)
        except Exception:
            return (4, 0, 0)

    print("\nSaving files to data directory...")
    total_verified = 0

    for cat_name, prefixes in verified_categories.items():
        if not prefixes:
            continue
        sorted_prefixes = sorted(prefixes, key=sort_key)
        total_verified += len(sorted_prefixes)
        
        filename = f"japan_ips_{cat_name}.txt"
        file_path = os.path.join(DATA_DIR, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"# Verified Japan IP Ranges - Category: {cat_name.upper()}\n")
            for p in sorted_prefixes:
                f.write(f"{p}\n")
        print(f"  Saved {len(sorted_prefixes)} ranges to {filename}")

    print(f"\nSUCCESS: Removed {total_removed} non-JP/blacklisted/invalid-ASN ranges.")
    print(f"Total combined verified JP ranges: {total_verified}")

if __name__ == "__main__":
    main()
