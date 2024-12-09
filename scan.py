import socket
import sys
import time
import json
import subprocess
import http.client
import maxminddb


# 0. Read public_dns_resolvers.txt and return public DNS resolvers as list
def get_public_dns_resolvers():
    dns_resolvers = []

    with open("public_dns_resolvers.txt", "r") as file:
        for line in file:
            resolver = line.split()[0]
            dns_resolvers.append(resolver)
    
    return dns_resolvers

# 1. Scan time
def get_scan_time():
    return time.time()

# 2. Take in domain name and list of public dns resolvers, return DNS A records as python list
def get_ipv4_addresses(domain, public_dns_resolvers):
    a_records = set()

    for resolver in public_dns_resolvers:
        try:
            result = subprocess.check_output(
                ["nslookup", "-type=A", domain, resolver], 
                timeout=3, 
                stderr=subprocess.STDOUT
            ).decode("utf-8")

            for line in result.splitlines():
                if line.strip().startswith("Address:") and "#" not in line:
                    ip = line.split("Address: ", 1)[1].strip()
                    a_records.add(ip)

        except subprocess.TimeoutExpired:
            sys.stderr.write(f"Error: Timeout expired while querying {resolver} for domain {domain}.\n")
        except Exception as e:
            sys.stderr.write(f"Unexpected error: {e}\n")
    
    return list(a_records)

# 3. Take in domain name and list of public dns resolvers, return DNS AAAA records as python list
def get_ipv6_addresses(domain, public_dns_resolvers):
    aaaa_records = set()

    for resolver in public_dns_resolvers:
        try:
            result = subprocess.check_output(
                ["nslookup", "-type=AAAA", domain, resolver], 
                timeout=3, 
                stderr=subprocess.STDOUT
            ).decode("utf-8")

            for line in result.splitlines():
                if line.strip().startswith("Address:") and "#" not in line:
                    ip = line.split("Address: ", 1)[1].strip()
                    aaaa_records.add(ip)

        except subprocess.TimeoutExpired:
            sys.stderr.write(f"Error: Timeout expired while querying {resolver} for domain {domain}.\n")
        except Exception as e:
            sys.stderr.write(f"Unexpected error: {e}\n")
    
    return list(aaaa_records)

# 4. Take in domain name, get the web server software reported in 
# the server header of the HTTP response
def get_http_server(domain):
    conn = None
    try:
        conn = http.client.HTTPConnection(domain, timeout=5)
        conn.request("GET", "/")
        response = conn.getresponse()
        server_header = response.getheader('Server')

        return server_header
    
    except socket.timeout:
        sys.stderr.write(f"Error: Timeout expired while connecting to {domain}.\n")
        return None
    except Exception as e:
        sys.stderr.write(f"Unexpected error: {e}\n")
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception as e:
                sys.stderr.write(f"Error: Failed to close the connection: {e}\n")

# 5. Take in domain, return if webserver listens on port 80
def is_insecure_http(domain):
    conn = None
    try:
        conn = http.client.HTTPConnection(domain, port=80, timeout=5)
        conn.request("GET", "/")
        response = conn.getresponse()

        return response.status is not None
        
    except socket.timeout:
        sys.stderr.write(f"Error: Timeout expired while connecting to {domain}.\n")
        return None
    except Exception as e:
        sys.stderr.write(f"Unexpected error: {e}\n")
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception as e:
                sys.stderr.write(f"Error: Failed to close the connection: {e}\n")


# 6. Take in domain, return if webserver redirects to https
def is_redirect_to_https(domain):
    redirect_count = 0
    curr_domain = domain
    curr_path = "/"

    try:
        while redirect_count <= 10:
            conn = http.client.HTTPConnection(curr_domain, port=80, timeout=5)
            conn.request("GET", curr_path)
            response = conn.getresponse()

            if response.status in (301, 302, 303, 307, 308):
                location_header = response.getheader("Location")
                if location_header:
                    if location_header.startswith("https://"):
                        return True
                    elif location_header.startswith("http://"):
                        location_header = location_header[7:]
                        parts = location_header.split("/", 1)
                        curr_domain = parts[0]
                        curr_path = f"/{parts[1]}" if len(parts) > 1 else "/"
                    elif location_header.startswith("/"):
                        curr_path = location_header
                    else:
                        break

                    redirect_count += 1
                    conn.close()
                    continue
                else:
                    # no location header
                    break
            else:
                # no redirect
                break

        # hit redirect limit of 10
        return False
        
    except Exception as e:
        sys.stderr.write(f"Error while checking redirects for {domain}: {e}\n")
        return False
    finally:
        try:
            conn.close()
        except Exception as e:
            sys.stderr.write(f"Error: Failed to close the connection: {e}\n")

# 7. Take in domain, return whether website has enabled strict transport security
def has_hsts(domain):
    redirect_count = 0
    curr_domain = domain
    curr_path = "/"

    try:
        while redirect_count <= 10:
            conn = http.client.HTTPSConnection(curr_domain, timeout=5)
            conn.request("GET", curr_path)
            response = conn.getresponse()

            if response.status == 200:
                hsts_header = response.getheader("Strict-Transport-Security")
                return bool(hsts_header)
            
            elif response.status in (301, 302, 303, 307, 308):
                location_header = response.getheader("Location")
                if location_header:
                    if location_header.startswith("https://"):
                        location_header = location_header[8:]
                    elif location_header.startswith("http://"):
                        location_header = location_header[7:]
                    else:
                        curr_path = location_header
                        redirect_count += 1
                        conn.close()
                        continue

                    parts = location_header.split("/", 1)
                    curr_domain = parts[0]
                    curr_path = f"/{parts[1]}" if len(parts) > 1 else "/"
                    redirect_count += 1
                    conn.close()
                    continue
                else:
                    # no location header
                    break
            else:
                # no redirection
                break

        # hit redirect limit of 10
        return False
        
    except Exception as e:
        sys.stderr.write(f"Error while checking redirects for {domain}: {e}\n")
        return False
    finally:
        try:
            conn.close()
        except Exception as e:
            sys.stderr.write(f"Error: Failed to close the connection: {e}\n")

# 8. Take in domain, return list of all versions of \
# TLS/SSL supported by the server
def get_tls_versions(domain):
    tls_versions = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
    supported_tls_versions = set()

    try:
        result = subprocess.check_output(
                ["nmap", "--script", "ssl-enum-ciphers", '-p',
                '443', domain], 
                timeout=10, 
                stderr=subprocess.STDOUT
            ).decode("utf-8")
        
        for line in result.splitlines():
            line = line.lstrip('|').strip()
            for tls_version_option in tls_versions:
                if line.startswith(tls_version_option):
                    supported_tls_versions.add(tls_version_option)

        return list(supported_tls_versions)
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"Error: Timeout expired while probing TLS versions supported by domain {domain}.\n")
        return []
    except FileNotFoundError:
        sys.stderr.write(f"Error: 'nmap' is not installed or not found in PATH.\n")
        return None
    except Exception as e:
        sys.stderr.write(f"Unexpected error: {e}\n")
        return []
    
# 9. Take in domain, return root CA at the base of the chain of trust
# If domain does not support TLS, return null
def get_root_ca(domain):
    try:
        command = ["openssl", "s_client", "-connect", f"{domain}:443"]
        result = subprocess.check_output(
            command,
            input=b"",  # Simulate echo by providing an empty stdin input
            stderr=subprocess.STDOUT,
            timeout=10,
        ).decode("utf-8")

        root_ca = result.splitlines()[0].split("O = ")[1].split(",")[0]

        return root_ca
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"Error: Timeout expired while probing root CA of domain {domain}.\n")
        return []
    except FileNotFoundError:
        sys.stderr.write(f"Error: 'openssl' is not installed or not found in PATH.\n")
        return None
    except Exception as e:
        sys.stderr.write(f"Unexpected error: {e}\n")
        return []
    
# 10. Take in ipv4 addresses, then query ptr records
def get_rdns_names(ipv4_addresses):
    rdns_names = set()

    for address in ipv4_addresses:
        try:
            result = subprocess.check_output(
                ["nslookup", address], 
                timeout=3, 
                stderr=subprocess.STDOUT
            ).decode("utf-8")

            for line in result.splitlines():
                line = line.strip()
                if "name = " in line and "canonical name = " not in line:
                    rdns_name = line.split("name = ", 1)[-1].strip().rstrip('.')
                    rdns_names.add(rdns_name)

        except subprocess.TimeoutExpired as e:
            sys.stderr.write(f"Error: Timeout expired while probing rDNS of {address}.\n")
        except Exception as e:
            sys.stderr.write(f"Unexpected error: {e}\n")
    
    return list(rdns_names)

# 11. Take in list of IPv4 addresses, return a list of two numbers [min, max] rtt
def get_rtt_range(ipv4_addresses):
    minRtt = float('inf')
    maxRtt = float('-inf')

    for address in ipv4_addresses:
        try:
            command = [
                "sh", "-c",
                f"time echo -e '\\x1dclose\\x0d' | telnet {address} 443"
            ]

            result = subprocess.check_output(
                command,
                stderr=subprocess.STDOUT,  # Capture stderr in stdout
                timeout=10  
            ).decode("utf-8")

            for line in result.splitlines():
                if 'real' in line:
                    time_parts = line.split('\t')[1]
                    minutes, seconds = map(float, time_parts.replace('s', '').split('m'))
                    rtt_ms = int((minutes * 60 + seconds) * 1000)
                    minRtt = min(minRtt, rtt_ms)
                    maxRtt = max(maxRtt, rtt_ms)

        except subprocess.TimeoutExpired as e:
            sys.stderr.write(f"Error: Timeout expired while probing RTT for {address}.\n")
        except FileNotFoundError:
            sys.stderr.write(f"Error: 'telnet' is not installed or not found in PATH.\n")
            return None
        except Exception as e:
            sys.stderr.write(f"Unexpected error: {e}\n")
    
    return [minRtt, maxRtt]

# 12. Take in a list of IPv4 addresses, return list of 
# real world locations
def get_geo_locations(ipv4_addresses):
    locations = set()
    with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
        for address in ipv4_addresses:
            try:
                record = reader.get(address)
                city = record['city']['names']['en']
                country = record['country']['names']['en']
                state = record['subdivisions'][0]['names']['en']
                locations.add(f"{city}, {state}, {country}")
            except Exception as e:
                pass

    return list(locations)


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py [input_file.txt] [output_file.json]")
        sys.exit(1)

    input_filename = sys.argv[1]
    output_filename = sys.argv[2]
    if (not sys.argv[1].endswith(".txt")) or (not sys.argv[2].endswith(".json")):
        print("Usage: python3 scan.py [input_file.txt] [output_file.json]")
        sys.exit(1)

    public_dns_resolvers = get_public_dns_resolvers()
    json_object = {}

    with open(input_filename, "r") as file:
        for line in file:
            domain = line.strip()
            domain_info = {}
            scan_time = get_scan_time()
            if scan_time:
                domain_info["scan_time"] = scan_time

            ipv4_addresses = get_ipv4_addresses(domain, public_dns_resolvers)
            domain_info["ipv4_addresses"] = ipv4_addresses
            domain_info["ipv6_addresses"] = get_ipv6_addresses(domain, public_dns_resolvers)
            domain_info["http_server"] = get_http_server(domain)
            insecure_http = is_insecure_http(domain)
            if insecure_http is not None:
                domain_info["insecure_http"] = insecure_http
            domain_info["redirect_to_https"] = is_redirect_to_https(domain)
            domain_info["hsts"] = has_hsts(domain)
            tls_versions = get_tls_versions(domain)
            if tls_versions is not None:
                domain_info["tls_versions"] = tls_versions
            root_ca = get_root_ca(domain)
            if root_ca is not None:
                domain_info["root_ca"] = root_ca
            domain_info["rdns_names"] = get_rdns_names(ipv4_addresses)
            rtt_range = get_rtt_range(ipv4_addresses)
            if rtt_range is not None:
                domain_info["rtt_range"] = rtt_range
            domain_info["geo_locations"] = get_geo_locations(ipv4_addresses)

            json_object[domain] = domain_info
    
    try:
        with open(output_filename, "w") as f:
            json.dump(json_object, f, sort_keys=True, indent=4)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to write to {output_filename}: {e}")

    
if __name__ == "__main__":
    main()