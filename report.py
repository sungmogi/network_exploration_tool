import json
from texttable import Texttable
import sys
from collections import Counter


# 1. Given dictionary of data, list all the information returned
def list_data(data):
    listing = ""
    for domain, information in data.items():
        listing += f"Domain: {domain}\n"
        for key, val in information.items():
            listing += f"    {key.capitalize().replace('_', ' ')}: {val}\n"

    return listing

# 2. Given dictionary of data, generate table showing the RTT ranges 
# for all domains, sorted by the minimum RTT
def show_rtt(data):
    rtt_list = [(domain, data[domain]['rtt_range']) for domain in data.keys()]
    rtt_list = sorted(rtt_list, key=lambda x: x[1][0])

    table = Texttable()

    table.header(["Domain", "Min RTT", "Max RTT"])

    for domain, rtts in rtt_list:
        table.add_row([domain, rtts[0], rtts[1]])

    return table.draw()

# 3. Given dictionary of data, generate table showing the number of 
# occurrences for each observed root CA
def show_root_cas(data):
    root_ca_count = Counter()
    for domain, information in data.items():
        root_ca = information.get('root_ca')
        root_ca_count[root_ca] += 1

    root_cas = sorted([(ca, count) for ca, count in root_ca_count.items()], key=lambda x:x[1], reverse=True)

    table = Texttable()

    table.header(["Root CA", "Occurrence"])

    for ca, count in root_cas:
        table.add_row([ca, count])

    return table.draw()

# 4. Given dictionary of data, generate table showing the number of
# occurrences of each web server, ordered from most popular to least
def show_http_servers(data):
    http_server_count = Counter()
    for domain, information in data.items():
        http_server = information.get('http_server')
        http_server_count[http_server] += 1

    http_servers = sorted([(server, count) for server, count in http_server_count.items()], key=lambda x:x[1], reverse=True)

    table = Texttable()

    table.header(["HTTP Server", "Occurrence"])

    for server, count in http_servers:
        table.add_row([server, count])

    return table.draw()

# 5. Given dictionary of data, generate table showing the percentage of 
# scanned domains supporting SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3,
# Plain HTTP, HTTPS redirect, hsts, IPv6
def show_supported_features(data):
    domain_count = 0
    sslv2_count = 0
    sslv3_count = 0
    tlsv1_0_count = 0
    tlsv1_1_count = 0
    tlsv1_2_count = 0
    tlsv1_3_count = 0
    plain_http_count = 0
    https_redirect_count = 0
    hsts_count = 0
    ipv6_count = 0
    for domain, information in data.items():
        domain_count += 1
        if "SSLv2" in information.get('tls_versions'):
            sslv2_count += 1
        if "SSLv3" in information.get('tls_versions'):
            sslv3_count += 1
        if "TLSv1.0" in information.get('tls_versions'):
            tlsv1_0_count += 1
        if "TLSv1.1" in information.get('tls_versions'):
            tlsv1_1_count += 1
        if "TLSv1.2" in information.get('tls_versions'):
            tlsv1_2_count += 1
        if "TLSv1.3" in information.get('tls_versions'):
            tlsv1_3_count += 1
        if information.get('insecure_http') is True:
            plain_http_count += 1
        if information.get('redirect_to_https') is True:
            https_redirect_count += 1
        if information.get('hsts') is True:
            hsts_count += 1
        if len(information.get('ipv6_addresses')) > 0:
            ipv6_count += 1

    table = Texttable()

    table.header(["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", 
                  "TLSv1.3", "Plain HTTP", "HTTPS Redirect", "HSTS", "IPv6"])

    table.add_row([
        f"{sslv2_count / domain_count * 100:.2f}%",
        f"{sslv3_count / domain_count * 100:.2f}%",
        f"{tlsv1_0_count / domain_count * 100:.2f}%",
        f"{tlsv1_1_count / domain_count * 100:.2f}%",
        f"{tlsv1_2_count / domain_count * 100:.2f}%",
        f"{tlsv1_3_count / domain_count * 100:.2f}%",
        f"{plain_http_count / domain_count * 100:.2f}%",
        f"{https_redirect_count / domain_count * 100:.2f}%",
        f"{hsts_count / domain_count * 100:.2f}%",
        f"{ipv6_count / domain_count * 100:.2f}%"
        ])

    return table.draw()
        
        

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 report.py [input_file.json] [output_file.txt]")
        sys.exit(1)

    input_filename = sys.argv[1]
    output_filename = sys.argv[2]
    if (not sys.argv[1].endswith(".json")) or (not sys.argv[2].endswith(".txt")):
        print("Usage: python3 report.py [input_file.json] [output_file.txt]")
        sys.exit(1)

    try: 
        with open(input_filename, "r") as file:
            data = json.load(file)
        
        all_data = list_data(data)
        rtt_data = show_rtt(data)
        root_ca_data = show_root_cas(data)
        http_server_data = show_http_servers(data)
        supported_features_data = show_supported_features(data)

        with open(output_filename, "w") as file:
                file.write("Domain Data:\n")
                file.write(all_data + "\n\n")
                
                file.write("RTTs:\n")
                file.write(rtt_data + "\n\n")
                
                file.write("Root CAs:\n")
                file.write(root_ca_data + "\n\n")
                
                file.write("HTTP Servers:\n")
                file.write(http_server_data + "\n\n")
                
                file.write("Features Supported by Webservers:\n")
                file.write(supported_features_data + "\n\n")
    except FileNotFoundError:
        sys.stderr.write(f"Error: File {input_filename} not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        sys.stderr.write(f"Error: File {input_filename} is not a valid JSON file.")
        sys.exit(1)

if __name__ == "__main__":
    main()