# network_exploration_tool

## Introduction
This is a network exploration tool that which takes in a list of domains to probe and returns their network characteristics and security features, including their
1. IPv4 addresses
2. IPv6 addresses
3. HTTP server
4. Whether the server listens on port 80
5. Whether the server redirects to HTTPS
6. Whether the server has enabled strict transport security
7. Supported SSL/TLS versions
8. Root CA at the base of the chain of trust
9. Pointer records
10. Round-trip times for different instances of the server
11. Real-world locations of different instances of the server

## Usage

### Installing necessary packages
Install maxminddb and texttable:
```
pip install -r requirements.txt
```

### scan.py
scan.py takes in a .txt file with a list of domains and returns their network characteristics in JSON format.
Run scan.py like so:
```
python3 scan.py [input_file.txt] [output_file.json]
```
output_file.json will then be generated in a similar format as this:
```
{
    "amazon.com": {
        "geo_locations": [
            "Ashburn, Virginia, United States"
        ],
        "hsts": true,
        "http_server": "Server",
        "insecure_http": true,
        "ipv4_addresses": [
            "205.251.242.103",
            "52.94.236.248",
            "54.239.28.85"
        ],
        "ipv6_addresses": [],
        "rdns_names": [
            "s3-console-us-standard.console.aws.amazon.com"
        ],
        "redirect_to_https": true,
        "root_ca": "DigiCert Inc",
        "rtt_range": [
            19,
            21
        ],
        "scan_time": 1733114254.0878787,
        "tls_versions": [
            "TLSv1.1",
            "TLSv1.2",
            "TLSv1.3",
            "TLSv1.0"
        ]
    },
}
```
You can check out scan_out.json to see how an example output might look. 

### report.py
report.py takes in the JSON file generated from scan.py and formats the information in a pretty way. It lists the information in plain text, then uses the texttable package to generate tables containing information such as common root CAs, HTTP servers, and TLS versions supported by servers. 
```
python3 report.py [input_file.json] [output_file.txt]
```
You can check out report_out.txt for an example.
