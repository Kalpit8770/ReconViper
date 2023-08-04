import logging
import whois
import dns.resolver
import requests
import argparse
import socket
import shodan
import json
import pprint

arg_parser = argparse.ArgumentParser(description="This information Gathering Tool.", usage="python3 info_gather.py -d DOMAIN [-s IP]")
arg_parser.add_argument("-d", "--domain", help="Enter Domain Name For Footprinting.", required=True)
arg_parser.add_argument("-s", "--shodan", help="Enter IP For Shodan search.")
arg_parser.add_argument("-a", "--api_key", help="Shodan API key.", required=True)

args = arg_parser.parse_args()
domain = args.domain
ip = args.shodan
shodan_api_key = args.api_key
# Setting up logging to save output to a file
logging.basicConfig(
    filename=domain + "_info.log",
    filemode="w",
    format="[%(asctime)s] - %(levelname)s: %(message)s",
    level=logging.INFO,)


# WHOIS module
logging.info("[+] Getting WHOIS information")
try:
    whois_info = whois.whois(domain)
    if whois_info:
        logging.info("Name: {}".format(whois_info.get('name')))
        logging.info("Registrar: {}".format(whois_info.get('registrar')))
        logging.info("Creation Date: {}".format(whois_info.get('creation_date')))
        logging.info("Expiration Date: {}".format(whois_info.get('expiration_date')))
        logging.info("Registrant: {}".format(whois_info.get('registrant')))
        logging.info("Registrant Country: {}".format(whois_info.get('registrant_country')))
    else:
        logging.warning("Failed to retrieve WHOIS information for the domain.")
except Exception as e:
    logging.error("An error occurred while querying WHOIS: {}".format(str(e)))
    # You can handle the error here as needed.

print("[+] Getting DNS Information")
logging.info("[+] Getting DNS Information")
# Setting up dns.resolver from dnspython
try:
    # A record
    for a in dns.resolver.resolve(domain, 'A'):
        print("[+] A record: {}".format(a.to_text()))
        logging.info("[+] A record: {}".format(a.to_text()))

    # NS record
    for ns in dns.resolver.resolve(domain, 'NS'):
        print("[+] NS record: {}".format(ns.to_text()))
        logging.info("[+] NS record: {}".format(ns.to_text()))

    # MX record
    for mx in dns.resolver.resolve(domain, 'MX'):
        print("[+] MX record: {}".format(mx.to_text()))
        logging.info("[+] MX record: {}".format(mx.to_text()))

    # TXT record
    for txt in dns.resolver.resolve(domain, 'TXT'):
        print("[+] TXT record: {}".format(txt.to_text()))
        logging.info("[+] TXT record: {}".format(txt.to_text()))
except dns.resolver.NXDOMAIN:
    print("The domain does not exist.")
    logging.warning("The domain does not exist.")
except dns.resolver.NoAnswer:
    print("No DNS records found for the domain.")
    logging.warning("No DNS records found for the domain.")
except dns.exception.DNSException as e:
    print("An error occurred while querying DNS: {}".format(str(e)))
    logging.error("An error occurred while querying DNS: {}".format(str(e)))

# Geolocation Module
logging.info("[+] Getting Geolocation information")
print("[+] Getting Geolocation information")

try:
    # Organizing request for web request
    response = requests.get("https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    print("[+] Country: {}".format(response['country_name']))
    logging.info("[+] Country: {}".format(response['country_name']))
    print("[+] Latitude: {}".format(response['latitude']))
    logging.info("[+] Latitude: {}".format(response['latitude']))
    print("[+] Longitude: {}".format(response['longitude']))
    logging.info("[+] Longitude: {}".format(response['longitude']))
    print("[+] City: {}".format(response['city']))
    logging.info("[+] City: {}".format(response['city']))
    print("[+] State: {}".format(response['state']))
    logging.info("[+] State: {}".format(response['state']))
except Exception as e:
    print("An error occurred while querying geolocation API: {}".format(str(e)))
    logging.error("An error occurred while querying geolocation API: {}".format(str(e)))

# Shodan module
ip = socket.gethostbyname(domain)
if ip:
    print("[+] Getting info from Shodan For IP {}".format(ip))
    logging.info("[+] Getting info from Shodan For IP {}".format(ip))
    # Shodan API key
    api = shodan.Shodan(shodan_api_key)

    try:
        results = api.host(ip)
        print(type(results))
        # rs = json.dumps(results, indent=4)
        # print(rs)
        with open(f"{domain}-log.json", 'w') as file :
            json.dump(results, file, indent=4)
            
        # print("[+] Results found: {}".format(results['total']))
        # logging.info("[+] Results found: {}".format(results['total']))
        # for result in results['matches']:
        print("[+] IP: {}".format(results['ip_str']))
        logging.info("[+] IP: {}".format(results['ip_str']))
        print("[+] Data:\n{}".format(results['data']))
        logging.info("[+] Data:\n{}".format(results['data']))
        print("[+] city:\n{}".format(results['city']))
        logging.info("[+] city:\n{}".format(results['city']))
        print("[+] Data:\n{}".format(results['latitude']))
        logging.info("[+] Data:\n{}".format(results['latitude']))
        print()
        results['data'][0]['http']['status']
        results['ports']

    except shodan.APIError as e:
        print("[-] Shodan Search error: {}".format(e))
        logging.error("[-] Shodan Search error: {}".format(e))
else:
    print("[-] No IP provided for Shodan search.")
    logging.warning("[-] No IP provided for Shodan search.")