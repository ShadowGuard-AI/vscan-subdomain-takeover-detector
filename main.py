import argparse
import logging
import requests
import socket
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Detect potential subdomain takeover vulnerabilities.")
    parser.add_argument("domain", help="The domain to scan for subdomain takeovers.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("-o", "--output", help="Output file to save results.")
    return parser

def check_s3_bucket(domain):
    """
    Checks if a CNAME record points to an inactive AWS S3 bucket.
    """
    try:
        response = requests.get(f"http://{domain}.s3.amazonaws.com", timeout=5)
        if response.status_code == 404 and "NoSuchBucket" in response.text:
            logging.warning(f"[POTENTIAL TAKEOVER] S3 Bucket {domain} not found or not accessible. Potential takeover: http://{domain}.s3.amazonaws.com")
            return True
        elif response.status_code == 403 and "AccessDenied" in response.text:
            logging.info(f"S3 Bucket {domain} exists but access is denied. Investigate manually.")
            return False
        else:
            logging.debug(f"S3 Bucket {domain}: Status Code {response.status_code}, Text: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error checking S3 Bucket {domain}: {e}")
        return False

def check_github_pages(domain):
    """
    Checks if a CNAME record points to an inactive Github Pages site.
    """
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        if response.status_code == 404:
            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.find(string=lambda text: "There isn't a GitHub Pages site here." in text if text else False): # Handle NoneType text
                logging.warning(f"[POTENTIAL TAKEOVER] GitHub Pages site {domain} not found. Potential takeover: http://{domain}")
                return True
        else:
             logging.debug(f"Github Pages {domain}: Status Code {response.status_code}, Text: {response.text}")
             return False
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error checking Github Pages {domain}: {e}")
        return False

def check_azure_storage(domain):
    """
    Checks if a CNAME record points to an inactive Azure Storage account.
    """
    try:
        response = requests.get(f"http://{domain}.blob.core.windows.net", timeout=5)
        if response.status_code == 404:
            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.find("Code", text="ResourceNotFound"): # Check specifically for ResourceNotFound
                logging.warning(f"[POTENTIAL TAKEOVER] Azure Storage account {domain} not found. Potential takeover: http://{domain}.blob.core.windows.net")
                return True
        else:
            logging.debug(f"Azure Storage {domain}: Status Code {response.status_code}, Text: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        logging.debug(f"Error checking Azure Storage {domain}: {e}")
        return False


def resolve_cname(domain):
    """
    Resolves a CNAME record for a given domain. Returns None if no CNAME record is found.
    """
    try:
        cname = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, socket.AI_CANONNAME)[0][3]
        return cname
    except socket.gaierror:
        return None

def check_subdomain_takeover(domain):
     """
     Orchestrates the subdomain takeover checks for various services.
     """
     cname = resolve_cname(domain)

     if cname:
         logging.info(f"CNAME record found: {domain} -> {cname}")
         if "s3.amazonaws.com" in cname:
             return check_s3_bucket(domain)
         elif "github.io" in cname:
             return check_github_pages(domain)
         elif "blob.core.windows.net" in cname:
             return check_azure_storage(domain)
         else:
             logging.info(f"CNAME record points to an unsupported service: {cname}")
             return False
     else:
         logging.info(f"No CNAME record found for {domain}")
         return False

def main():
    """
    Main function to execute the subdomain takeover detector.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    domain_to_scan = args.domain

    if not domain_to_scan:
        logging.error("Please provide a domain to scan.")
        return

    logging.info(f"Starting subdomain takeover scan for: {domain_to_scan}")

    try:
        takeover_vulnerable = check_subdomain_takeover(domain_to_scan)

        if takeover_vulnerable:
            logging.info(f"Potential subdomain takeover vulnerability found for: {domain_to_scan}")
            if args.output:
                try:
                    with open(args.output, "a") as f:
                        f.write(f"Potential subdomain takeover vulnerability found for: {domain_to_scan}\n")
                except Exception as e:
                    logging.error(f"Error writing to output file: {e}")

        else:
            logging.info(f"No subdomain takeover vulnerability found for: {domain_to_scan}")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

    logging.info("Subdomain takeover scan complete.")


if __name__ == "__main__":
    main()