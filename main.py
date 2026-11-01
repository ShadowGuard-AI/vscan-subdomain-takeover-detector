import argparse
import logging
import requests
import sys
from bs4 import BeautifulSoup

try:
    import dns.resolver
    import dns.exception
except ImportError:
    dns = None

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

def check_s3_bucket(target):
    """
    Checks the S3 host named by the CNAME target. The target already
    names the service host, so no suffix is built from the supplied domain.
    Returns True, False, or None when the check could not be carried out.
    """
    url = f"http://{target}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 404 and "NoSuchBucket" in response.text:
            logging.warning(f"[POTENTIAL TAKEOVER] S3 Bucket {target} not found or not accessible. Potential takeover: {url}")
            return True
        elif response.status_code == 403 and "AccessDenied" in response.text:
            logging.info(f"S3 Bucket {target} exists but access is denied. Investigate manually.")
            return False
        else:
            logging.debug(f"S3 Bucket {target}: Status Code {response.status_code}, Marker: NoSuchBucket not matched")
            return False
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error checking S3 Bucket {target}: {e}")
        return None

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
            logging.debug(f"Github Pages {domain}: Status Code {response.status_code}, Marker: GitHub Pages missing site text not matched")
            return False
        else:
             logging.debug(f"Github Pages {domain}: Status Code {response.status_code}, Marker: GitHub Pages missing site text not matched")
             return False
    except requests.exceptions.RequestException as e:
        logging.debug(f"Error checking Github Pages {domain}: {e}")
        return None

def check_azure_storage(target):
    """
    Checks the Azure host named by the CNAME target. Returns True, False,
    or None when the check could not be carried out.
    """
    url = f"http://{target}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 404:
            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.find("Code", text="ResourceNotFound"):
                logging.warning(f"[POTENTIAL TAKEOVER] Azure Storage account {target} not found. Potential takeover: {url}")
                return True
            logging.debug(f"Azure Storage {target}: Status Code {response.status_code}, Marker: ResourceNotFound not matched")
            return False
        else:
            logging.debug(f"Azure Storage {target}: Status Code {response.status_code}, Marker: ResourceNotFound not matched")
            return False

    except requests.exceptions.RequestException as e:
        logging.debug(f"Error checking Azure Storage {target}: {e}")
        return None


def resolve_cname(domain):
    """
    Performs a real DNS CNAME lookup with dnspython. Returns the CNAME
    target, or None when the name has no CNAME record. A name is never
    treated as its own CNAME. Raises RuntimeError when the lookup itself
    could not be carried out.
    """
    if dns is None:
        raise RuntimeError("dnspython is not installed, so no CNAME lookup can be performed")
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except Exception as e:
        raise RuntimeError(f"CNAME lookup failed for {domain}: {e}")
    for answer in answers:
        target = str(answer.target).rstrip(".")
        if target and target.lower() != domain.lower():
            return target
        return None
    return None

def check_subdomain_takeover(domain):
     """
     Orchestrates the subdomain takeover checks for various services.
     """
     cname = resolve_cname(domain)

     if cname:
         logging.info(f"CNAME record found: {domain} -> {cname}")
         if "s3.amazonaws.com" in cname:
             return check_s3_bucket(cname)
         elif "github.io" in cname:
             return check_github_pages(domain)
         elif "blob.core.windows.net" in cname:
             return check_azure_storage(cname)
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
        sys.exit(1)

    logging.info(f"Starting subdomain takeover scan for: {domain_to_scan}")

    try:
        takeover_vulnerable = check_subdomain_takeover(domain_to_scan)

        if takeover_vulnerable is None:
            logging.error(f"Subdomain takeover scan inconclusive for: {domain_to_scan}: a check could not be carried out.")
            sys.exit(1)

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

    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

    logging.info("Subdomain takeover scan complete.")


if __name__ == "__main__":
    main()