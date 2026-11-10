# vscan-subdomain-takeover-detector
Identifies potential subdomain takeover vulnerabilities by checking if a DNS CNAME record points to a service that are no longer active or claimed by the target. Checks common cloud services like AWS S3 buckets, Azure Storage accounts, and Github Pages. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuard-AI/vscan-subdomain-takeover-detector`

## Usage
`python3 main.py example.com [-v] [-o results.txt]`

The output file, when given, is overwritten on each run that finds a vulnerability, so it never accumulates stale lines from earlier runs. Requires dnspython for the CNAME lookup; without it the scan ends as inconclusive instead of guessing.

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose output.
- `-o`: Output file to save results (overwritten when a finding is written).

## License
MIT License (see LICENSE)
