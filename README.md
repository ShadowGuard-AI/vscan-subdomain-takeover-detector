# vscan-subdomain-takeover-detector
Identifies potential subdomain takeover vulnerabilities by checking if DNS records (CNAME, A records) point to services that are no longer active or claimed by the target. Checks common cloud services like AWS S3 buckets, Azure Storage accounts, and Github Pages. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-subdomain-takeover-detector`

## Usage
`./vscan-subdomain-takeover-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose output.
- `-o`: Output file to save results.

## License
Copyright (c) ShadowStrikeHQ
