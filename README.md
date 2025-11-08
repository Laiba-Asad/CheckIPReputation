Purpose

This script gives cybersecurity professionals, SOC analysts, devs, or anyone curious about IP threat levels a quick way to query the reputation of one or more IP addresses. It wraps the AbuseIPDB API and lets you get readable results from the command line or via a list file.

Key Features

⦁	Accepts one or multiple IPs (via command line or from a file)
⦁	Queries AbuseIPDB with your API key
⦁	Returns a summary of reports, threat score, last reported date, and more
⦁	Easy to plug into automation (e.g., in a SOC pipeline)
⦁	Lightweight, pure Python (no heavy dependencies)

Getting Started

Prerequisites

⦁	Python 3.x installed
⦁	An API key from AbuseIPDB (free tier available)
⦁	Internet connection for API queries
⦁	File ips.txt (optional) – list of IP addresses, one per line
