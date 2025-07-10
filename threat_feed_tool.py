#!/usr/bin/env python3

import argparse
import requests
import json
import sys
from datetime import datetime

THREAT_FEED_FILE = "threat_feed.json"

# Dummy threat feed URLs (you can replace/add actual feeds)
THREAT_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "https://blocklistproject.github.io/Lists/alt-version/all-ip.json"
]

def fetch_feeds():
    collected_data = {"feeds": [], "fetched_at": datetime.utcnow().isoformat()}

    print("[+] Fetching threat feeds...")
    for url in THREAT_FEEDS:
        try:
            print(f"    - Fetching from: {url}")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                feed_data = response.json()
                collected_data["feeds"].append({"url": url, "data": feed_data})
                print("      ✔ Success")
            else:
                print(f"      ✖ Failed (Status: {response.status_code})")
        except Exception as e:
            print(f"      ✖ Error fetching {url}: {e}")

    with open(THREAT_FEED_FILE, "w") as f:
        json.dump(collected_data, f, indent=2)
    print(f"[+] Threat feeds saved to {THREAT_FEED_FILE}")

def search_threat(indicator):
    try:
        with open(THREAT_FEED_FILE, "r") as f:
            feed_data = json.load(f)
    except FileNotFoundError:
        print("[!] Threat feed file not found. Run with --fetch first.")
        return

    print(f"[+] Searching for indicator: {indicator}")
    found = False

    for feed in feed_data.get("feeds", []):
        data = json.dumps(feed["data"])
        if indicator in data:
            print(f"[!] Indicator found in feed: {feed['url']}")
            found = True

    if not found:
        print("[+] Indicator not found in any feed.")

def view_feed():
    try:
        with open(THREAT_FEED_FILE, "r") as f:
            feed_data = json.load(f)
        print(json.dumps(feed_data, indent=2))
    except FileNotFoundError:
        print("[!] No threat feed file found. Run with --fetch first.")

def main():
    parser = argparse.ArgumentParser(description="DefenseOps Threat Feed Tool")
    parser.add_argument("--fetch", action="store_true", help="Fetch latest threat feeds")
    parser.add_argument("--search", metavar="INDICATOR", help="Search for an indicator in feeds")
    parser.add_argument("--view", action="store_true", help="View cached threat feeds")
    args = parser.parse_args()

    if args.fetch:
        fetch_feeds()
    elif args.search:
        search_threat(args.search)
    elif args.view:
        view_feed()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
