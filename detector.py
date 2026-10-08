#!/usr/bin/env python3
"""SSH Brute-Force Detector: flags IPs with repeated failed logins in an auth log."""
import argparse
import json
import re
from collections import Counter, defaultdict

FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse(path):
    attempts = Counter()
    users = defaultdict(set)
    with open(path, errors="ignore") as f:
        for line in f:
            m = FAILED.search(line)
            if m:
                attempts[m["ip"]] += 1
                users[m["ip"]].add(m["user"])
    return attempts, users


def main():
    ap = argparse.ArgumentParser(description="Detect SSH brute-force attempts")
    ap.add_argument("logfile", help="path to auth.log or secure log")
    ap.add_argument("-t", "--threshold", type=int, default=5,
                    help="failed attempts before an IP is flagged (default 5)")
    ap.add_argument("--json", action="store_true", help="output JSON")
    args = ap.parse_args()

    attempts, users = parse(args.logfile)
    flagged = [
        {"ip": ip, "failed_attempts": n, "usernames_tried": sorted(users[ip])}
        for ip, n in attempts.most_common() if n >= args.threshold
    ]

    if args.json:
        print(json.dumps(flagged, indent=2))
    elif not flagged:
        print("No suspicious IPs found.")
    else:
        print(f"{'IP':<18}{'FAILED':<10}USERS TRIED")
        for r in flagged:
            print(f"{r['ip']:<18}{r['failed_attempts']:<10}{', '.join(r['usernames_tried'][:5])}")


if __name__ == "__main__":
    main()
