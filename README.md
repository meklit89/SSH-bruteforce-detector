# SSH Brute-Force Detector

A lightweight Python tool that parses Linux SSH authentication logs and flags IP addresses showing brute-force behavior.

## Features
- Parses `auth.log` / `secure` for failed SSH logins
- Flags IPs above a configurable attempt threshold
- Shows which usernames each attacker tried
- Table or JSON output (easy to feed into a SIEM or firewall script)

## Usage
```bash
python3 detector.py /var/log/auth.log
python3 detector.py /var/log/auth.log -t 10 --json
```

## Example output
```
IP                FAILED    USERS TRIED
203.0.113.45      87        root, admin, ubuntu
198.51.100.7      12        test, oracle
```

## How it works
Matches `Failed password for ... from <ip>` lines with a regex, counts attempts per source IP, and reports those over the threshold.

## Roadmap
- [ ] Time-window detection (N failures within M minutes)
- [ ] GeoIP lookup for flagged IPs
- [ ] Auto-generate `iptables`/`ufw` block rules
- [ ] Email/Telegram alerts
- [ ] Unit tests with sample logs

## Defensive use only
Run this only on systems and logs you own or are authorized to analyze.

## License
MIT
