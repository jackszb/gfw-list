#!/usr/bin/env python3
"""
Download gfwlist.txt, parse it and generate a sing-box rule-set source file
(rules/gfw.json) containing all extracted domains as domain_suffix rules.
"""
import base64
import json
import re
import sys
import urllib.request

GFWLIST_URL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
OUTPUT_PATH = "rules/gfw.json"

DOMAIN_RE = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$'
)


def is_ip(s: str) -> bool:
    parts = s.split('.')
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def fetch_gfwlist(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "gfwlist-updater"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
    return base64.b64decode(raw).decode('utf-8', errors='ignore')


def extract_domains(content: str) -> set:
    domains = set()

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        # comments / header
        if line.startswith('!') or line.startswith('['):
            continue
        # whitelist rules (@@) are exceptions, not something that needs proxying
        if line.startswith('@@'):
            continue
        # pure regex rules (/.../) are not reliably convertible to a domain
        if line.startswith('/') and line.endswith('/'):
            continue

        # strip adblock option modifiers, e.g. "||example.com$important"
        if '$' in line:
            line = line.split('$', 1)[0]

        if line.startswith('||'):
            domain = line[2:]
        elif line.startswith('|https://'):
            domain = line[9:]
        elif line.startswith('|http://'):
            domain = line[8:]
        elif line.startswith('https://'):
            domain = line[8:]
        elif line.startswith('http://'):
            domain = line[7:]
        elif line.startswith('.'):
            domain = line[1:]
        elif line.startswith('|'):
            domain = line[1:]
        else:
            domain = line

        # drop path / query
        domain = domain.split('/')[0].split('?')[0]
        # drop port
        domain = domain.split(':')[0]

        if domain.startswith('*.'):
            domain = domain[2:]
        domain = domain.strip('*').strip('.')

        if not domain or is_ip(domain):
            continue
        if not DOMAIN_RE.match(domain):
            continue

        domains.add(domain.lower())

    return domains


def main():
    try:
        content = fetch_gfwlist(GFWLIST_URL)
    except Exception as exc:
        print(f"Failed to fetch gfwlist: {exc}", file=sys.stderr)
        sys.exit(1)

    domains = extract_domains(content)
    if len(domains) < 100:
        # sanity check: gfwlist normally has thousands of entries
        print(f"Suspiciously few domains extracted ({len(domains)}), aborting.", file=sys.stderr)
        sys.exit(1)

    rule_set = {
        "version": 3,
        "rules": [
            {
                "domain_suffix": sorted(domains)
            }
        ]
    }

    import os
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(rule_set, f, ensure_ascii=False, indent=2)
        f.write('\n')

    print(f"Wrote {len(domains)} domains to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
