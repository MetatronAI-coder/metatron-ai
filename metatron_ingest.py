#!/usr/bin/env python3
"""
PRISTINE — Threat Intelligence Ingest Script v1.0
Free, open-source threat intelligence pipeline (Metatron AI framework).
Pulls CISA KEV + abuse.ch feeds into local SQLite (zero config).

Usage:
  python3 metatron_ingest.py --once
  python3 metatron_ingest.py --loop 3600

Optional: set your own free abuse.ch key
  export ABUSECH_AUTH_KEY="your-key-here"
  Get free key at: https://auth.abuse.ch/
"""

import argparse
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

DB_PATH = Path(__file__).parent / "metatron_intel.db"
USER_AGENT = "PRISTINE/1.0 (Metatron AI non-profit; metatronai@icloud.com)"
ABUSECH_KEY = os.environ.get("ABUSECH_AUTH_KEY", "")

FEEDS = {
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "parser": "kev",
    },
    "urlhaus_recent": {
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "parser": "urlhaus",
        "method": "GET",
        "auth": True,
    },
    "threatfox_recent": {
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "parser": "threatfox",
        "method": "POST",
        "body": {"query": "get_iocs", "days": 1},
        "auth": True,
    },
    "feodo_ipblocklist": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "parser": "feodo",
    },
}

def init_db(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        last_pull TEXT,
        status TEXT,
        records INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_type TEXT NOT NULL,
        value TEXT NOT NULL,
        source TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        confidence REAL DEFAULT 0.7,
        tags TEXT,
        raw TEXT,
        provenance TEXT,
        UNIQUE(ioc_type, value, source)
    );
    CREATE TABLE IF NOT EXISTS kev (
        cve_id TEXT PRIMARY KEY,
        vendor_project TEXT,
        product TEXT,
        vulnerability_name TEXT,
        date_added TEXT,
        short_description TEXT,
        required_action TEXT,
        due_date TEXT,
        known_ransomware TEXT,
        notes TEXT,
        raw TEXT,
        ingested_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
    CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(ioc_type);
    """)
    conn.commit()

def upsert_source(conn, name, status, records):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT INTO sources (name, last_pull, status, records)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            last_pull=excluded.last_pull, status=excluded.status, records=excluded.records
    """, (name, now, status, records))
    conn.commit()

def fetch(url, method="GET", body=None, auth=False):
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if auth and ABUSECH_KEY:
        headers["Auth-Key"] = ABUSECH_KEY
    data = None
    if method == "POST":
        data = json.dumps(body or {}).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=45) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            if content.strip().startswith(("{", "[")):
                return json.loads(content)
            return content
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def parse_kev(data, conn):
    if not data or "vulnerabilities" not in data:
        return 0
    count = 0
    now = datetime.now(timezone.utc).isoformat()
    for vuln in data["vulnerabilities"]:
        cve = vuln.get("cveID")
        if not cve:
            continue
        conn.execute("""
            INSERT INTO kev (cve_id, vendor_project, product, vulnerability_name,
                date_added, short_description, required_action, due_date,
                known_ransomware, notes, raw, ingested_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET ingested_at=excluded.ingested_at, raw=excluded.raw
        """, (cve, vuln.get("vendorProject"), vuln.get("product"), vuln.get("vulnerabilityName"),
              vuln.get("dateAdded"), vuln.get("shortDescription"), vuln.get("requiredAction"),
              vuln.get("dueDate"), vuln.get("knownRansomwareCampaignUse"), vuln.get("notes"),
              json.dumps(vuln), now))
        conn.execute("""
            INSERT INTO indicators (ioc_type, value, source, first_seen, last_seen, confidence, tags, raw, provenance)
            VALUES ('cve', ?, 'cisa_kev', ?, ?, 0.95, ?, ?, ?)
            ON CONFLICT(ioc_type, value, source) DO UPDATE SET last_seen=excluded.last_seen
        """, (cve, now, now, json.dumps(["kev"]), json.dumps(vuln), f"cisa_kev|{now}"))
        count += 1
    conn.commit()
    return count

def parse_urlhaus(data, conn):
    urls = data.get("urls") if isinstance(data, dict) else data
    if not urls:
        return 0
    count = 0
    now = datetime.now(timezone.utc).isoformat()
    for item in urls:
        url_val = item.get("url")
        if not url_val:
            continue
        conn.execute("""
            INSERT INTO indicators (ioc_type, value, source, first_seen, last_seen, confidence, tags, raw, provenance)
            VALUES ('url', ?, 'urlhaus', ?, ?, 0.85, ?, ?, ?)
            ON CONFLICT(ioc_type, value, source) DO UPDATE SET last_seen=excluded.last_seen
        """, (url_val, item.get("date_added") or now, now, json.dumps(item.get("tags") or []), json.dumps(item), f"urlhaus|{now}"))
        count += 1
    conn.commit()
    return count

def parse_threatfox(data, conn):
    if not data or data.get("query_status") != "ok":
        return 0
    iocs = data.get("data") or []
    count = 0
    now = datetime.now(timezone.utc).isoformat()
    for item in iocs:
        ioc = item.get("ioc")
        if not ioc:
            continue
        ioc_type = item.get("ioc_type", "unknown").lower()
        if "ip" in ioc_type:
            ioc_type = "ip"
        elif "hash" in ioc_type or ioc_type in ("md5", "sha1", "sha256"):
            ioc_type = "hash"
        conn.execute("""
            INSERT INTO indicators (ioc_type, value, source, first_seen, last_seen, confidence, tags, raw, provenance)
            VALUES (?, ?, 'threatfox', ?, ?, 0.9, ?, ?, ?)
            ON CONFLICT(ioc_type, value, source) DO UPDATE SET last_seen=excluded.last_seen
        """, (ioc_type, ioc, item.get("first_seen") or now, now, json.dumps([item.get("malware") or ""]), json.dumps(item), f"threatfox|{now}"))
        count += 1
    conn.commit()
    return count

def parse_feodo(data, conn):
    if not data or not isinstance(data, list):
        return 0
    count = 0
    now = datetime.now(timezone.utc).isoformat()
    for item in data:
        ip = item.get("ip_address") or item.get("ip")
        if not ip:
            continue
        conn.execute("""
            INSERT INTO indicators (ioc_type, value, source, first_seen, last_seen, confidence, tags, raw, provenance)
            VALUES ('ip', ?, 'feodo', ?, ?, 0.9, ?, ?, ?)
            ON CONFLICT(ioc_type, value, source) DO UPDATE SET last_seen=excluded.last_seen
        """, (ip, item.get("first_seen") or now, now, json.dumps([item.get("malware") or ""]), json.dumps(item), f"feodo|{now}"))
        count += 1
    conn.commit()
    return count

PARSERS = {
    "kev": parse_kev,
    "urlhaus": parse_urlhaus,
    "threatfox": parse_threatfox,
    "feodo": parse_feodo,
}

def run_once(conn):
    print(f"[*] Metatron ingest starting — {datetime.now(timezone.utc).isoformat()}")
    total = 0
    for name, cfg in FEEDS.items():
        print(f"  → Pulling {name} ...", end=" ", flush=True)
        raw = fetch(cfg["url"], method=cfg.get("method", "GET"), body=cfg.get("body"), auth=cfg.get("auth", False))
        if raw is None:
            upsert_source(conn, name, "error", 0)
            print("FAILED")
            continue
        try:
            count = PARSERS[cfg["parser"]](raw, conn)
            upsert_source(conn, name, "ok", count)
            print(f"OK ({count} records)")
            total += count
        except Exception as e:
            upsert_source(conn, name, f"error: {e}", 0)
            print(f"PARSE ERROR: {e}")
    print(f"[+] Cycle complete. Total new/updated: {total}")
    print(f"[+] Indicators in DB: {conn.execute('SELECT COUNT(*) FROM indicators').fetchone()[0]}")
    print(f"[+] KEV entries: {conn.execute('SELECT COUNT(*) FROM kev').fetchone()[0]}")

def main():
    parser = argparse.ArgumentParser(description="PRISTINE — Threat Intelligence Ingest (Metatron AI)")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--loop", type=int, default=0)
    args = parser.parse_args()
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    if args.loop > 0:
        while True:
            run_once(conn)
            time.sleep(args.loop)
    else:
        run_once(conn)
    conn.close()

if __name__ == "__main__":
    main()
