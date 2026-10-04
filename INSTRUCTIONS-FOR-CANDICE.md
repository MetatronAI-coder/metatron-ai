# PRISTINE — Instructions for Candice

**What this is**  
PRISTINE is the operational engine of the Metatron AI framework.  
It is a free, open-source tool that automatically downloads the most important known cyber threats from official public sources and stores them on your computer. It is built for non-profits, water utilities, rural hospitals, and small organizations that cannot afford commercial threat intelligence.

**What you get**
- Latest CISA Known Exploited Vulnerabilities (the official U.S. government list of actively exploited flaws)
- Recent malicious URLs and indicators from abuse.ch
- A simple local database you fully control
- Access to the public PRISTINE / Metatron AI website for weekly summaries

---

## Quick Start (5 minutes)

### 1. Get your own free API key (required for full data)
- Go to: https://auth.abuse.ch/
- Sign up with any email
- Copy your **Auth-Key**

### 2. Run the script
```bash
# Put the key in your terminal (do not share this key)
export ABUSECH_AUTH_KEY="paste-your-key-here"

# Run one time
python3 metatron_ingest.py --once

# Or run every hour
python3 metatron_ingest.py --loop 3600
```

### 3. View the data
After the first run you will have a file called `metatron_intel.db` in the same folder.  
You can open it with any SQLite viewer, or just ask for summaries.

---

## Public Website
Once GitHub Pages is enabled, the live public page is at:  
https://metatronai-coder.github.io/metatron-ai/

It shows the latest high-priority vulnerabilities and the free assessment offer.

---

## Rules (important)
- This is for **defensive** use only.
- Do not use it against systems you do not own or have written permission to test.
- Never put someone else’s API key in the script.
- Everything is free and open source.

---

## Contact
Questions or request for a free OT Security Assessment:  
metatronai@icloud.com

**Motto:** Magenta tests. Blue defends. Purple learns. Metatron scores.
