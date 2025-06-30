# CVE Exploitation Prediction Dataset

Used for training centralized and federated models to predict exploited vulnerabilities.

Built from the National Vulnerability Database (NVD) and ExploitDB.

---

## Overview

* Records: \~270,000 CVEs
* Exploited: \~24,590 labeled as exploited
* Label:

  * `1` → Exploited
  * `0` → Not Exploited
* Format: CSV (`labeled_cves_updated.csv`)
* Features:

  * Description (text)
  * CVSS vectors
  * Exploitability and impact scores
  * Missing flags
* Source:

  * [NVD API](https://nvd.nist.gov/developers/vulnerabilities)
  * [ExploitDB](https://www.exploit-db.com/)

---
## Generate Dataset

Run scripts in this order:

```bash
# 1. Fetch CVEs from NVD
python data/scripts/fetch_nvd_cves.py

# 2. Extract exploited CVEs from ExploitDB
python data/scripts/extract_exploited_ids.py

# 3. Label CVEs based on description and exploit match
python data/scripts/label_exploited_cves.py
```

Output:
`data/processed/labeled_cves_updated.csv`

