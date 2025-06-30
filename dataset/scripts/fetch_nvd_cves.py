import requests
import csv
import logging
import time
import os

logging.basicConfig(format='[%(asctime)s %(levelname)s]: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.INFO)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"User-Agent": "NVD-Data-Scraper"}
PAGE_SIZE = 1000
MAX_RETRIES = 3
RETRY_DELAY = 10


def safe_request(url, headers, params, retries=MAX_RETRIES):
    for attempt in range(1, retries + 1):
        try:
            res = requests.get(url, headers=headers, params=params, timeout=20)
            res.raise_for_status()
            return res.json()
        except requests.exceptions.Timeout:
            logging.warning(f"Timeout on attempt {attempt}, retrying in {RETRY_DELAY}s...")
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP error: {e}")
            break
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            break
        time.sleep(RETRY_DELAY)
    return None


def count_existing_rows(csv_path):
    if not os.path.exists(csv_path):
        return 0
    with open(csv_path, 'r', encoding='utf-8') as f:
        return sum(1 for _ in f) - 1  # subtract header


def fetch_cves(save_path, max_pages=1):
    start_index = count_existing_rows(save_path)
    start_page = start_index // PAGE_SIZE
    params = {
        "resultsPerPage": PAGE_SIZE,
        "startIndex": start_page * PAGE_SIZE
    }

    file_exists = os.path.exists(save_path)
    mode = 'a' if file_exists else 'w'

    with open(save_path, mode, newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'id', 'sourceIdentifier', 'published', 'lastModified', 'vulnStatus',
            'description', 'baseSeverity', 'baseScore', 'attackVector',
            'confidentialityImpact', 'integrityImpact', 'availabilityImpact',
            'exploitabilityScore', 'impactScore'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()

        total_saved = 0

        for page in range(start_page, start_page + max_pages):
            logging.info(f"Fetching page {page + 1}")
            data = safe_request(API_URL, HEADERS, params)
            if data is None:
                logging.warning("Skipping page due to repeated failures")
                params["startIndex"] += PAGE_SIZE
                continue

            cves = data.get("vulnerabilities", [])
            if not cves:
                logging.info("No more data available.")
                break

            for item in cves:
                try:
                    cve = item.get('cve', {})
                    desc_list = cve.get('descriptions', [])
                    description = next((d['value'] for d in desc_list if d.get('lang') == 'en'), '')

                    metrics = cve.get('metrics', {})
                    cvss = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30') or []
                    cvss_data = cvss[0].get('cvssData', {}) if cvss else {}
                    exploitability_score = cvss[0].get('exploitabilityScore', '') if cvss else ''
                    impact_score = cvss[0].get('impactScore', '') if cvss else ''

                    row = {
                        'id': cve.get('id'),
                        'sourceIdentifier': cve.get('sourceIdentifier'),
                        'published': cve.get('published'),
                        'lastModified': cve.get('lastModified'),
                        'vulnStatus': cve.get('vulnStatus'),
                        'description': description,
                        'baseSeverity': cvss_data.get('baseSeverity'),
                        'baseScore': cvss_data.get('baseScore'),
                        'attackVector': cvss_data.get('attackVector'),
                        'confidentialityImpact': cvss_data.get('confidentialityImpact'),
                        'integrityImpact': cvss_data.get('integrityImpact'),
                        'availabilityImpact': cvss_data.get('availabilityImpact'),
                        'exploitabilityScore': exploitability_score,
                        'impactScore': impact_score
                    }
                    writer.writerow(row)
                    total_saved += 1
                except Exception as e:
                    logging.warning(f"Skipping CVE due to error: {e}")
                    continue

            params["startIndex"] += PAGE_SIZE
            time.sleep(6)

        logging.info(f"Saved {total_saved} new CVE records to {save_path}")


if __name__ == '__main__':
    fetch_cves(save_path="nvd1_cves.csv", max_pages=10000)
