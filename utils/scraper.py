import requests
from bs4 import BeautifulSoup
import json
import time

def scrape_acunetix_full():
    base_url_template = "https://www.acunetix.com/vulnerabilities/web/severity/{}/{}/" # format: severity/page/number/
    severities = ["critical", "high", "medium", "low", "info"]
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Referer": "https://www.google.com/"
    }

    all_vulnerabilities = []

    for severity in severities:
        print(f"\n[*] Starting crawl for severity: {severity.upper()}")
        page_num = 1
        
        while True:
            # Construct URL untuk pagination yang benar
            # Halaman 1 di Acunetix biasanya redirect dari base url, tapi kita tembak pattern page/X/ biar konsisten
            if page_num == 1:
                target_url = f"https://www.acunetix.com/vulnerabilities/web/severity/{severity}/"
            else:
                target_url = f"https://www.acunetix.com/vulnerabilities/web/severity/{severity}/page/{page_num}/"

            try:
                response = requests.get(target_url, headers=headers, timeout=10)
                
                # Kalau halaman tidak ditemukan (404), berarti paginasi sudah habis
                if response.status_code == 404:
                    print(f"    [-] End of list for {severity} at page {page_num-1}.")
                    break
                
                if response.status_code != 200:
                    print(f"    [!] Error fetching page {page_num}: Status {response.status_code}")
                    break

                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Cari container artikel/list
                content_area = soup.find('main') or soup.find('div', class_='page-content') or soup
                
                # Ambil semua link
                links = content_area.find_all('a', href=True)
                
                items_found_on_page = 0
                
                for link in links:
                    href = link['href']
                    text = link.text.strip()
                    
                    # --- LOGIKA FILTERING YANG DIPERBAIKI ---
                    # 1. Harus mengandung base path vuln
                    if "/vulnerabilities/web/" not in href:
                        continue
                    
                    # 2. Skip jika ini adalah link paginasi (mengandung '/page/')
                    if "/page/" in href:
                        continue
                        
                    # 3. Skip jika ini adalah link tag/kategori (mengandung '/severity/' atau '/tag/')
                    #    Link vuln asli biasanya langsung: .../web/nama-vuln-nya/
                    if "/severity/" in href or "/tag/" in href:
                        continue
                    
                    # 4. Skip jika text link kosong atau angka doang (sisa paginasi yang lolos)
                    if not text or text.isdigit():
                        continue

                    # Cek duplikasi (kadang ada link 'Read More' yang mengarah ke url sama)
                    if not any(v['reference_link'] == href for v in all_vulnerabilities):
                        all_vulnerabilities.append({
                            "vulnerability_name": text,
                            "severity": severity,
                            "reference_link": href if href.startswith('http') else f"https://www.acunetix.com{href}"
                        })
                        items_found_on_page += 1

                print(f"    [+] Page {page_num}: Found {items_found_on_page} items.")
                
                # Kalau di page ini 0 item ditemukan, kemungkinan besar struktur halamannya beda atau sudah habis tapi return 200
                if items_found_on_page == 0 and page_num > 1:
                     print(f"    [-] No items found on page {page_num}. Stopping {severity}.")
                     break

                page_num += 1
                time.sleep(1) # Delay biar sopan

            except Exception as e:
                print(f"    [!] Exception on page {page_num}: {e}")
                break

    # Simpan
    output_file = "acunetix_vulnerabilities_fixed.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_vulnerabilities, f, indent=4, ensure_ascii=False)

    print(f"\n[SUCCESS] Total {len(all_vulnerabilities)} vulnerabilities saved to {output_file}")

if __name__ == "__main__":
    scrape_acunetix_full()