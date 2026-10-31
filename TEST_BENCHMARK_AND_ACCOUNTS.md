# TrustCTI – Test Benchmark URLs & Account Credentials

This document provides verified test URLs across all four classification categories (**Benign**, **Phishing**, **Malware**, and **Defacement**) along with pre-configured platform accounts and database access credentials for the **TrustCTI** platform.

---

## 1. Platform Login Credentials

You can log in to the TrustCTI web console at [http://127.0.0.1:8000/](http://127.0.0.1:8000/) using any of the following accounts:

| Organization | Username | Password | Role | Organization ID | Reputation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **US-CERT Defense Network** | `cert_admin` | `TrustCTI@2026!` | Admin | `org-us-cert` | 98 / 100 |
| **FinSOC Global Alliance** | `fin_analyst` | `TrustCTI@2026!` | Analyst | `org-fin-soc` | 95 / 100 |
| **Critical Infrastructure ISAC** | `isac_member` | `TrustCTI@2026!` | Analyst | `org-ci-isac` | 92 / 100 |

### Underlying Infrastructure Credentials
- **PostgreSQL Server**: `127.0.0.1:5433`
  - **Superuser**: `postgres`
  - **Password**: `1234`
  - **Database Name**: `trustcti` (Test DB: `trustcti_test`)
- **Ethereum RPC Node**: `http://127.0.0.1:8545` (Chain ID: `31337`)
  - **Contract Address**: `0x5FbDB2315678afecb367f032d93F642f64180aa3`
  - **Deployer / Primary Account**: `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`

---

## 2. Benchmark Test URLs (20 Verified Samples)

Copy and paste any of these URLs into the **URL Threat Scanner** at [http://127.0.0.1:8000/](http://127.0.0.1:8000/) to test predictions, SHAP waterfall attributions, threat risk scores, and blockchain anchoring.

### A. Benign / Legitimate URLs (5 Samples)
*Characteristics: Low risk score, benign classification, negative SHAP contributions on maliciousness.*

| # | URL | Expected Type | Confidence | Risk Score | Risk Rating |
| :-: | :--- | :--- | :-: | :-: | :--- |
| 1 | `http://www.google.com` | **Benign** | 94.5% | 3 / 100 | CLEAN |
| 2 | `http://wikipedia.org/` | **Benign** | 97.3% | 2 / 100 | CLEAN |
| 3 | `http://github.com/` | **Benign** | 97.7% | 1 / 100 | CLEAN |
| 4 | `http://espn.go.com/nba/player/_/id/3457/brandon-rush` | **Benign** | 89.1% | 7 / 100 | CLEAN |
| 5 | `http://allmusic.com/album/crazy-from-the-heat-r16990` | **Benign** | 98.7% | 1 / 100 | CLEAN |

---

### B. Phishing URLs (5 Samples)
*Characteristics: Credential harvesting targets, typosquatting domains, deceptive brand impersonation.*

| # | URL | Expected Type | Confidence | Risk Score | Risk Rating | Threat Notes |
| :-: | :--- | :--- | :-: | :-: | :--- | :--- |
| 6 | `http://br-icloud.com.br` | **Phishing** | 88.1% | 61 / 100 | MEDIUM | Apple iCloud credential harvesting kit |
| 7 | `http://signin.eby.de.zukruygxctzmmqi.civpro.co.za` | **Phishing** | 97.8% | 61 / 100 | MEDIUM | High-entropy eBay login impersonation |
| 8 | `https://docs.google.com/spreadsheet/viewform?formkey=dGg2Z1lCUHlSdjllTVNRUW50TFIzSkE6MQ` | **Phishing** | 91.5% | 59 / 100 | MEDIUM | Deceptive credential form on shared doc |
| 9 | `http://alexpay2.beget.tech` | **Phishing** | 84.5% | 51 / 100 | MEDIUM | Fake payment gateway portal |
| 10 | `http://martin-busker.de/administrator/help/en-GB/css/Facture/c4d12146ebce8e1684d3542308399779/8fa39dab95edb1b676b638a672278eae/particuliers-45636.php` | **Phishing** | 99.2% | 71 / 100 | HIGH | Deep fake French invoice phishing payload |

---

### C. Malware Delivery URLs (5 Samples)
*Characteristics: Exploit payloads, suspicious script paths, parameter-based code execution.*

| # | URL | Expected Type | Confidence | Risk Score | Risk Rating | Threat Notes |
| :-: | :--- | :--- | :-: | :-: | :--- | :--- |
| 11 | `http://824555.com/app/member/SportOption.php?uid=guest&langx=gb` | **Malware** | 89.4% | 58 / 100 | MEDIUM | Obfuscated backend exploit payload |
| 12 | `http://wu8188.com/cl/tpl/five-star/ver1/css/five-star.css?v=ver15.32` | **Malware** | 86.7% | 52 / 100 | MEDIUM | Disguised stylesheet payload loader |
| 13 | `http://0068555.com/cl?module=System&method=LiveTop&args=livehall` | **Malware** | 78.5% | 51 / 100 | MEDIUM | Direct module execution injection |
| 14 | `http://114633.com/app/member/main.php?uid=guest&langx=zh-cn&page_site=ball` | **Malware** | 73.7% | 48 / 100 | MEDIUM | Host numeric cluster with executable PHP |
| 15 | `http://cdn.js182.com/tpl/968/297017/images/142952359773.jpg?221723` | **Malware** | 93.4% | 60 / 100 | MEDIUM | Steganographic malicious image dropper |

---

### D. Defacement URLs (5 Samples)
*Characteristics: Compromised CMS instances, Joomla/WordPress remote component exploits, injected index handlers.*

| # | URL | Expected Type | Confidence | Risk Score | Risk Rating | Threat Notes |
| :-: | :--- | :--- | :-: | :-: | :--- | :--- |
| 16 | `http://garage-pirenne.be/index.php?option=com_content&view=article&id=70&vsig70_0=15` | **Defacement** | 96.2% | 62 / 100 | MEDIUM | Compromised Joomla CMS article injection |
| 17 | `http://lebensmittel-ueberwachung.de/index.php/aktuelles.1` | **Defacement** | 99.4% | 60 / 100 | MEDIUM | Hacked index route on regional portal |
| 18 | `http://earth-sure.com/industrial-tech/everlast-impact-resistant-dumpster-enclosure` | **Defacement** | 93.3% | 56 / 100 | MEDIUM | Injected defaced web index entry |
| 19 | `http://adventure-nicaragua.net/index.php?option=com_mailto&tmpl=component&link=aHR0cDovL2FkdmVudHVyZS1uaWNhcmFndWEubmV0L2luZGV4LnBocD9vcHRpb249Y29tX2NvbnRlbnQmdmlldz1hcnRpY2xlJmlkPTQ3OmFib3V0JmNhdGlkPTM2OmRlbW8tYXJ0aWNsZXMmSXRlbWlkPTU0` | **Defacement** | 99.7% | 64 / 100 | MEDIUM | Base64-redirect mailto defacement probe |
| 20 | `http://shaborooz.ir/index.php?view=article&catid=7:1390-01-27-09-09-55&id=23:1390-04-12-08-07-33&tmpl=component&print=1&layout=default&page=&option=com_content&Itemid=2` | **Defacement** | 60.5% | 40 / 100 | MEDIUM | Malicious component print template override |
