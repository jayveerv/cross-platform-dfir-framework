# Cross-Platform DFIR Framework (Phase-II Implementation)

**Title:** A Scalable Cross-Platform DFIR Framework for Automated Evidence Collection, Correlation, and Cloud Forensic Investigation
**Student:** Jayveer Vasava (2503032330032) | **Guides:** Dr. Ankita Gandhi, Dr. Kruti Kamal Sutaria

Windows, Linux aur AWS ke logs se evidence collect karta hai, ek common format me laata hai, alag-alag platforms ke events ko ek attack
timeline me jodta hai, aur har step ka hash-based chain of custody rakhta hai.


> **Version note (7 Oct 2026):** `correlate.py`, `pipeline.py`, `main.py`, `cloudstate.py`, `make_dashboard.py` aur `tests/test_rules_and_pipeline.py` dobara likhe gaye (purani zip ki ye files kharab ho gayi thi). Is README ke saare numbers isi version ko dobara chala ke liye gaye hain (`main.py evaluate`, `main.py real-eval`, `main.py selftest`, `main.py triage`).

---

## ★ Web Console (naya, 11 Oct 2026) — framework ko asli software ki tarah chalao

**`start_web.bat`** par double-click karo (ya `run.bat` → **W**). Browser me **http://127.0.0.1:8765** khulta hai.
Server sirf isi computer par sunta hai (127.0.0.1), internet par kuch nahi jaata.

| Kya kar sakte ho | Kaise |
|---|---|
| **Apni logs analyze karo** | Files ya poora folder **drag & drop** karo. **Naam kuch bhi ho** — framework har file ke andar dekh ke pehchaanta hai: Windows (.evtx / Event Viewer XML), Linux (auth.log / secure, .gz bhi), AWS CloudTrail JSON, .zip archive |
| **Built-in attack chalao** | S1–S5 scenario chuno → "Run scenario" (demo / viva ke liye) |
| **INPUT folder** | Explorer se files `INPUT\` folder me copy karo → "Analyse INPUT folder" (ya `run.bat` → **I**) |
| **Is laptop ka live triage** | "Start live triage" — processes, network, accounts, persistence, recent files, logs (Run as administrator se poora data) |
| **Live progress** | Intake → Acquisition → Normalization → Correlation → Chain of custody → Report, har stage live dikhta hai |
| **Case dekho** | Overview (verdict, KPIs, rules fired), Incidents (timeline, kill chain, entity graph — platforms kaise jude), Evidence (har original file ka SHA-256), Chain of custody (ledger blocks, re-verify, **tamper test copy par**), Events (search / filter) |
| **Export** | Full forensic HTML report, timeline CSV, poora case .zip |
| **Purane cases** | "Cases" me sab investigations list hoti hain, dobara khol sakte ho |

**Evidence intake (`intake.py`)**: original files kabhi badli nahi jaati. Har original ka SHA-256 `intake_manifest.json`
me likha jaata hai aur ye **custody ledger ki pehli entry** banti hai, phir normal acquisition (hash before/after copy) chalta hai.
Same platform ki kai files (jaise `auth.log`, `auth.log.1`, `auth.log.2.gz`) apne aap ek me jud jaati hain.
Jo file pehchaani nahi gayi (jaise notes.txt) wo "Not recognised" dikhti hai aur analysis me use nahi hoti.

Command line: `python main.py web` · `python main.py inbox [--input DIR]` · `python intake.py FILES... --out DIR`

---

## 0. Sundar Dashboard (sabse pehle ye dekho)

**`view_dashboard.bat`** par double-click karo — **CP-DFIR Investigation Console** browser me
khulega (dark SOC-style, internet ki zarurat nahi). Left menu dissertation title ke hisaab se hai:

| Menu | Kya dikhata hai |
|---|---|
| Mission Control | title, 4-layer pipeline, main KPIs, F1 per scenario |
| Evidence Collection | 5 collectors, acquisition per case, forensic-soundness rules |
| Cross-Platform Correlation | precision/recall/F1, unified vs siloed, ablation |
| Attack Investigation | case S1/S2/S3/S5 chuno — drag/zoom entity graph, timeline, kill chain |
| Cloud Forensics | AWS posture checks (moto emulator), read-only API, cloud attack stages |
| Chain of Custody | hash-chain blocks of the ledger, 7 tamper tests |
| MITRE ATT&CK Coverage | 57 rules → 38 techniques → 11 tactics matrix |
| Scalability | time vs records chart, per-stage time |
| Real-World Validation | EVTX-ATTACK-SAMPLES, LogHub, Stratus results |
| Evidence Explorer | S1 ke saare events, search + platform filter |

Upar ◐ button se light theme. Kisi section ko seedha kholna ho to `dashboard.html#mitre` jaisa likho.

> Saare numbers `results/evaluation.json`, `results/real_data_results.json` aur `cases/` ke **real output**
> se aate hain — haath se kuch nahi likha. Command line: `python make_dashboard.py`.
> Har section ka screenshot `screenshots/dashboard_*.png` me hai.

---

## 1. Chalana kaise hai (Windows)

1. **Python** install karo (python.org/downloads). Install ke time **"Add python.exe to PATH"** tick karna.
2. Zip par **Extract All** karo (zip ke andar se mat chalao), folder Desktop par rakho.
3. **`run.bat`** par double-click karo. Pehli baar zaroori packages apne aap install honge (internet chahiye).

| Menu | Kya karta hai |
|---|---|
| **W** | **Web Console** (upar dekho) |
| **I** | **INPUT folder** ki saari files analyze karo (koi bhi naam) |
| 1 | Demo: simulated attack, report browser me khulti hai |
| 2 | Simulated scenarios par full evaluation (~1 min) |
| 3 | **Asli public data par validation** (pehli baar ~44 MB download, ~3 min) |
| 4 | Tampering demo (viva ke liye) |
| 5 | **Apni logs analyze karo** |
| 6 | Is laptop ka Windows Security log export karo (**Run as Administrator**) |
| 7 | AWS CloudTrail events **aur account state** (IAM, access keys, S3, security groups) kheecho (AWS credentials chahiye) |
| 8 | Unit tests (53 tests) |
| 9 | **TRIAGE**: is laptop ka live evidence (processes, sockets, accounts, persistence, files, logs) collect karo, analyze karo, report banao |

Command line: `python main.py web | inbox | triage | collect-host | demo | evaluate | real-eval | tamper-demo | analyze --input DIR | collect-live | collect-aws | collect-linux | verify --case DIR | selftest`

---

## 2. Framework ki layers

| Layer | File | Kaam |
|---|---|---|
| **Intake** | **`intake.py`** | Kisi bhi naam ki file / .zip / .gz / folder ko content se pehchaanna (Windows / Linux / AWS / host / cloud), originals ka SHA-256 manifest |
| Acquisition | `collect.py`, **`hostcollect.py`, `cloudstate.py`** | Logs `evidence/` me copy (hash pehle aur baad). **Live host collector** (section 3b), Windows `wevtutil` (XML/.evtx), AWS boto3 `LookupEvents`, Linux local/SSH |
| Normalization | `normalize.py` | Sab formats ek schema me, sab time UTC me |
| Correlation | `correlate.py` | 57 rule types, sab MITRE ATT&CK mapped (Windows 16, Linux 2, login/brute force 2, AWS CloudTrail 11, live host 15, AWS account posture 11) + NetworkX entity graph. Har connected component jisme activity alert hai, ek incident (posture findings akele incident nahi banate) |
| Chain of Custody | `custody.py` | Har action ka SHA-256 + hash-chained ledger, **optional HMAC** (secret key se sign). File badle, entry badle, entry delete ho, last entry hate, ya poori chain rewrite ho (HMAC ke saath) to pakad leta hai |
| Reporting | `report.py` | Self-contained HTML report (internet ya JavaScript nahi chahiye) |
| Evaluation | `evaluate.py`, `generate_data.py` | Simulated scenarios + ground truth, tampering tests, scalability |
| **Real-data validation** | `realdata.py` | **Asli** public logs par test (section 4) |
| **Web Console** | **`webapp.py`, `web/`** | Local web app (Flask, 127.0.0.1): upload, live pipeline progress, cases, kill chain, entity graph, custody re-verify, tamper test, export |
| Tests | `tests/` | 53 tests (7 naye: intake + web console): asli processes/sockets (Linux), AWS collectors (botocore Stubber, AWS service model se validated), SSH collector (fake runner), parsers, rules, custody |

**Supported inputs**
- **Windows:** `wevtutil` XML export ya binary **`.evtx`**. Security (4624, 4625, 4634, 4672, 4688, 4698, 4720, 4732, 5145, 1102), System (7045, 104), **Sysmon (1, 3, 10, 13)**, PowerShell 4104
- **Linux:** `auth.log` / `secure`: sshd Failed/Accepted, sudo COMMAND, useradd; PAM-only logs (purane RedHat); traditional aur ISO timestamps; "message repeated N times"
- **AWS:** CloudTrail JSON (`Records`, list, JSON Lines, glued objects, enriched exports jaise Datadog)

**Cross-platform link kaise bante hain** (report me graph dikhta hai): same attacker IP; Linux par credential file read + `credential_inventory` (`case_config.json`) se AWS key; `CreateAccessKey` se purani key -> nayi key.

**Configurable policy:** `privileged_source_allowlist` (case_config.json): admin logons sirf in IPs se expected; baaki flag.

---

## 3. Results: simulated data (ground truth generator se)

Poori detail `results/evaluation_report.html`.

| Measure | Result |
|---|---|
| Evidence completeness | 100% (5 scenarios) |
| Correlation, core S1-S4 | Precision 100%, Recall 100%, **F1 = 1.000** |
| Correlation, hard cases S5 | Precision 90.0%, Recall 69.2%, **F1 = 0.783** |
| S5 + admin-source policy | Precision 92.9%, Recall 100%, **F1 = 0.963**; benign S4 + policy: 0 false alerts |
| Unified vs siloed | S1: siloed best 42.1% of attack chain, unified 100%. S2: 64.0% vs 100% |
| Integrity | 25/25 tampering attacks detected (5 attack types x 5 scenarios, including a forged chain caught by HMAC), 5/5 untouched cases verified. Bina HMAC/anchor ke forged chain **nahi** pakdi jaati (table me "known limitation" row) |
| Scalability | 1,067 records: 0.06 s ... 104,634 records: 6.2 s (~16,700 records/s, linear); attack still found (F1 1.000) |

**Ye numbers kamzor saboot hain**: data aur rules dono isi project me bane hain. Isliye section 4 zaroori hai.

---

## 3b. Live host evidence collection (`hostcollect.py`)

`python main.py triage` (menu 9) is laptop se live evidence collect karta hai, order of volatility (RFC 3227) me, sirf read-only:

| Artifact | Kya |
|---|---|
| `system.json` | host, OS, boot time, logged-in users, admin hai ya nahi |
| `connections.json` | network sockets + owning process |
| `processes.json` | process list: exe path, command line, user, parent, **exe SHA-256**, deleted binary |
| `accounts.json` | local accounts, admin groups, sudoers (Linux) / `net user`, Administrators (Windows) |
| `persistence.json` | cron, systemd, rc.local, ld.so.preload, authorized_keys (Linux); Run keys, startup folder, scheduled tasks, services (Windows); LaunchAgents (macOS) |
| `files.json` | pichhle 7 din ki temp/download files: ELF/PE/script magic, SHA-256, **timestomp** check (ctime) |
| `Security.evtx` / `auth.log` | security logs (Windows: Administrator chahiye) |
| `manifest.json` | har artifact ka hash, chalaye gaye commands, errors, **jo collect NAHI ho paya** |

Har file custody ledger me jaati hai, aur analysis me wahi logs wale rules + 15 host rules chalte hain (temp se chalta process, deleted/memfd binary, reverse shell, cron/systemd/authorized_keys persistence, UID 0 duplicate, executable in temp, timestomp, ...). Host ka process/socket **auth.log ya CloudTrail ke attacker IP se same incident me judta hai**.

**Asli test (Linux, isi machine par):** tests asli process banate hain (`/tmp` se chalta binary, deleted binary, memfd process, timestomped binary, bash ka asli TCP connection) aur check karte hain ki collector unhe dekhta hai aur rule fire hota hai. Asli system par chalane se 5 bug mile aur theek hue: journalctl ka "-- No entries --" nakli auth.log ban gaya; collector apni hi files "recent files" me ginta tha; `psutil` deleted-binary ka `(deleted)` hata deta hai; recent-file check sirf `mtime` par tha (timestomp se bach jaata); 500 ki cap purani-mtime wali dropped binary ko kaat deti thi.
**Asli benign host par false positives:** 1 asli benign Linux host (ye test VM): 62 processes, 57 accounts, 15 persistence entries, 978 recent files -> **3 alerts**, teeno benign: (1) `/tmp` me ek chromedriver binary (test tool, *executable_in_temp*), (2) `/tmp` me ek chhoti executable file (*executable_in_temp*), (3) sandbox ka apna telemetry agent memfd se chalta hai (*fileless_memfd_process*). Yaani **3 false positives**. Sirf ek host hai, isliye ye FP *rate* nahi, ek data point hai. Apne laptop par menu 9 chalake dekho kitne alerts aate hain.

---

## 3c. Cloud account state (`cloudstate.py`)

`python main.py collect-aws --days 7 --region ap-south-1 [--all-regions]` CloudTrail events ke saath **account ki state** bhi collect karta hai (`--no-state` se skip). Read-only. CloudTrail batata hai kya hua; state batati hai attacker kya kar sakta tha, kya band tha, aur kya khula tha.

| Artifact | Kya |
|---|---|
| `trails.json` | CloudTrail trails, logging on/off, multi-region, log-file validation |
| `iam_account.json` | root account MFA |
| `iam_users.json` | users, MFA, **administrator rights** (AdministratorAccess ya customer-managed policy jiska document `Action *` / `Resource *` de, direct ya group se), access keys (age, last use) |
| `iam_roles.json` | roles aur **kaun assume kar sakta hai** (dusra account, "anyone") |
| `s3_buckets.json` | public-access block, public bucket policy (`IsPublic` na mile to policy khud evaluate hoti hai) |
| `security_groups.json` | Internet ke liye khule ports (ek region, ya `--all-regions`) |
| `manifest.json` | har artifact ka hash, API operations jo use hue, **denied ya failed calls** |

Denied call "unknown" record hota hai, "missing" nahi (jis account ka IAM padha nahi gaya use "no MFA" nahi kaha jata). **11 posture rules:** no trail / trail logging off, trail log-file validation off, root MFA missing, admin without MFA, stale access key (90+ din), role trusts anyone, role trusts another account (`cloud_trusted_accounts` se allowlist), public bucket, public-access block incomplete, SSH/RDP/all ports world-open. **Posture findings akele incident nahi banate**; agar attacker ne koi key use ki ho to us key ka account record (user, stale ya nahi) incident me judta hai.

**Tests, teen tarah:**
1. **Labelled fixture** (JSON, maine banayi): 13 me se 13 findings, 0 false positive, clean account par 0.
2. **botocore Stubber** (responses AWS service model se validated): collector ka call order aur error handling, AccessDenied.
3. **moto AWS emulator ke saath asli boto3 code path** (`tests/test_cloud_emulated.py`): seeded account me 14 misconfigurations aur harmless look-alikes (custom-policy admin, group se admin MFA ke saath, inactive aur fresh key, conditional aur service role trust, fully blocked bucket, port 443, internal rule). **14 me se 14 mile, 0 false positive**; `--all-regions` se 15 me 15. Collector ne **sirf List/Get/Describe** operations use kiye (test isko check karta hai). 230 users ki pagination. Abused key ke saath attack: 5 key records me se sirf abused wali incident me judi.
**Ye emulator hai, asli AWS account nahi**: emulator boto3 ke request/response handling aur meri code ko test karta hai, AWS ke asli behaviour ko nahi. Asli account par kabhi nahi chala. Permissions (sab read-only): sts:GetCallerIdentity, cloudtrail:DescribeTrails/GetTrailStatus, iam:GetAccountSummary/ListUsers/ListRoles/ListAccessKeys/GetAccessKeyLastUsed/ListMFADevices/ListAttachedUserPolicies/ListGroupsForUser/ListAttachedGroupPolicies/GetPolicy/GetPolicyVersion, s3:ListAllMyBuckets/GetBucketPublicAccessBlock/GetBucketPolicyStatus/GetBucketPolicy, ec2:DescribeSecurityGroups (+ DescribeRegions).
Emulator tests ke liye `pip install moto freezegun` (`requirements-dev.txt`); nahi hon to ye tests skip hote hain.

---

## 4. Results: REAL public data

Poori detail `results/real_data_report.html`. Data GitHub se download hota hai (zip me nahi hai).

| Data | Kya | Result |
|---|---|---|
| **Windows** EVTX-ATTACK-SAMPLES | 278 asli attack captures, 37,364 records | **0 parse errors.** 228 samples (82.0%) me supported events (pehle 12.2%). Labelled 26 samples me se **25 detected**; 5 jaan-boojhkar mushkil/unsupported cases me **0/5** |
| **Linux** LogHub OpenSSH_2k | asli Internet-facing SSH server, 2,000 lines | 520 events (26%); failures **527 = 527** independent regex count; brute-force IPs **11 = 11** (independent naive detector se same set) |
| Linux LogHub Linux_2k | purana RedHat format | 489 events (24.4%); brute-force IPs 39 = 39 |
| **AWS** Stratus Red Team CloudTrail | 4 asli attack samples (15 events) | **4/4 detected** (pehle version: 1/4 aur ek file par crash) |

**Asli data se jo bugs mile aur theek hue:** `.evtx` binary padha nahi jaata tha; real time format (`2019-03-19 23:35:07+00:00`) fail; CloudTrail me source IP alag jagah (enriched export); ek real CloudTrail file invalid JSON (records ke beech comma nahi) par crash; syslog "message repeated 5 times" ek failure ginta tha (brute-force IPs 9 -> 11 hue); purane RedHat `sshd(pam_unix)` format 0% parse.

**Jo abhi bhi nahi pakda gaya (report me MISS likha hai):** rdrleakdiag LSASS dump (sample me LSASS-access event nahi hai; command line se *credential_dump_tool* alert aata hai, par label *lsass_access* maangta hai, isliye MISS gina), renamed regsvr32, msxsl, Security 4656/4663 object-access LSASS, TeamViewer memory dump, Kerberos password spray (4771).

---

## 5. Kya measure NAHI hua (thesis aur viva me sach bolna)

1. **Asli benign traffic par false-positive rate** measure nahi hua: koi labelled asli benign log available nahi tha.
2. **Asli multi-platform incident par correlation** measure nahi hua: koi public dataset me ek incident ke asli Windows + Linux + AWS logs nahi hain. Cross-platform correlation sirf **simulated** scenarios par evaluate hua.
3. Detection rules **asli samples dekhne ke baad** likhe gaye. Isliye asli-data ke labelled results "development set" hain, optimistic. Unbiased test ke liye naya data chahiye.
4. Sample labels file names se liye gaye hain (meri reading), dataset ke official per-rule labels nahi.
5. **Live collectors ka asli test kahan hua:** host collector Linux par **asli system par** test hua. **Windows aur macOS paths (registry Run keys, schtasks, services, wevtutil, LaunchAgents) is project ke dauran Windows/macOS machine par chale nahi**: parsers documented output formats par fixture se test hue, par asli output par nahi. AWS collector botocore stub se, SSH collector fake runner se test hua (asli sshd/AWS account nahi). **Apne Windows laptop par menu 9 chalao: wahi sabse zaroori check hai.**
6. Rule-based detection: rules se bahar ke attacks nahi pakde jaate.
7. Linux session attribution heuristic hai (same user ka latest login). S5 me isse ek false positive aata hai.
8. Credential file -> AWS key link ke liye analyst ka `credential_inventory` chahiye.
9. Custody ledger tampering **pakadta hai, rokta nahi**. Last entries ka delete hona tabhi pakda jata hai jab anchor hash alag noted ho, aur poori chain ka rewrite tabhi jab ledger HMAC-signed ho (`--custody-key-file` ya `DFIR_CUSTODY_KEY`) aur key attacker ke paas na ho. Agar attacker ke paas key ya ledger likhne ka poora access hai to ye guarantee nahi.
10b. Host collector memory dump ya disk image nahi leta, sirf artifacts. Timestomp check Linux par ctime se; Windows par nahi. Live collection khud system ko thoda badalti hai (nayi process, files padhna).
11. Speed single process me, 100,000 records tak.

---

## 6. Apni logs analyze karna

Ek folder me jo files hain wo daalo: `windows_security.xml` ya `*.evtx`, `auth.log`, `cloudtrail.json`, aur (optional) `case_config.json`:

```json
{
  "case_id": "CASE-001",
  "investigator": "Jayveer Vasava",
  "linux_timezone_offset": "+05:30",
  "linux_log_year": 2026,
  "internal_ranges": ["198.51.100.0/24"],
  "credential_inventory": { "web01:/home/ubuntu/.aws/credentials": "AKIA................" },
  "privileged_source_allowlist": ["10.0.5.10/32"]
}
```

Menu 5 ya `python main.py analyze --input "folder"`. Report `cases/<case_id>/report.html`. Verify: `python main.py verify --case cases/DEMO --anchor <hash>`.

**AWS live:** `pip install boto3`, AWS credentials (`aws configure` ya read-only IAM user jisme `cloudtrail:LookupEvents` ho), phir `python main.py collect-aws --days 7 --region ap-south-1`. Sirf management events aate hain (last 90 din).
**Linux:** `python main.py collect-linux --host SERVER --user ubuntu --key key.pem` (key-based SSH) ya bina `--host` ke local file copy.
**Windows:** menu 6 (Administrator), ya `wevtutil qe Security /c:5000 /rd:false /f:xml > windows_security.xml`.

## 7. Aage ka kaam

Asli benign logs par FP measure karna, asli AWS account / Windows / Linux par live test, Sysmon 11/7 aur Kerberos events, anomaly-based detection, Azure/GCP aur Docker/Kubernetes, blockchain-based custody ledger.
