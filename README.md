<div align="center">

# Cross-Platform DFIR Framework

**A Scalable Cross-Platform DFIR Framework for Automated Evidence Collection, Correlation, and Cloud Forensic Investigation**

M.Tech Dissertation (Phase II) · Computer Science & Engineering – Cyber Security
Parul Institute of Engineering & Technology (PIET), Parul University

**Jayveer Vasava** (2503032330032) · Guide: Dr. Ankita Gandhi · Co-guide: Dr. Kruti Kamal Sutaria

[**▶ Live investigation console**](https://jayveerv.github.io/cross-platform-dfir-framework/) ·
[Sample forensic report](https://jayveerv.github.io/cross-platform-dfir-framework/report_S1.html) ·
[How to run](#how-to-run)

</div>

---

One attack today rarely stays on one machine. An attacker can brute-force a **Windows** workstation, move to a
**Linux** server, read stored cloud keys and then misuse an **AWS** account. Each platform keeps its evidence in a
different format and is examined with a different tool, so the investigator has to join the pieces by hand and
keep the chain of custody separately.

This framework collects the evidence from all of these sources, converts it into one common schema, links related
events into incidents through an entity graph, maps every finding to **MITRE ATT&CK**, and records every step in a
**tamper-evident chain-of-custody ledger**.

<p align="center"><img src="docs/images/demo.gif" width="860" alt="Terminal: demo case, verification and tampering test"></p>

## Architecture

<p align="center"><img src="docs/images/architecture.png" width="560" alt="Four-layer architecture with a chain-of-custody ledger"></p>

| Layer | What it does | Module |
|---|---|---|
| **Acquisition** | Copies evidence and checks SHA-256 before and after copying; live host triage in order of volatility (RFC 3227); read-only AWS account state (List / Get / Describe calls only) | `collect.py`, `hostcollect.py`, `cloudstate.py` |
| **Normalization** | Windows Security / Sysmon / PowerShell (EVTX or XML), Linux auth logs, AWS CloudTrail and host snapshots → 35 event types, all times in UTC | `normalize.py` |
| **Correlation** | 57 ATT&CK-mapped rules in six families and a NetworkX entity graph (attacker IPs, credential files, cloud access keys); every link has a stated reason | `correlate.py` |
| **Reporting** | Self-contained HTML report with incident graph and timeline, CSV timeline, JSON, and the investigation console | `report.py`, `make_dashboard.py` |
| **Chain of custody** | SHA-256 hash-chained ledger, optional HMAC signature and an external anchor hash; re-verified at the end of every run | `custody.py` |

## Investigation console

All results are shown in one offline page, organised around the title of the work:
collection, cross-platform correlation, cloud forensics, chain of custody, ATT&CK coverage, scalability and
validation on real data. **[Open it live →](https://jayveerv.github.io/cross-platform-dfir-framework/)**

<p align="center"><img src="docs/images/console.png" width="900" alt="Investigation console: mission control"></p>

| Attack investigation | MITRE ATT&CK coverage |
|---|---|
| <img src="docs/images/dashboard_investigation.png" alt="Entity graph, timeline and kill chain"> | <img src="docs/images/dashboard_mitre.png" alt="57 rules, 38 techniques, 11 tactics"> |
| **Chain of custody** | **Cloud forensics (AWS)** |
| <img src="docs/images/dashboard_custody.png" alt="Hash-chain ledger and tampering tests"> | <img src="docs/images/dashboard_cloud.png" alt="AWS posture checks"> |

## Results

All numbers below are measured by `python main.py evaluate` and `python main.py real-eval`
(full output in [`results/`](results/)).

**Simulated multi-platform attacks (ground truth written by the generator)**

| Measure | Result |
|---|---|
| Correlation F1, core scenarios S1–S4 | **1.000** (precision 100%, recall 100%) |
| Hard cases S5 (session collision, insider from an internal IP) | F1 0.783; 0.963 with the admin-source policy |
| Attack chain captured in one incident (S1–S3): best single platform vs unified | 42–100% vs **100%** |
| Tampering attacks detected / untouched cases verified | **25 / 25**, 5 / 5 |
| AWS misconfigurations found (moto emulator, all regions, read-only) | **15 / 15**, 0 false positives, 22 API operations |
| Scalability | 104,634 records in 6.25 s (≈16,700 records/s), F1 1.000 |

**Real public data**

| Dataset | Result |
|---|---|
| EVTX-ATTACK-SAMPLES (278 Windows attack captures, 37,364 records) | 0 parse errors; 25 / 26 labelled samples detected; 0 / 5 hard cases |
| LogHub OpenSSH_2k and Linux_2k | Brute-force source IPs match an independent count (11 / 11, 39 / 39) |
| Stratus Red Team CloudTrail samples (cloudtrail2sightings) | 4 / 4 attacks detected |

**Limitations, stated openly.** Detection is rule-based. Rules were refined after looking at the real samples, so
the real-data figures are development-set results. The false-positive rate on real benign traffic and correlation
on a real multi-platform incident were not measured. The AWS collectors were tested on an emulator, not a live
AWS account.

## How to run

**Windows (no command line needed)**

1. Install Python 3.10 or newer from [python.org](https://www.python.org/downloads/) (tick *Add Python to PATH*).
2. Download this repository (**Code → Download ZIP**) and extract it.
3. Double-click **`run.bat`** and choose an option:

```
1. Demo: simulated attack across Windows, Linux and AWS
2. Full evaluation on simulated scenarios, about 1 minute
3. Validation on REAL public data, downloads 44 MB first time, about 3 minutes
4. Tampering demo
5. Analyse my own logs
6. Export this laptop's Windows Security log, run as Administrator
7. Pull AWS CloudTrail events and account state, needs AWS credentials
8. Self-tests
9. TRIAGE this laptop: collect live evidence, analyse, report
```

4. Double-click **`view_dashboard.bat`** to open the investigation console.

**Any operating system (command line)**

```bash
pip install -r requirements.txt          # networkx, python-evtx, boto3, psutil
python main.py demo                       # simulated attack -> cases/DEMO/report.html
python main.py evaluate                   # all scenarios, tamper tests, scalability
python main.py tamper-demo                # change evidence and watch it being detected
python main.py analyze --input <folder>   # your own windows_security.xml / *.evtx, auth.log, cloudtrail.json
python main.py triage                     # live evidence from this computer
python main.py verify --case cases/DEMO   # re-verify the chain of custody

pip install -r requirements-dev.txt       # adds moto and freezegun
python main.py selftest                   # 46 automated tests
```

## Repository layout

```
main.py              command-line entry point (12 commands)
collect.py           acquisition with hashing, Windows/AWS/Linux collectors
hostcollect.py       live host triage (Windows, Linux, macOS)
cloudstate.py        read-only AWS account-state collector
normalize.py         common schema (35 event types, UTC)
correlate.py         57 ATT&CK rules and the entity graph
custody.py           hash-chained, optionally HMAC-signed ledger
pipeline.py          runs the four layers for one case
report.py            HTML forensic report
make_dashboard.py    investigation console
evaluate.py          scenarios S1-S5, tamper tests, ablation, scalability
generate_data.py     simulated attacks with ground truth
realdata.py          validation on public datasets
cloud_emulation.py   AWS tests on the moto emulator
tests/               46 automated tests
results/             evaluation output used in the dissertation
docs/                live console (GitHub Pages) and images
```

15 Python modules, 5,313 lines of code, standard library plus `networkx`, `python-evtx`, `boto3` and `psutil`.

## Citation

If you refer to this work, please cite the dissertation:

```
J. Vasava, "A Scalable Cross-Platform DFIR Framework for Automated Evidence Collection, Correlation,
and Cloud Forensic Investigation," M.Tech dissertation, Dept. of Computer Science & Engineering
(Cyber Security), Parul Institute of Engineering & Technology, Parul University, 2026.
```

## License

Released under the [MIT License](LICENSE).
Public datasets used for validation belong to their authors: EVTX-ATTACK-SAMPLES (sbousseaden), LogHub (logpai) and
the Stratus Red Team CloudTrail samples in cloudtrail2sightings (zmallen); they are downloaded at run time and are not included in this repository.
