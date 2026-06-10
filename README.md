# Network Anomaly Detector

A lightweight, real-time network monitoring tool built for cybersecurity professionals and enthusiasts. It continuously scans your local network, tracks connected devices, detects anomalies, and displays findings on a live security dashboard.

---

## Features

- **Real-time network scanning** — continuously scans your local subnet every 10 seconds using ARP
- **Device tracking** — records every device seen on the network with first seen and last seen timestamps
- **Threat detection** — automatically detects and alerts on:
  - New devices joining the network
  - Devices disappearing from the network
  - IP spoofing (same MAC, different IP on same subnet)
- **Risk engine** — assigns a risk level to every device based on:
  - Vendor recognition
  - Device behaviour history
  - Reconnect frequency
  - Active hours (flags activity between 2AM–5AM)
  - MAC address randomisation detection
- **Risk explainer** — every device shows exactly why it received its risk level
- **Scan history** — keeps a record of the last 50 devices scanned
- **Alerts tab** — full log of all anomaly alerts with severity levels
- **Auto network detection** — automatically detects your current subnet, no hardcoding needed

---

## Risk Levels

| Level | Meaning |
|---|---|
| **NONE** | Known device with recognised vendor |
| **LOW** | New device with known vendor, or known device with unknown vendor |
| **MEDIUM** | Frequent reconnects, active at unusual hours, or new device with unknown vendor |
| **HIGH** | IP changed on same MAC, randomised MAC detected, or 7+ reconnects in one hour |
| **CRITICAL** | Multiple high-risk flags detected simultaneously |

---

## Requirements

- Python 3.10+
- Linux (tested on Kali Linux)
- Root privileges or `cap_net_raw` capability for ARP scanning

---

## Installation

```bash
git clone https://github.com/Khris8330/network-anomaly-detector.git
cd network-anomaly-detector
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Grant raw socket capability (avoids needing sudo):
```bash
sudo setcap cap_net_raw=eip $(which python3)
```

---

## Usage

```bash
source venv/bin/activate
python dashboard.py
```

Then open your browser and go to:
http://127.0.0.1:5000
---

## Dashboard

The dashboard has three tabs:

- **Live Devices** — all currently tracked devices with IP, MAC, vendor, risk level and timestamps
- **Scan History** — last 50 devices scanned, sorted by most recently seen
- **Alerts** — full log of anomaly alerts (new devices, missing devices, IP spoofing)

---

## Project Structure

network-anomaly-detector/
├── dashboard.py          # Flask web dashboard + scanner thread
├── monitor_engine.py     # Continuous scan loop
├── anomaly.py            # Threat detection logic
├── scanner.py            # ARP network scanner
├── database.py           # SQLite database layer
├── fingerprint.py        # MAC vendor lookup
├── network_utils.py      # Local IP and subnet detection
├── data/
│   └── network.db        # SQLite database (auto-created)
└── templates/
└── index.html        # Dashboard UI
---

## How It Works

1. On startup, `dashboard.py` initialises the database and launches the scanner as a background thread
2. The scanner detects your current subnet automatically using your active network interface
3. Every 10 seconds, an ARP scan discovers all devices on the subnet
4. New devices are compared against the known device database
5. Anomalies are detected and saved as alerts
6. The dashboard reads live data from the database on every page load

---

## Integration

This tool is designed to work alongside the [Correlation Engine](https://github.com/Khris8330/correlation-engine), which reads from this tool's database to perform deeper threat correlation and attack surface analysis.

---

## Legal Disclaimer

This tool is intended for use on networks you own or have explicit written permission to monitor. Unauthorised network scanning is illegal in most jurisdictions. The author assumes no responsibility for misuse.

---

## Author

**Khris8330**
