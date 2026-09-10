# Network Attack Forecast - Phase 1

This repository contains Phase 1 of the cybersecurity World Model project: a real-time network traffic monitoring and log-generation pipeline. It converts real-time network traffic into structured telemetry for later ML processing.

## Architecture

```text
eth0
  |
  +--------------------+
  |                    |
  v                    v
Zeek              CICFlowMeter
  |                    |
  v                    v
data/zeek/        data/cic/flows/
  |                    |
  v                    v
data/events/      (future: CIC-IDS model)
(normalized JSONL)   (timestamped CSVs)
```

**Zeek pipeline**: Captures raw network traffic → Zeek TSV logs → Python collector tails and normalizes → JSONL events for the Zeek-trained model.

**CICFlowMeter pipeline**: Captures raw network traffic → CICFlowMeter flow analysis → CIC-IDS-compatible CSV flow records for the CIC-IDS-trained LSTM model.

## Installation

### WSL2/Ubuntu Setup
1. Ensure you have WSL2 installed with an Ubuntu distribution.
2. Clone this repository into your project directory.

### Python Environment
1. Create a virtual environment: `python3 -m venv .venv`
2. Activate it: `source .venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`

### Zeek Installation
1. Install Zeek on Ubuntu: `sudo apt-get install zeek`
2. Ensure Zeek is in your PATH.

### CICFlowMeter Installation
1. Activate the project venv: `source .venv/bin/activate`
2. Install via pip: `pip install cicflowmeter`
3. Verify: `.venv/bin/cicflowmeter --help`
4. Note: Live capture requires `sudo`. The scripts automatically resolve the venv binary even under `sudo`.

### Configuration
1. Copy `.env.example` to `.env`.
2. Configure `NETWORK_INTERFACE` and directory paths. Paths are relative to the project root.

## Running

### Zeek Pipeline

1. Activate virtual environment:
   ```bash
   source .venv/bin/activate
   ```
2. Start the Zeek process (example script provided):
   ```bash
   ./scripts/start_zeek.sh
   ```
3. Start the collector:
   ```bash
   python -m src.main
   ```

### CICFlowMeter Pipeline

1. Run the acceptance test first:
   ```bash
   sudo ./scripts/test_cic_capture.sh
   ```
2. Start continuous capture with rotation:
   ```bash
   sudo ./scripts/start_cic.sh
   ```
3. Stop capture:
   ```bash
   ./scripts/stop_cic.sh
   ```

## Output

### Zeek Events
Normalized events are written to `data/events/` as JSONL files.

Example:
```json
{"timestamp": "2026-09-08T19:30:00Z", "event_type": "connection", "src_ip": "192.168.1.5", "src_port": 12345, "dst_ip": "8.8.8.8", "dst_port": 443, "protocol": "tcp", "duration": 1.42, "orig_bytes": 1234, "resp_bytes": 5678, "orig_pkts": 12, "resp_pkts": 18, "conn_state": "SF"}
```

### CICFlowMeter Flows
CIC-IDS-compatible flow records are written to `data/cic/flows/` as timestamped CSV files.

Files are named: `flows_YYYY-MM-DD_HH-MM.csv`

The CSV contains 80+ CICFlowMeter feature columns including Flow ID, Source/Destination IP and Port, Protocol, Flow Duration, packet/byte counts, inter-arrival times, flag counts, and statistical features — directly compatible with the CSE-CIC-IDS2018 dataset format.

## Redis Rolling Buffer

While the CSV logs remain the permanent historical archive, the project uses **Redis** as a short-lived working memory for recent traffic.

### Why Redis?
To perform real-time ML inference, the system needs fast, time-ordered access to the most recent network flows without continuously re-reading large CSV files from disk. Redis provides an efficient in-memory sliding window using a Sorted Set.

### Architecture
Flows are inserted simultaneously into the CSV archive and the Redis rolling buffer:
```text
Redis (recent raw flows)
        |
        v
1-minute aggregation (Future)
        |
        v
S(t-4), S(t-3), S(t-2), S(t-1), S(t)
        |
        v
LSTM World Model (Future)
```

### Design and Retention
- **Sorted Set:** Each flow is serialized as JSON and stored in a Redis Sorted Set (`cic:flows`) scored by its actual Unix event timestamp.
- **Timestamp-Based Retention:** The buffer retains exactly the last `REDIS_RETENTION_SECONDS` (default: 300 seconds / 5 minutes) of traffic relative to the latest inserted flow. It automatically drops older traffic.
- **Conceptual Distinction:** The 5-minute Redis retention window is *not* the LSTM's 5-step sequence (`SEQ_LEN=5`). The Redis buffer simply holds raw flows for the past N minutes. A future aggregation layer will read these raw flows, aggregate them into 1-minute state vectors, and form the 5-step sequences expected by the model.

## Directory Structure

```text
network-attack-forecast/
├── config/
│   └── config.py              # Environment-based configuration
├── data/
│   ├── zeek/                  # Zeek raw logs
│   ├── cic/
│   │   ├── flows/             # CICFlowMeter CSV output
│   │   └── windows/           # Future: windowed aggregations
│   └── events/                # Normalized Zeek events (JSONL)
├── logs/                      # Application logs
├── scripts/
│   ├── start_zeek.sh          # Start Zeek capture
│   ├── stop_zeek.sh           # Stop Zeek capture
│   ├── start_cic.sh           # Start CICFlowMeter capture
│   ├── stop_cic.sh            # Stop CICFlowMeter capture
│   ├── test_cic_capture.sh    # CICFlowMeter acceptance test
│   └── test_pipeline.sh       # Zeek pipeline verification
├── src/
│   ├── collector/
│   │   ├── zeek_collector.py  # Zeek log tailing & collection
│   │   └── cic_collector.py   # CICFlowMeter subprocess wrapper
│   ├── parsers/
│   │   └── zeek_parser.py     # Zeek TSV parser
│   ├── normalizer/
│   │   └── event_normalizer.py # Zeek event normalization
│   ├── retention/
│   │   └── retention_manager.py # File lifecycle management
│   └── main.py                # Zeek pipeline entry point
├── tests/
│   ├── test_collector.py
│   ├── test_cic_collector.py
│   ├── test_zeek_parser.py
│   ├── test_normalizer.py
│   └── test_retention.py
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Testing

Run the pytest suite:
```bash
pytest
```

Run the pipeline verification script:
```bash
./scripts/test_pipeline.sh
```

Run the CICFlowMeter acceptance test:
```bash
sudo ./scripts/test_cic_capture.sh
```

## Troubleshooting

- **Zeek not installed**: Ensure Zeek is installed via package manager.
- **Incorrect interface**: Check `NETWORK_INTERFACE` in `.env` matches your active network interface (e.g. `eth0`).
- **Permission problems**: You may need `sudo` to run Zeek or CICFlowMeter.
- **No traffic appearing**: Ensure the selected interface has active traffic and Zeek is successfully writing to `data/zeek/`.
- **Log directory problems**: Ensure `data/zeek/` and `data/cic/flows/` exist and are writable.
- **WSL networking limitations**: WSL2 has its own virtual network. To monitor host Windows traffic, you may need a workaround or monitor the WSL `eth0` interface explicitly.
- **CICFlowMeter not found**: Install with `.venv/bin/pip install cicflowmeter`. The scripts resolve the binary from `.venv/bin/` automatically, even under `sudo`.
- **CICFlowMeter permission denied**: Live capture requires root — run with `sudo`.
