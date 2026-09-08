# Network Attack Forecast - Phase 1

This repository contains Phase 1 of the cybersecurity World Model project: a real-time network traffic monitoring and log-generation pipeline. It converts real-time network traffic into structured telemetry for later ML processing.

## Architecture

```text
Network
   ↓
Zeek
   ↓
Zeek logs
   ↓
Python collector
   ↓
Normalized JSONL
   ↓
Phase 2 (Future)
```

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

### Configuration
1. Copy `.env.example` to `.env`.
2. Configure `NETWORK_INTERFACE` and directory paths. Paths are relative to the project root.

## Running

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

## Output

Normalized events are written to `data/events/` as JSONL files.

Example:
```json
{"timestamp": "2026-09-08T19:30:00Z", "event_type": "connection", "src_ip": "192.168.1.5", "src_port": 12345, "dst_ip": "8.8.8.8", "dst_port": 443, "protocol": "tcp", "duration": 1.42, "orig_bytes": 1234, "resp_bytes": 5678, "orig_pkts": 12, "resp_pkts": 18, "conn_state": "SF"}
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

## Troubleshooting

- **Zeek not installed**: Ensure Zeek is installed via package manager.
- **Incorrect interface**: Check `NETWORK_INTERFACE` in `.env` matches your active network interface (e.g. `eth0`).
- **Permission problems**: You may need `sudo` to run Zeek.
- **No traffic appearing**: Ensure the selected interface has active traffic and Zeek is successfully writing to `data/zeek/`.
- **Log directory problems**: Ensure `data/zeek/` exists and is writable.
- **WSL networking limitations**: WSL2 has its own virtual network. To monitor host Windows traffic, you may need a workaround or monitor the WSL `eth0` interface explicitly.
