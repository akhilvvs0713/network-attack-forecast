import os
from pathlib import Path
from dotenv import load_dotenv
import logging

# Load environment variables from .env if present
load_dotenv()

# Base project directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Network monitoring
NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "auto")

# Directories
_zeek_log_dir = os.getenv("ZEEK_LOG_DIR", "./data/zeek")
ZEEK_LOG_DIR = Path(BASE_DIR / _zeek_log_dir).resolve()

_event_output_dir = os.getenv("EVENT_OUTPUT_DIR", "./data/events")
EVENT_OUTPUT_DIR = Path(BASE_DIR / _event_output_dir).resolve()

# CIC directories
_cic_flow_dir = os.getenv("CIC_FLOW_DIR", "./data/cic/flows")
CIC_FLOW_DIR = Path(BASE_DIR / _cic_flow_dir).resolve()

_cic_window_dir = os.getenv("CIC_WINDOW_DIR", "./data/cic/windows")
CIC_WINDOW_DIR = Path(BASE_DIR / _cic_window_dir).resolve()

# Retention & Rotation
EVENT_RETENTION_MINUTES = int(os.getenv("EVENT_RETENTION_MINUTES", "10"))
EVENT_ROTATION_MINUTES = int(os.getenv("EVENT_ROTATION_MINUTES", "15"))
CIC_ROTATION_MINUTES = int(os.getenv("CIC_ROTATION_MINUTES", "1"))

# Logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Redis Configuration
REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_FLOW_KEY = os.getenv("REDIS_FLOW_KEY", "cic:flows")
REDIS_RETENTION_SECONDS = int(os.getenv("REDIS_RETENTION_SECONDS", "300"))

def ensure_directories():
    """Ensure that required directories exist."""
    ZEEK_LOG_DIR.mkdir(parents=True, exist_ok=True)
    EVENT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    CIC_FLOW_DIR.mkdir(parents=True, exist_ok=True)
    CIC_WINDOW_DIR.mkdir(parents=True, exist_ok=True)

def setup_logging():
    """Configure basic logging for the application."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    return logging.getLogger("NetworkMonitor")
