import sys
from pathlib import Path

# Ensure the repository root and backend directory are in sys.path so imports work
root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "backend"))

def test_backend_imports():
    """Verify backend modules can be imported."""
    import backend.main
    import backend.model
    
def test_src_imports():
    """Verify src modules can be imported."""
    import src.collector.cic_wrapper
    import src.collector.zeek_collector
    import src.parsers.zeek_parser
    import src.normalizer.event_normalizer
    import src.retention.retention_manager
