import subprocess
import sys

def test_pytorch_cpu_only():
    """Verify that PyTorch is installed and is explicitly CPU-only (CUDA not available)."""
    import torch
    
    assert torch.__version__ is not None
    # Test CPU only validation
    assert not torch.cuda.is_available(), "CUDA is available, but this environment must be CPU-only."

def test_pip_check():
    """Run pip check to ensure there are no conflicting dependencies."""
    # Run pip check as a subprocess
    result = subprocess.run([sys.executable, "-m", "pip", "check"], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("pip check failed:")
        print(result.stdout)
        print(result.stderr)
        
    assert result.returncode == 0, f"pip check failed: {result.stdout}"
