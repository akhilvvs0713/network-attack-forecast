from pathlib import Path

def test_project_structure():
    """Verify that expected files and directories exist."""
    root_dir = Path(__file__).parent.parent
    
    expected_paths = [
        "backend/main.py",
        "backend/model.py",
        "backend/lstm_world_model.pth",
        "backend/scenarios.json",
        "frontend/package.json",
        "frontend/package-lock.json",
        "frontend/src",
        "requirements.txt",
        "scripts",
        "src"
    ]
    
    missing = []
    for rel_path in expected_paths:
        full_path = root_dir / rel_path
        if not full_path.exists():
            missing.append(rel_path)
            
    assert not missing, f"Missing expected project paths: {missing}"
