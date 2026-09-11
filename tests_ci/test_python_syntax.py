import ast
from pathlib import Path

def test_python_syntax():
    """Verify that all relevant Python files compile successfully."""
    root_dir = Path(__file__).parent.parent
    
    # Directories to check
    dirs_to_check = ['backend', 'src', 'scripts']
    
    python_files = []
    
    # Collect files in directories
    for d in dirs_to_check:
        dir_path = root_dir / d
        if dir_path.exists():
            python_files.extend(list(dir_path.rglob("*.py")))
            
    # Add root level py files
    python_files.extend(list(root_dir.glob("*.py")))
    
    failed_files = []
    
    for py_file in python_files:
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                ast.parse(f.read(), filename=str(py_file))
        except SyntaxError as e:
            failed_files.append(f"{py_file}: {e}")
        except Exception as e:
            failed_files.append(f"{py_file}: {e}")
            
    if failed_files:
        print("Syntax errors found in:")
        for f in failed_files:
            print(f)
            
    assert not failed_files, f"Syntax errors found in {len(failed_files)} files."
