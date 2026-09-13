import subprocess
from pathlib import Path


def test_frontend_validation():
    """Validates the frontend builds and lints cleanly."""
    root_dir = Path(__file__).parent.parent
    frontend_dir = root_dir / "frontend"

    # 1. npm ci (ensure dependencies are installed cleanly based on package-lock.json)
    result_ci = subprocess.run(
        ["npm", "ci"], cwd=frontend_dir, capture_output=True, text=True
    )
    assert (
        result_ci.returncode == 0
    ), f"npm ci failed: {result_ci.stderr}\n{result_ci.stdout}"

    # 2. npm run lint (check for lint errors)
    result_lint = subprocess.run(
        ["npm", "run", "lint"], cwd=frontend_dir, capture_output=True, text=True
    )
    assert (
        result_lint.returncode == 0
    ), f"npm run lint failed: {result_lint.stderr}\n{result_lint.stdout}"

    # 3. npm run build (verify the production build succeeds)
    result_build = subprocess.run(
        ["npm", "run", "build"], cwd=frontend_dir, capture_output=True, text=True
    )
    assert (
        result_build.returncode == 0
    ), f"npm run build failed: {result_build.stderr}\n{result_build.stdout}"
