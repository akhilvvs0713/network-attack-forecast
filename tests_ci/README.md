# CI Validation Tests (`tests_ci/`)

## Purpose
This directory contains an isolated CI smoke and integration validation suite. It is designed to verify the overall integrity of the repository—such as correct environment setup, successful compilation, valid imports, frontend build sanity, and backend model loading—without modifying the application state or touching the existing test suite.

## Why it is separate from `tests/`
The existing `tests/` directory contains the unit tests for the core telemetry components, Redis buffer integration, and parsing logic. The `tests_ci/` directory serves as a lightweight integration/quality gate specifically for automated environments (e.g., GitHub Actions), separating CI-level environment checks from application-level business logic tests.

## What Each Test Validates
- `test_python_syntax.py`: Recursively verifies that all Python files compile cleanly using AST parsing, preventing syntax errors from breaking the build.
- `test_imports.py`: Ensures that all critical application and backend modules can be successfully imported.
- `test_project_structure.py`: Checks for the existence of required files (such as `lstm_world_model.pth`, `package.json`, etc.) to ensure the repository is structurally sound.
- `test_environment.py`: Verifies that `torch` is CPU-only, confirming the absence of CUDA/GPU environments, and runs `pip check` to validate dependency consistency.
- `test_backend_smoke.py`: Tests the FastApi initialization and verifies that the pre-trained LSTM World Model (`lstm_world_model.pth`) loads successfully and can process a forward pass.
- `test_frontend.py`: Validates the React frontend by executing `npm ci`, `npm run lint`, and `npm run build` using the existing package configuration.

## Requirements
The project explicitly requires a CPU-only PyTorch environment (`torch==2.14.0+cpu`). CUDA should not be installed.

## Important Note
**Do not modify application code from these tests.** These tests are strictly READ-ONLY and must not start background capture processes, modify network settings, write to the repository files (except temporary test directories or frontend `dist/` handled via `.gitignore`), or start persistent servers.

## How to Run

To run just the CI validation suite:
```bash
pytest tests_ci -v
```

To run both the application tests and the CI suite together:
```bash
pytest tests tests_ci -v
```

## Frontend Validation Commands Used
The suite uses the existing Node.js toolchain defined in `frontend/package.json`:
- `npm ci`
- `npm run lint`
- `npm run build`
