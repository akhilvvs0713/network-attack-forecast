import sys
import torch
from pathlib import Path

root_dir = Path(__file__).parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "backend"))


def test_model_loading():
    """Smoke test to ensure the LSTM world model can be instantiated and loaded."""
    from backend import main
    from backend.model import LSTMWorldModel

    # Assert model was loaded successfully by main.py's initialization
    assert main._model is not None, "Model failed to load in backend/main.py"
    assert isinstance(
        main._model, LSTMWorldModel
    ), "Loaded model is not an instance of LSTMWorldModel"

    # Generate a tiny mock input to verify it handles a forward pass without crashing
    seq_len = main._seq_len
    state_dim = main._model.lstm.input_size

    X_t = torch.zeros((1, seq_len, state_dim), dtype=torch.float32)

    with torch.no_grad():
        # Single forward pass to get predictions
        pred_state, atk_log, mitre_log, (h_n, c_n) = main._model(X_t)

    assert pred_state.shape == (
        1,
        state_dim,
    ), f"Unexpected pred_state shape: {pred_state.shape}"
    assert atk_log.shape == (1, 1)


def test_api_initialization():
    """Test that the FastAPI application initializes correctly without starting a server."""
    from backend.main import app
    from fastapi import FastAPI

    assert isinstance(app, FastAPI), "app is not a FastAPI instance"
    assert app.title == "NCIIPC Cyber World Model Defense API"

    # Verify that the expected routes exist
    routes = [route.path for route in app.routes]
    assert "/api/scenarios" in routes, "Expected route /api/scenarios not found"
    assert "/api/upload-csv" in routes, "Expected route /api/upload-csv not found"
