import json
import asyncio
from pathlib import Path
from fastapi.testclient import TestClient
from backend.main import app, _load_static_scenarios, load_data, SCENARIOS_PATH, startup_event
import backend.main as main_module

client = TestClient(app)

def test_load_static_scenarios_does_not_modify_file():
    original_content = SCENARIOS_PATH.read_text()
    _ = _load_static_scenarios()
    new_content = SCENARIOS_PATH.read_text()
    assert original_content == new_content, "scenarios.json was modified by loading"

def test_live_state_updates():
    # Set up empty live state
    main_module._live_state = {
        "metadata": {"name": "Live Telemetry", "total_windows": 0},
        "windows": []
    }
    
    # Verify scenarios.json hash before
    original_content = SCENARIOS_PATH.read_text()
    
    # Check that API returns the static scenarios plus live
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    scenarios = response.json()
    assert any(s["id"] == "live" for s in scenarios), "live scenario missing from API"
    assert any(s["id"] == "scenario_recon_to_lateral" for s in scenarios), "static scenario missing"
    
    # Update live state in-memory (simulating redis_stream_consumer)
    main_module._live_state["windows"].append({"timestamp": "12:00:00", "flow_count": 10})
    main_module._live_state["metadata"]["total_windows"] = 1
    
    # Check that API reflects updates
    step_resp = client.get("/api/scenario/live/step/0")
    assert step_resp.status_code == 200
    data = step_resp.json()
    assert data["total_steps"] == 1
    assert data["current_window"]["flow_count"] == 10
    
    # Verify scenarios.json is unchanged
    assert SCENARIOS_PATH.read_text() == original_content, "scenarios.json was modified during live update!"

def test_empty_live_state_does_not_remove_static():
    # Reset live state
    main_module._live_state = {}
    response = client.get("/api/scenarios")
    assert response.status_code == 200
    scenarios = response.json()
    # "live" should not exist if _live_state is empty
    assert not any(s["id"] == "live" for s in scenarios)
    # but static should definitely exist
    assert any(s["id"] == "scenario_recon_to_lateral" for s in scenarios)

if __name__ == "__main__":
    test_load_static_scenarios_does_not_modify_file()
    test_live_state_updates()
    test_empty_live_state_does_not_remove_static()
    print("All tests passed!")
