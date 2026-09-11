import io
import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
import torch
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from model import (
    LSTMWorldModel, ManualScaler, signed_log1p, normalize_col,
    build_agg_names, MITRE_NAMES,
)

app = FastAPI(title="NCIIPC Cyber World Model Defense API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
SCENARIOS_PATH = BASE_DIR / "scenarios.json"
CHECKPOINT_PATH = BASE_DIR / "lstm_world_model.pth"

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ─── Load trained checkpoint once at startup ───────────────────────────────
_checkpoint = None
_model: Optional[LSTMWorldModel] = None
_scaler: Optional[ManualScaler] = None
_feature_cols: List[str] = []
_seq_len: int = 5
_best_threshold: float = 0.5
_benign_mse_baseline: Optional[dict] = None
_k_steps: int = 5
_window_size: str = "1min"
_agg_names: List[str] = []


def _load_checkpoint():
    global _checkpoint, _model, _scaler, _feature_cols, _seq_len
    global _best_threshold, _benign_mse_baseline, _k_steps, _window_size, _agg_names

    if not CHECKPOINT_PATH.exists():
        # Server can still run in "static scenarios only" mode.
        print(f"[warn] {CHECKPOINT_PATH} not found — /api/upload-csv will be disabled.")
        return

    ckpt = torch.load(CHECKPOINT_PATH, map_location=device, weights_only=False)
    _feature_cols = ckpt["feature_cols"]
    state_dim = ckpt["state_dim"]
    _seq_len = ckpt["seq_len"]
    _best_threshold = float(ckpt["best_threshold"])
    _benign_mse_baseline = ckpt.get("benign_mse_baseline")
    cfg = ckpt.get("config", {})
    _k_steps = cfg.get("k_steps", 5)
    _window_size = cfg.get("window_size", "1min")

import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
import torch
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from model import (
    LSTMWorldModel, ManualScaler, signed_log1p, normalize_col,
    build_agg_names, MITRE_NAMES,
)

app = FastAPI(title="NCIIPC Cyber World Model Defense API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
SCENARIOS_PATH = BASE_DIR / "scenarios.json"
CHECKPOINT_PATH = BASE_DIR / "lstm_world_model.pth"

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ─── Load trained checkpoint once at startup ───────────────────────────────
_checkpoint = None
_model: Optional[LSTMWorldModel] = None
_scaler: Optional[ManualScaler] = None
_feature_cols: List[str] = []
_seq_len: int = 5
_best_threshold: float = 0.5
_benign_mse_baseline: Optional[dict] = None
_k_steps: int = 5
_window_size: str = "1min"
_agg_names: List[str] = []


def _load_checkpoint():
    global _checkpoint, _model, _scaler, _feature_cols, _seq_len
    global _best_threshold, _benign_mse_baseline, _k_steps, _window_size, _agg_names

    if not CHECKPOINT_PATH.exists():
        # Server can still run in "static scenarios only" mode.
        print(f"[warn] {CHECKPOINT_PATH} not found — /api/upload-csv will be disabled.")
        return

    ckpt = torch.load(CHECKPOINT_PATH, map_location=device, weights_only=False)
    _feature_cols = ckpt["feature_cols"]
    state_dim = ckpt["state_dim"]
    _seq_len = ckpt["seq_len"]
    _best_threshold = float(ckpt["best_threshold"])
    _benign_mse_baseline = ckpt.get("benign_mse_baseline")
    cfg = ckpt.get("config", {})
    _k_steps = cfg.get("k_steps", 5)
    _window_size = cfg.get("window_size", "1min")
    _agg_names = build_agg_names(_feature_cols)

    model = LSTMWorldModel(
        state_dim=state_dim,
        hidden_size=ckpt["hidden_size"],
        num_layers=ckpt["num_layers"],
    )
    model.load_state_dict(ckpt["model_state_dict"])
    model.to(device)
    model.eval()

    scaler = ManualScaler(ckpt["scaler_mean"], ckpt["scaler_scale"])

    globals()["_checkpoint"] = ckpt
    globals()["_model"] = model
    globals()["_scaler"] = scaler
    print(f"[ok] Loaded checkpoint: {len(_feature_cols)} features, seq_len={_seq_len}, "
          f"threshold={_best_threshold:.4f}")


_load_checkpoint()

# ─── scenarios.json persistence (static scenarios + ingested uploads) ──────

def load_data() -> Dict:
    if not SCENARIOS_PATH.exists():
        return {}
    with open(SCENARIOS_PATH, "r") as f:
        return json.load(f)


def save_data(data: Dict) -> None:
    with open(SCENARIOS_PATH, "w") as f:
        json.dump(data, f)


@app.get("/api/scenarios")
def list_scenarios():
    data = load_data()
    return [
        {"id": k, "name": v["metadata"]["name"], "target": v["metadata"]["target_asset"]}
        for k, v in data.items()
    ]


@app.get("/api/scenario/{scenario_id}/step/{step_idx}")
def get_scenario_step(scenario_id: str, step_idx: int):
    data = load_data()
    if scenario_id not in data:
        raise HTTPException(status_code=404, detail="Scenario not found")

    windows = data[scenario_id]["windows"]
    if step_idx < 0 or step_idx >= len(windows):
        raise HTTPException(status_code=400, detail="Step out of range")

    return {
        "metadata": data[scenario_id]["metadata"],
        "current_window": windows[step_idx],
        "total_steps": len(windows),
    }


# ─── Real inference on an uploaded CICFlowMeter-style CSV ──────────────────

def _aggregate_windows(df: pd.DataFrame) -> tuple:
    """Reproduces the notebook's 1-minute aggregation (Cell 16) for a
    single in-memory dataframe. Returns (states, timestamps, counts,
    missing_feature_indices)."""

    n_feat = len(_feature_cols)
    norm_feat = [normalize_col(c) for c in _feature_cols]
    dst_port_idx = norm_feat.index("dstport") if "dstport" in norm_feat else None
    protocol_idx = norm_feat.index("protocol") if "protocol" in norm_feat else None

    # CICFlowMeter exports timing fields in seconds; the training data (and
    # this model) used microseconds — convert to match.
    time_keywords = ["iat", "active", "idle", "duration"]
    for c in df.columns:
        if any(kw in c.lower() for kw in time_keywords):
            df[c] = pd.to_numeric(df[c], errors="coerce") * 1_000_000.0

    model_col_map = {normalize_col(c): c for c in _feature_cols}
    model_col_map["timestamp"] = "Timestamp"
    rename_dict = {}
    for c in df.columns:
        norm_c = normalize_col(c)
        if norm_c == "cwrflagcount":
            norm_c = "cweflagcount"
        if norm_c in model_col_map:
            rename_dict[c] = model_col_map[norm_c]
    df = df.rename(columns=rename_dict)

    if "Timestamp" not in df.columns:
        raise HTTPException(
            status_code=400,
            detail="Uploaded CSV has no recognizable Timestamp column.",
        )

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.dropna(subset=["Timestamp"])

    present = set(df.columns)
    missing_feature_indices = [i for i, col in enumerate(_feature_cols) if col not in present]

    for col in _feature_cols:
        if col not in df.columns:
            df[col] = 0.0
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df[_feature_cols] = df[_feature_cols].replace([np.inf, -np.inf, np.nan], 0.0)

    df["_window"] = df["Timestamp"].dt.floor("1min")

    accumulators = {}
    for wkey, group in df.groupby("_window"):
        X = group[_feature_cols].values.astype(np.float64)
        n = len(X)
        acc = accumulators.setdefault(wkey, {
            "count": 0, "sum": np.zeros(n_feat), "sum_sq": np.zeros(n_feat),
            "min": np.full(n_feat, np.inf), "max": np.full(n_feat, -np.inf),
            "dst_ports": set(), "protocols": set(), "high_port_count": 0,
        })
        acc["count"] += n
        acc["sum"] += X.sum(axis=0)
        acc["sum_sq"] += (X ** 2).sum(axis=0)
        acc["min"] = np.minimum(acc["min"], X.min(axis=0))
        acc["max"] = np.maximum(acc["max"], X.max(axis=0))
        if dst_port_idx is not None:
            acc["dst_ports"].update(X[:, dst_port_idx].astype(int).tolist())
            acc["high_port_count"] += int((X[:, dst_port_idx] > 1024).sum())
        if protocol_idx is not None:
            acc["protocols"].update(X[:, protocol_idx].astype(int).tolist())

    sorted_keys = sorted(accumulators.keys())
    states, timestamps, counts = [], [], []
    for wkey in sorted_keys:
        acc = accumulators[wkey]
        n = acc["count"]
        mean = acc["sum"] / n
        var = np.maximum((acc["sum_sq"] / n) - (mean ** 2), 0.0)
        states.append(np.concatenate([
            mean, np.sqrt(var), acc["min"], acc["max"],
            np.array([
                np.log1p(n),
                np.log1p(len(acc["dst_ports"])),
                len(acc["protocols"]),
                acc["high_port_count"] / n if n > 0 else 0.0,
            ]),
        ]))
        timestamps.append(wkey)
        counts.append(int(n))

    return np.array(states), timestamps, counts, missing_feature_indices


def _format_horizon(k: int) -> str:
    """Label a k-step-ahead forecast using the model's actual window size
    (e.g. '+3min' for WINDOW_SIZE='1min', k=3)."""
    try:
        delta = pd.Timedelta(_window_size) * k
    except Exception:
        return f"+{k} step(s)"
    total_seconds = delta.total_seconds()
    if total_seconds < 60:
        return f"+{int(total_seconds)}s"
    if total_seconds % 60 == 0:
        return f"+{int(total_seconds // 60)}min"
    return f"+{total_seconds / 60:.1f}min"


def _scale_sequence(seq: np.ndarray, missing_feature_indices: list) -> np.ndarray:
    n_feat = len(_feature_cols)
    seq_s = signed_log1p(seq.astype(np.float64))
    seq_sc = _scaler.transform(seq_s).astype(np.float32)
    seq_sc = np.clip(seq_sc, -3.0, 3.0)
    # Zero out columns for features absent from the uploaded CSV, across
    # each of the 4 aggregation blocks (mean/std/min/max).
    for m_idx in missing_feature_indices:
        for agg_offset in range(4):
            col_idx = agg_offset * n_feat + m_idx
            if col_idx < seq_sc.shape[1]:
                seq_sc[:, col_idx] = 0.0
    return seq_sc


def _gradient_attribution(X_t: torch.Tensor, top_k: int = 3):
    """Gradient-based attribution of the attack-risk head w.r.t. the input
    sequence — same method as notebook Cell 11, applied per-sequence rather
    than averaged over a sample, since this is a live single-window
    explanation. Returns (top features list, detached model outputs)."""
    X_t = X_t.clone().detach().requires_grad_(True)
    with torch.backends.cudnn.flags(enabled=False):
        pred_state, atk_log, mitre_log, (h_n, c_n) = _model(X_t)
        atk_log.squeeze().backward()

    grads = np.abs(X_t.grad.detach().cpu().numpy().squeeze(0))  # (seq_len, state_dim)
    per_dim = grads.mean(axis=0)  # importance per state dimension
    max_val = per_dim.max() if per_dim.max() > 0 else 1.0
    top_idx = np.argsort(per_dim)[::-1][:top_k]
    shap_features = [
        {
            "feature": _agg_names[idx] if idx < len(_agg_names) else f"dim_{idx}",
            "importance": round(float(per_dim[idx] / max_val), 4),
        }
        for idx in top_idx
    ]
    hc = (h_n.detach(), c_n.detach())
    return shap_features, pred_state.detach(), atk_log.detach(), mitre_log.detach(), hc


def _k_step_trajectory(pred_state, atk_log, mitre_log, h_c) -> List[Dict]:
    """Autoregressive K-step forecast, mirroring notebook Cell 10's
    k_step_forecast — chains the LSTM hidden state forward using the model's
    own predicted state as the next input."""
    trajectory = []
    h_n, c_n = h_c

    atk_prob = torch.sigmoid(atk_log).item()
    mt_cls = int(mitre_log.argmax(dim=1).item())
    trajectory.append({
        "step_ahead": _format_horizon(1),
        "prob": round(float(atk_prob), 4),
        "stage": MITRE_NAMES.get(mt_cls, "Unknown"),
    })

    with torch.no_grad():
        for step in range(1, _k_steps):
            next_input = pred_state.unsqueeze(1)
            pred_state, atk_log, mitre_log, (h_n, c_n) = _model(next_input, (h_n, c_n))
            atk_prob = torch.sigmoid(atk_log).item()
            mt_cls = int(mitre_log.argmax(dim=1).item())
            trajectory.append({
                "step_ahead": _format_horizon(step + 1),
                "prob": round(float(atk_prob), 4),
                "stage": MITRE_NAMES.get(mt_cls, "Unknown"),
            })
    return trajectory


def _run_model_inference(states: np.ndarray, timestamps: list, counts: list,
                          missing_feature_indices: list) -> List[Dict]:
    windows_out = []

    for i in range(len(states) - _seq_len):
        seq = states[i: i + _seq_len]
        seq_sc = _scale_sequence(seq, missing_feature_indices)
        X_t = torch.tensor(seq_sc).unsqueeze(0).to(device)

        # Single forward+backward pass gives us the attack/mitre/state
        # predictions, the hidden state (for trajectory chaining), and the
        # gradient-based feature attribution all together.
        shap_features, pred_state, atk_log, mitre_log, hc = _gradient_attribution(X_t)
        attack_head_prob = torch.sigmoid(atk_log).item()
        mitre_cls = int(mitre_log.argmax(dim=1).item())

        # Hybrid score for the *current* step: attack head + calibrated
        # reconstruction error, same scheme as notebook Cell 9 test-set
        # evaluation (we already have the true next-window state, since this
        # is a completed window within the uploaded file).
        current_risk = attack_head_prob
        calibrated_mse = None
        mse_val = None
        if _benign_mse_baseline is not None:
            true_future = states[i + _seq_len].astype(np.float64)
            true_future_sc = _scaler.transform(
                signed_log1p(true_future).reshape(1, -1)
            )[0]
            mse_val = float(np.mean((pred_state.cpu().numpy().flatten() - true_future_sc) ** 2))
            z = (mse_val - _benign_mse_baseline["mean"]) / (_benign_mse_baseline["std"] + 1e-8)
            calibrated_mse = 1 / (1 + np.exp(-(z - 3.0)))
            current_risk = max(attack_head_prob, calibrated_mse)

        # Forward-looking trajectory (Cell 10 style k-step forecast). This is
        # a genuine forecast, not graded against ground truth, so it uses the
        # raw attack-head probability rather than the hybrid score. Reuses
        # the pred_state/atk_log/mitre_log/hidden-state already computed
        # above instead of re-running the forward pass.
        trajectory = _k_step_trajectory(pred_state, atk_log, mitre_log, hc)

        windows_out.append({
            "step_index": len(windows_out),
            "timestamp": timestamps[i + _seq_len].strftime("%H:%M:%S"),
            "flow_count": counts[i + _seq_len],
            "current_risk": round(float(current_risk), 4),
            "current_stage": MITRE_NAMES.get(mitre_cls, "Unknown"),
            "trajectory": trajectory,
            "shap_features": shap_features,
            # TEMPORARY diagnostics — remove once current_risk is verified.
            # Lets you see whether the attack head or the reconstruction-
            # error term is driving current_risk on a given window.
            "_debug": {
                "attack_head_prob": round(float(attack_head_prob), 4),
                "calibrated_mse": round(float(calibrated_mse), 4) if calibrated_mse is not None else None,
                "raw_mse": round(mse_val, 6) if mse_val is not None else None,
                "benign_mse_baseline": _benign_mse_baseline,
            },
        })

    return windows_out


@app.post("/api/upload-csv")
async def upload_csv(file: UploadFile = File(...)):
    if _model is None:
        raise HTTPException(
            status_code=503,
            detail="No trained model checkpoint loaded on the server "
                   "(lstm_world_model.pth missing).",
        )

    content = await file.read()
    decoded = content.decode("utf-8", errors="ignore")
    try:
        df = pd.read_csv(io.StringIO(decoded), low_memory=False)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not parse CSV: {exc}")

    if len(df) == 0:
        raise HTTPException(status_code=400, detail="Uploaded CSV has no rows.")

    states, timestamps, counts, missing_idx = _aggregate_windows(df)

    if len(states) < _seq_len + 1:
        raise HTTPException(
            status_code=422,
            detail=f"Need at least {_seq_len + 1} one-minute traffic windows "
                   f"to run inference, only got {len(states)}. Upload a "
                   f"longer capture.",
        )

    windows = _run_model_inference(states, timestamps, counts, missing_idx)

    scenario_id = f"upload_{uuid.uuid4().hex[:10]}"
    n_attack = sum(1 for w in windows if w["current_risk"] >= _best_threshold)

    # Flat detection log — mirrors the notebook's test_csv_file() console
    # output ("Time | P(Attack) | Is Attack" + anomalous-window summary) so
    # the frontend can render the same log/verdict view, not just the
    # richer trajectory/SHAP view used for the story-mode scenarios.
    detection_log = [
        {
            "timestamp": w["timestamp"],
            "attack_prob": w["current_risk"],
            "is_attack": w["current_risk"] >= _best_threshold,
        }
        for w in windows
    ]
    detection_summary = {
        "model_threshold": _best_threshold,
        "total_windows_evaluated": len(windows),
        "anomalous_windows_detected": n_attack,
        "verdict": (
            "ATTACK DETECTED - malicious traffic flagged in this capture."
            if n_attack > 0
            else "No attack detected in this capture."
        ),
    }

    scenario_entry = {
        "metadata": {
            "name": f"Ingested Dataset: {file.filename}",
            "target_asset": f"Uploaded capture ({file.filename})",
            "total_windows": len(windows),
            "detected_features": list(df.columns)[:8],
            "rows_ingested": len(df),
            "attack_windows_detected": n_attack,
        },
        "windows": windows,
    }

    # Persist so the frontend can page through it via the normal
    # /api/scenario/{id}/step/{idx} endpoint, same as the static scenarios.
    data = load_data()
    data[scenario_id] = scenario_entry
    save_data(data)

    return {
        "status": "success",
        "scenario_id": scenario_id,
        "filename": file.filename,
        "detection_log": detection_log,
        "detection_summary": detection_summary,
        **scenario_entry,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
