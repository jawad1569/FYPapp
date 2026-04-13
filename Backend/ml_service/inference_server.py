"""
WazuhBot — Random Forest Inference Service
Loads trained model artifacts and serves predictions over HTTP.
Later: Wazuh MCP → this service → SLM chatbot
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import json
import os
import time

# ─────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────
MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "output"))
PORT      = int(os.environ.get("ML_PORT", 5001))

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────
# LOAD MODEL ARTIFACTS (once at startup)
# ─────────────────────────────────────────
print(f"Loading model artifacts from: {os.path.abspath(MODEL_DIR)}")

try:
    rf_model      = joblib.load(os.path.join(MODEL_DIR, "rf_anomaly_model.pkl"))
    scaler        = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
    feature_list  = joblib.load(os.path.join(MODEL_DIR, "feature_list.pkl"))
    with open(os.path.join(MODEL_DIR, "label_mapping.json")) as f:
        label_mapping = json.load(f)

    # Pre-compute the "Normal" class index for fast lookup
    NORMAL_INDEX = next((int(k) for k, v in label_mapping.items() if v == "Normal"), None)

    print(f"✅ Model loaded — {len(feature_list)} features, {len(label_mapping)} classes")
    print(f"   Classes: {list(label_mapping.values())}")
    MODEL_LOADED = True
except Exception as e:
    print(f"❌ Failed to load model: {e}")
    rf_model = scaler = feature_list = label_mapping = None
    NORMAL_INDEX = None
    MODEL_LOADED = False


# ─────────────────────────────────────────
# HELPER — single prediction
# ─────────────────────────────────────────
def classify_log(parsed_log: dict) -> dict:
    """Run RF inference on a single parsed network flow / Wazuh log."""
    fv = np.array(
        [parsed_log.get(feat, 0) for feat in feature_list],
        dtype=np.float32
    ).reshape(1, -1)

    fv = np.nan_to_num(fv, nan=0.0, posinf=0.0, neginf=0.0)
    fv = scaler.transform(fv)

    prediction    = rf_model.predict(fv)[0]
    probabilities = rf_model.predict_proba(fv)[0]
    confidence    = float(max(probabilities))
    normal_prob   = float(probabilities[NORMAL_INDEX]) if NORMAL_INDEX is not None else None

    return {
        "prediction":         label_mapping[str(prediction)],
        "confidence":         round(confidence, 4),
        "is_threat":          label_mapping[str(prediction)] != "Normal",
        "normal_probability": round(normal_prob, 4) if normal_prob is not None else None,
        "probabilities":      {
            label_mapping[str(i)]: round(float(p), 4)
            for i, p in enumerate(probabilities)
        },
    }


# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":       "ok" if MODEL_LOADED else "degraded",
        "model_loaded": MODEL_LOADED,
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


@app.route("/model-info", methods=["GET"])
def model_info():
    if not MODEL_LOADED:
        return jsonify({"error": "Model not loaded"}), 503

    # Feature importance (top 15)
    importances = sorted(
        zip(feature_list, rf_model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )

    return jsonify({
        "n_features":       len(feature_list),
        "features":         feature_list,
        "n_classes":        len(label_mapping),
        "classes":          list(label_mapping.values()),
        "n_estimators":     rf_model.n_estimators,
        "max_depth":        rf_model.max_depth,
        "top_features":     [{"feature": f, "importance": round(imp, 4)} for f, imp in importances[:15]],
    })


@app.route("/predict", methods=["POST"])
def predict():
    """
    Classify a single network flow / Wazuh log.

    Body JSON:
        { "IN_BYTES": 12000, "OUT_BYTES": 400, "PROTOCOL": 6, ... }
    """
    if not MODEL_LOADED:
        return jsonify({"error": "Model not loaded"}), 503

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be JSON with flow features"}), 400

    try:
        result = classify_log(body)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/batch-predict", methods=["POST"])
def batch_predict():
    """
    Classify multiple logs at once.

    Body JSON:
        { "logs": [ { ... }, { ... }, ... ] }

    Returns:
        { "results": [ { prediction, confidence, ... }, ... ], "count": N }
    """
    if not MODEL_LOADED:
        return jsonify({"error": "Model not loaded"}), 503

    body = request.get_json(silent=True)
    if not body or "logs" not in body:
        return jsonify({"error": "Body must be { \"logs\": [ ... ] }"}), 400

    logs = body["logs"]
    if not isinstance(logs, list) or len(logs) == 0:
        return jsonify({"error": "logs must be a non-empty array"}), 400

    if len(logs) > 500:
        return jsonify({"error": "Max 500 logs per batch"}), 400

    try:
        # Vectorised batch for performance
        X = np.array(
            [[log.get(feat, 0) for feat in feature_list] for log in logs],
            dtype=np.float32
        )
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        X = scaler.transform(X)

        predictions   = rf_model.predict(X)
        probabilities = rf_model.predict_proba(X)

        results = []
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            confidence  = float(max(probs))
            normal_prob = float(probs[NORMAL_INDEX]) if NORMAL_INDEX is not None else None
            results.append({
                "prediction":         label_mapping[str(pred)],
                "confidence":         round(confidence, 4),
                "is_threat":          label_mapping[str(pred)] != "Normal",
                "normal_probability": round(normal_prob, 4) if normal_prob is not None else None,
                "probabilities":      {
                    label_mapping[str(j)]: round(float(p), 4)
                    for j, p in enumerate(probs)
                },
            })

        # Summary stats
        threat_count  = sum(1 for r in results if r["is_threat"])
        class_counts  = {}
        for r in results:
            cls = r["prediction"]
            class_counts[cls] = class_counts.get(cls, 0) + 1

        return jsonify({
            "results":       results,
            "count":         len(results),
            "threat_count":  threat_count,
            "normal_count":  len(results) - threat_count,
            "class_summary": class_counts,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n🚀 ML Inference Service starting on http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
