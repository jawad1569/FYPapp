"""
WazuhBot — Random Forest Inference Service
Loads trained model artifacts and serves predictions over HTTP.
Later: Wazuh MCP → this service → SLM chatbot
"""

import sys
sys.stdout.reconfigure(encoding='utf-8')

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
# HELPER — feature enrichment
# ─────────────────────────────────────────
def enrich_flow(raw: dict) -> dict:
    """
    Derive all 40 model features from the 9 basic fields that Wazuh can provide.
    Without this, missing features default to zero and the model always predicts DDoS.
    """
    in_b   = float(raw.get("IN_BYTES",    0) or 0)
    out_b  = float(raw.get("OUT_BYTES",   0) or 0)
    in_p   = max(float(raw.get("IN_PKTS",  1) or 1), 1)
    out_p  = max(float(raw.get("OUT_PKTS", 1) or 1), 1)
    dur    = max(float(raw.get("DURATION", 1) or 1), 1)
    proto  = float(raw.get("PROTOCOL",    6) or 6)
    dport  = float(raw.get("L4_DST_PORT", 0) or 0)
    sport  = float(raw.get("L4_SRC_PORT", 0) or 0)
    flags  = float(raw.get("TCP_FLAGS",  24) or 24)

    avg_in_pkt  = in_b / in_p
    avg_out_pkt = out_b / out_p

    enriched = dict(raw)
    enriched.update({
        "FLOW_DURATION_MILLISECONDS": dur * 1000,
        "DURATION_IN":                dur,
        "DURATION_OUT":               dur,
        "MIN_TTL":                    64,
        "MAX_TTL":                    128,
        "LONGEST_FLOW_PKT":           max(avg_in_pkt, avg_out_pkt),
        "SHORTEST_FLOW_PKT":          min(avg_in_pkt, avg_out_pkt),
        "MIN_IP_PKT_LEN":             min(avg_in_pkt, avg_out_pkt),
        "MAX_IP_PKT_LEN":             max(avg_in_pkt, avg_out_pkt),
        "SRC_TO_DST_SECOND_BYTES":    in_b  / dur,
        "DST_TO_SRC_SECOND_BYTES":    out_b / dur,
        "RETRANSMITTED_IN_BYTES":     0,
        "RETRANSMITTED_IN_PKTS":      0,
        "RETRANSMITTED_OUT_BYTES":    0,
        "RETRANSMITTED_OUT_PKTS":     0,
        "SRC_TO_DST_AVG_THROUGHPUT":  in_b  * 8 / dur,
        "DST_TO_SRC_AVG_THROUGHPUT":  out_b * 8 / dur,
        "NUM_PKTS_UP_TO_128_BYTES":    in_p if avg_in_pkt <= 128              else 0,
        "NUM_PKTS_128_TO_256_BYTES":   in_p if 128  < avg_in_pkt <= 256       else 0,
        "NUM_PKTS_256_TO_512_BYTES":   in_p if 256  < avg_in_pkt <= 512       else 0,
        "NUM_PKTS_512_TO_1024_BYTES":  in_p if 512  < avg_in_pkt <= 1024      else 0,
        "NUM_PKTS_1024_TO_1514_BYTES": in_p if avg_in_pkt > 1024              else 0,
        "TCP_WIN_MAX_IN":              65535 if proto == 6 else 0,
        "TCP_WIN_MAX_OUT":             65535 if proto == 6 else 0,
        "ICMP_TYPE":                   0,
        "ICMP_IPV4_TYPE":              0,
        "DNS_QUERY_ID":                0,
        "DNS_QUERY_TYPE":              1 if dport == 53 else 0,
        "DNS_TTL_ANSWER":              0,
        "FTP_COMMAND_RET_CODE":        0,
        "CLIENT_TCP_FLAGS":            flags,
        "SERVER_TCP_FLAGS":            24 if proto == 6 else 0,
    })
    return enriched


# ─────────────────────────────────────────
# HELPER — single prediction
# ─────────────────────────────────────────
def classify_log(parsed_log: dict) -> dict:
    """Run RF inference on a single parsed network flow / Wazuh log."""
    parsed_log = enrich_flow(parsed_log)
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
        # Enrich each flow with derived features before vectorising
        logs = [enrich_flow(log) for log in logs]

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
