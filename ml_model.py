"""
Wraps the trained scikit-learn model for use by the live sniffer.

Falls back to a simple rule-based heuristic if no trained model file is
found yet, so the dashboard still works before you've trained anything
(useful for demoing the pipeline early).
"""

import os
import joblib
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "nids_model.pkl")

FEATURE_ORDER = ["packet_rate", "unique_ports", "syn_rate", "avg_packet_len"]


class NIDSModel:
    def __init__(self):
        self.model = None
        self.classes = None
        if os.path.exists(MODEL_PATH):
            bundle = joblib.load(MODEL_PATH)
            self.model = bundle["model"]
            self.classes = bundle["classes"]
            print("[ml_model] Loaded trained model from", MODEL_PATH)
        else:
            print("[ml_model] No trained model found — using rule-based fallback. "
                  "Run train_model.py to enable ML classification.")

    def predict(self, features: dict):
        if self.model is not None:
            x = np.array([[features[f] for f in FEATURE_ORDER]])
            proba = self.model.predict_proba(x)[0]
            idx = np.argmax(proba)
            return self.classes[idx], float(proba[idx])

        # --- Rule-based fallback (no trained model yet) ---
        # Simple heuristics: a lot of SYNs or ports touched in a short window
        # looks like a scan/flood.
        if features["syn_rate"] > 20:
            return "syn_flood", 0.9
        if features["unique_ports"] > 15:
            return "port_scan", 0.9
        return "normal", 0.6
