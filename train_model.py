"""
Trains a Random Forest classifier for intrusion detection.

Expects data/KDDTrain+.csv (NSL-KDD dataset) by default. The NSL-KDD
columns are mapped down to the same feature set the live sniffer computes
(packet_rate, unique_ports, syn_rate, avg_packet_len) using proxy columns,
so the live pipeline and training pipeline line up.

If you use a different dataset (e.g. CICIDS2017), adjust COLUMN_MAP below
to point at equivalent columns.

Usage:
    python train_model.py
"""

import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

DATA_PATH = os.path.join("data", "KDDTrain+.csv")
MODEL_OUT = os.path.join("models", "nids_model.pkl")

# NSL-KDD has no header row by default; these are the standard 41 feature
# names + label + difficulty. Only a subset is used as proxies for our
# live features.
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]


def load_and_map_features(path):
    df = pd.read_csv(path, names=NSL_KDD_COLUMNS)

    # Map NSL-KDD columns to proxies for our 4 live features.
    mapped = pd.DataFrame()
    mapped["packet_rate"] = df["count"]                  # connections to same host in window
    mapped["unique_ports"] = df["dst_host_srv_count"]     # proxy for port diversity
    mapped["syn_rate"] = df["serror_rate"] * df["count"]  # SYN-error-driven connections
    mapped["avg_packet_len"] = df["src_bytes"] + df["dst_bytes"]

    # Collapse attack subtypes into broad categories used by our sniffer;
    # everything that isn't "normal" becomes a generic attack label, but we
    # keep a couple of common named types for a richer demo/report.
    def collapse(label):
        label = label.strip().lower()
        if label == "normal":
            return "normal"
        if label in ("neptune", "back", "land", "pod", "smurf", "teardrop"):
            return "syn_flood"
        if label in ("satan", "ipsweep", "nmap", "portsweep"):
            return "port_scan"
        return "other_attack"

    mapped["label"] = df["label"].apply(collapse)
    return mapped


def main():
    if not os.path.exists(DATA_PATH):
        print(f"[train_model] ERROR: dataset not found at {DATA_PATH}")
        print("Download NSL-KDD's KDDTrain+.csv from "
              "https://www.unb.ca/cic/datasets/nsl.html and place it in data/")
        return

    os.makedirs("models", exist_ok=True)

    print("[train_model] Loading and mapping dataset...")
    df = load_and_map_features(DATA_PATH)

    X = df[["packet_rate", "unique_ports", "syn_rate", "avg_packet_len"]]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[train_model] Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    print("[train_model] Evaluating on held-out test set...")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    joblib.dump({"model": clf, "classes": clf.classes_}, MODEL_OUT)
    print(f"[train_model] Saved trained model to {MODEL_OUT}")


if __name__ == "__main__":
    main()
