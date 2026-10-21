"""Explainable rules with an optional compatible local ML model."""

import os
from math import isfinite, isclose
from pathlib import Path

from features import (
    FEATURE_ORDER,
    WINDOW_SECONDS,
    SCHEMA_VERSION,
    LABELS,
)


class NIDSModel:
    def __init__(self, path=None):
        self.syn_rate_threshold = float(
            os.getenv("NIDS_SYN_RATE_THRESHOLD", "20")
        )

        self.port_scan_threshold = int(
            os.getenv("NIDS_PORT_SCAN_THRESHOLD", "15")
        )

        if (
            not isfinite(self.syn_rate_threshold)
            or self.syn_rate_threshold <= 0
        ):
            raise ValueError(
                "NIDS_SYN_RATE_THRESHOLD must be a positive finite number"
            )

        if self.port_scan_threshold <= 0:
            raise ValueError(
                "NIDS_PORT_SCAN_THRESHOLD must be a positive integer"
            )

        self.model = None
        self.status = "Rule-based fallback: no compatible model loaded"

        default_path = (
            Path(__file__).parent / "models" / "nids_model.pkl"
        )

        model_path = Path(
            path or os.getenv("NIDS_MODEL", str(default_path))
        )

        if not model_path.exists():
            return

        try:
            import joblib

            # Pickle/joblib files can execute code. Load trusted files only.
            bundle = joblib.load(model_path)

            if not isinstance(bundle, dict):
                raise ValueError("Model file must contain a metadata bundle")

            if (
                bundle.get("schema_version") != SCHEMA_VERSION
                or bundle.get("features") != FEATURE_ORDER
                or bundle.get("window_seconds") != WINDOW_SECONDS
            ):
                raise ValueError(
                    "Feature schema mismatch; retrain from labelled PCAPs"
                )

            candidate = bundle["model"]

            if (
                candidate.n_features_in_ != len(FEATURE_ORDER)
                or list(candidate.feature_names_in_) != FEATURE_ORDER
                or not set(candidate.classes_).issubset(LABELS)
                or "normal" not in candidate.classes_
                or len(candidate.classes_) < 2
                or not callable(getattr(candidate, "predict_proba", None))
            ):
                raise ValueError("Invalid model features or classes")

            self.model = candidate
            self.status = "ML + rules: compatible model loaded"

        except Exception as exc:
            self.status = (
                f"Rule-based fallback: {type(exc).__name__}: {exc}"
            )

    def predict(self, features):
        values = {
            key: float(features[key])
            for key in FEATURE_ORDER
        }

        if any(
            not isfinite(value) or value < 0
            for value in values.values()
        ):
            raise ValueError(
                "Features must be finite, nonnegative numbers"
            )

        result = {
            "label": "normal",
            "source": "rule",
            "probability": None,
            "severity": "info",
            "features": values,
            "reason": (
                "No configured rule threshold exceeded; "
                "this does not prove traffic is safe"
            ),
        }

        if values["syn_rate"] > self.syn_rate_threshold:
            result.update(
                label="syn_flood",
                severity="high",
                reason=(
                    f"{values['syn_rate']:.1f} initial SYN packets/second "
                    f"in a {WINDOW_SECONDS}-second window "
                    f"(threshold >{self.syn_rate_threshold:g})"
                ),
            )

        elif values["unique_ports"] > self.port_scan_threshold:
            result.update(
                label="port_scan",
                severity="medium",
                reason=(
                    f"{values['unique_ports']:.0f} destination ports "
                    f"in {WINDOW_SECONDS} seconds "
                    f"(threshold >{self.port_scan_threshold}; "
                    "aggregated across destinations)"
                ),
            )

        elif self.model is not None:
            try:
                import pandas as pd

                frame = pd.DataFrame(
                    [values],
                    columns=FEATURE_ORDER,
                )

                probabilities = self.model.predict_proba(frame)[0]

                if (
                    len(probabilities) != len(self.model.classes_)
                    or any(
                        not isfinite(value) or not 0 <= value <= 1
                        for value in probabilities
                    )
                    or not isclose(
                        sum(probabilities),
                        1.0,
                        abs_tol=1e-6,
                    )
                ):
                    raise ValueError("Invalid model probabilities")

                index = max(
                    range(len(probabilities)),
                    key=probabilities.__getitem__,
                )

                label = str(self.model.classes_[index])
                probability = float(probabilities[index])

                severity = (
                    "info" if label == "normal"
                    else "high" if probability >= 0.85
                    else "low"
                )

                result.update(
                    label=label,
                    source="ml",
                    probability=probability,
                    severity=severity,
                    reason=(
                        f"Model predicted {label}; score is uncalibrated. "
                        "Inspect the features."
                    ),
                )

            except Exception as exc:
                self.model = None
                self.status = (
                    f"Rule-based fallback: inference failed: {exc}"
                )
                result["reason"] += f"; ML unavailable: {exc}"

        return result