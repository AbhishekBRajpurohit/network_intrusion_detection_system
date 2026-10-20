"""Explainable rules and an optional compatible, trusted local model."""
import os
from math import isfinite, isclose
from pathlib import Path
from features import FEATURE_ORDER, WINDOW_SECONDS, SCHEMA_VERSION, LABELS


class NIDSModel:
    def __init__(self, path=None):
        self.model = None
        self.status = 'Rule-based fallback: no compatible model loaded'
        path = Path(path or os.getenv('NIDS_MODEL',
                    str(Path(__file__).parent / 'models/nids_model.pkl')))
        if not path.exists():
            return
        try:
            import joblib
            bundle = joblib.load(path)  # Only load files you trust.
            if (bundle.get('schema_version') != SCHEMA_VERSION or
                    bundle.get('features') != FEATURE_ORDER or
                    bundle.get('window_seconds') != WINDOW_SECONDS):
                raise ValueError('Feature schema mismatch; retrain from labelled PCAPs')
            model = bundle['model']
            if (model.n_features_in_ != len(FEATURE_ORDER) or
                    list(model.feature_names_in_) != FEATURE_ORDER or
                    not set(model.classes_).issubset(LABELS) or
                    'normal' not in model.classes_ or len(model.classes_) < 2):
                raise ValueError('Invalid model features or classes')
            self.model = model
            self.status = 'ML + rules: compatible model loaded'
        except Exception as exc:
            self.status = f'Rule-based fallback: {type(exc).__name__}: {exc}'

    def predict(self, features):
        values = {key: float(features[key]) for key in FEATURE_ORDER}
        if any(not isfinite(v) or v < 0 for v in values.values()):
            raise ValueError('Features must be finite, nonnegative numbers')
        result = {
            'label': 'normal', 'source': 'rule', 'probability': None,
            'severity': 'info', 'features': values,
            'reason': 'No configured rule threshold exceeded; this does not prove traffic is safe',
        }
        if values['syn_rate'] > 20:
            result.update(label='syn_flood', severity='high', reason=
                f"{values['syn_rate']:.1f} initial SYN packets/second "
                f"in {WINDOW_SECONDS} seconds (threshold >20)")
        elif values['unique_ports'] > 15:
            result.update(label='port_scan', severity='medium', reason=
                f"{values['unique_ports']:.0f} destination ports in {WINDOW_SECONDS} seconds "
                '(threshold >15; aggregated across destinations)')
        elif self.model is not None:
            try:
                import pandas as pd
                probabilities = self.model.predict_proba(
                    pd.DataFrame([values], columns=FEATURE_ORDER))[0]
                if (len(probabilities) != len(self.model.classes_) or
                        any(not isfinite(p) or not 0 <= p <= 1 for p in probabilities) or
                        not isclose(sum(probabilities), 1.0, abs_tol=1e-6)):
                    raise ValueError('Invalid model probabilities')
                index = max(range(len(probabilities)), key=probabilities.__getitem__)
                label = str(self.model.classes_[index])
                probability = float(probabilities[index])
                result.update(label=label, source='ml', probability=probability,
                    severity='info' if label == 'normal' else 'high' if probability >= .85 else 'low',
                    reason=f'Model predicted {label}; score is uncalibrated. Inspect the features.')
            except Exception as exc:
                self.model = None
                self.status = f'Rule-based fallback: inference failed: {exc}'
                result['reason'] += '; ML unavailable: ' + str(exc)
        return result
