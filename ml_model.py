"""Explainable rules with an optional compatible, locally trained model."""
from pathlib import Path
import os
from features import FEATURE_ORDER, WINDOW_SECONDS, SCHEMA_VERSION

class NIDSModel:
    def __init__(self, path=None):
        self.model = None
        self.status = 'Rule-based fallback: no compatible model loaded'
        path = Path(path or os.getenv('NIDS_MODEL', Path(__file__).parent/'models/nids_model.pkl'))
        if path.exists():
            try:
                import joblib
                bundle = joblib.load(path)  # Only load trusted local model files.
                if (bundle.get('schema_version') != SCHEMA_VERSION or
                    bundle.get('features') != FEATURE_ORDER or bundle.get('window_seconds') != WINDOW_SECONDS):
                    raise ValueError('Feature schema mismatch; retrain using labelled PCAPs')
                self.model = bundle['model']
                self.status = 'ML + rules: compatible model loaded'
            except Exception as exc:
                self.status = f'Rule-based fallback: {type(exc).__name__}: {exc}'

    def predict(self, features):
        # Explicit precedence: flood, scan, then ML. Rule scores are not probabilities.
        result = {'label': 'normal', 'source': 'rule', 'probability': None,
                  'severity': 'info', 'reason': 'No configured rule threshold exceeded',
                  'features': features}
        if features['syn_rate'] > 20:
            result.update(label='syn_flood', severity='high',
                reason=f"{features['syn_rate']:.1f} initial SYN packets/second in a {WINDOW_SECONDS}-second window (threshold >20)")
        elif features['unique_ports'] > 15:
            result.update(label='port_scan', severity='medium',
                reason=f"{features['unique_ports']} destination ports in {WINDOW_SECONDS} seconds (threshold >15; aggregated across destinations)")
        elif self.model is not None:
            import pandas as pd
            probabilities = self.model.predict_proba(pd.DataFrame([features], columns=FEATURE_ORDER))[0]
            index = int(probabilities.argmax())
            label, probability = str(self.model.classes_[index]), float(probabilities[index])
            result.update(label=label, source='ml', probability=probability,
                severity='info' if label == 'normal' else 'high' if probability >= .85 else 'low',
                reason=f'Model predicted {label}; probability is uncalibrated. Inspect feature values.')
        return result