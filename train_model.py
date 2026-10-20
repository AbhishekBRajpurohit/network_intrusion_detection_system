"""Train from labelled PCAP feature CSVs, keeping capture sessions separate."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from features import FEATURE_ORDER, WINDOW_SECONDS, SCHEMA_VERSION, LABELS


METADATA = ['label', 'session', 'capture_sha256', 'schema_version', 'window_seconds']


def load_features(paths):
    frames = []
    for path in paths:
        frame = pd.read_csv(path, dtype={key: str for key in METADATA if key != 'window_seconds'})
        missing = set(FEATURE_ORDER + METADATA) - set(frame.columns)
        if missing:
            raise ValueError(f'{path}: missing columns {sorted(missing)}; re-export the PCAP')
        if frame.empty or frame[FEATURE_ORDER + METADATA].isna().any().any():
            raise ValueError(f'{path}: empty data or missing values')
        frames.append(frame[FEATURE_ORDER + METADATA])
    data = pd.concat(frames, ignore_index=True)
    if not data['schema_version'].eq(SCHEMA_VERSION).all():
        raise ValueError('Feature schema mismatch; re-export all PCAPs')
    if not pd.to_numeric(data['window_seconds']).eq(WINDOW_SECONDS).all():
        raise ValueError('Feature window mismatch')
    for key in FEATURE_ORDER:
        data[key] = pd.to_numeric(data[key], errors='raise')
    values = data[FEATURE_ORDER].to_numpy(dtype=float)
    if not np.isfinite(values).all() or (values < 0).any():
        raise ValueError('Features must be finite and nonnegative')
    data['session'] = data['session'].str.strip()
    if data['session'].eq('').any():
        raise ValueError('Session IDs cannot be blank')
    if not data['capture_sha256'].str.fullmatch(r'[0-9a-f]{64}').all():
        raise ValueError('Invalid capture hashes; re-export the PCAP')
    if data.groupby('capture_sha256')['session'].nunique().max() > 1:
        raise ValueError('One capture has multiple session IDs; use the same session ID')
    classes = set(data['label'])
    if not classes.issubset(LABELS) or 'normal' not in classes or len(classes) < 2:
        raise ValueError('Need normal traffic and at least one supported attack label')
    if data['session'].nunique() < 4:
        raise ValueError('Need at least four independent capture sessions')
    if (data.groupby('label')['session'].nunique() < 2).any():
        raise ValueError('Each label needs at least two independent sessions')
    return data


def train(paths, output):
    output = Path(output)
    report_path = output.with_suffix('.metrics.json')
    if output.exists() or report_path.exists():
        raise FileExistsError('Choose a new output name; existing model/report will not be overwritten')
    data = load_features(paths)
    x, y = data[FEATURE_ORDER], data['label']
    # Never split overlapping windows from one session across train and test.
    splitter = GroupShuffleSplit(n_splits=100, test_size=.5, random_state=42)
    classes = set(y)
    for train_ids, test_ids in splitter.split(x, y, groups=data['session']):
        if set(y.iloc[train_ids]) == classes and set(y.iloc[test_ids]) == classes:
            break
    else:
        raise ValueError('Cannot represent every label in both splits; collect more sessions')
    model = RandomForestClassifier(n_estimators=200, max_depth=12,
        class_weight='balanced', random_state=42, n_jobs=-1)
    model.fit(x.iloc[train_ids], y.iloc[train_ids])
    actual = y.iloc[test_ids]
    predicted = model.predict(x.iloc[test_ids])
    normal = actual.to_numpy() == 'normal'
    report = {
        'evaluation': 'ML only; does not measure the combined rules + ML pipeline',
        'trained_at': datetime.now(timezone.utc).isoformat(),
        'schema_version': SCHEMA_VERSION,
        'features': FEATURE_ORDER,
        'window_seconds': WINDOW_SECONDS,
        'train_sessions': sorted(data.iloc[train_ids]['session'].unique().tolist()),
        'test_sessions': sorted(data.iloc[test_ids]['session'].unique().tolist()),
        'train_rows': len(train_ids), 'test_rows': len(test_ids),
        'classes': model.classes_.tolist(),
        'classification_report': classification_report(actual, predicted, output_dict=True, zero_division=0),
        'confusion_matrix': confusion_matrix(actual, predicted, labels=model.classes_).tolist(),
        'normal_false_positive_rate': float((predicted[normal] != 'normal').mean()),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    # New file names preserve the previous model for rollback.
    with output.open('xb') as stream:
        joblib.dump({'model': model, 'features': FEATURE_ORDER,
            'schema_version': SCHEMA_VERSION, 'window_seconds': WINDOW_SECONDS,
            'training': report}, stream)
    with report_path.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
    print(classification_report(actual, predicted, zero_division=0))
    print(f'Normal-traffic false-positive rate: {report["normal_false_positive_rate"]:.2%}')
    print(f'Model: {output}\nEvaluation: {report_path}')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv_files', nargs='+')
    parser.add_argument('--output', default='models/nids_model_v3.pkl')
    args = parser.parse_args()
    try:
        train(args.csv_files, args.output)
    except Exception as exc:
        parser.exit(1, f'Training failed: {exc}\n')
