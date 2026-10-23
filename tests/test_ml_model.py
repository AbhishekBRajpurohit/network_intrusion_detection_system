"""Deterministic model tests without loading the project's saved model."""

import os
import tempfile
import unittest

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from features import (
    FEATURE_ORDER,
    SCHEMA_VERSION,
    WINDOW_SECONDS,
)

from ml_model import NIDSModel


class TestMLModel(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.directory = Path(temporary.name)

        environment = patch.dict(os.environ, {
            "NIDS_SYN_RATE_THRESHOLD": "20",
            "NIDS_PORT_SCAN_THRESHOLD": "15",
        })

        environment.start()
        self.addCleanup(environment.stop)

        self.detector = NIDSModel(
            self.directory / "missing.pkl"
        )

        self.features = {
            "packet_rate": 30.0,
            "unique_ports": 2,
            "syn_rate": 1.0,
            "avg_packet_len": 100.0,
        }

    def fake_model(self, probabilities):
        return SimpleNamespace(
            classes_=["normal", "port_scan"],
            n_features_in_=len(FEATURE_ORDER),
            feature_names_in_=FEATURE_ORDER,
            predict_proba=Mock(
                return_value=[probabilities]
            ),
        )

    def test_missing_model_uses_rules(self):
        result = self.detector.predict(self.features)

        self.assertEqual(result["label"], "normal")
        self.assertEqual(result["source"], "rule")
        self.assertIsNone(result["probability"])

    def test_syn_flood_rule(self):
        result = self.detector.predict({
            **self.features,
            "syn_rate": 21,
        })

        self.assertEqual(result["label"], "syn_flood")
        self.assertEqual(result["severity"], "high")
        self.assertIsNone(result["probability"])

        self.assertIn(
            "initial SYN packets/second",
            result["reason"],
        )

    def test_port_scan_rule(self):
        result = self.detector.predict({
            **self.features,
            "unique_ports": 16,
        })

        self.assertEqual(result["label"], "port_scan")
        self.assertEqual(result["severity"], "medium")

        self.assertIn(
            "destination ports",
            result["reason"],
        )

    def test_exact_threshold_does_not_trigger_rule(self):
        result = self.detector.predict({
            **self.features,
            "syn_rate": 20,
            "unique_ports": 15,
        })

        self.assertEqual(result["label"], "normal")

    def test_rules_take_precedence_over_model(self):
        model = self.fake_model([1.0, 0.0])
        self.detector.model = model

        result = self.detector.predict({
            **self.features,
            "syn_rate": 25,
            "unique_ports": 20,
        })

        self.assertEqual(result["label"], "syn_flood")
        model.predict_proba.assert_not_called()

    def test_custom_thresholds(self):
        with patch.dict(os.environ, {
            "NIDS_SYN_RATE_THRESHOLD": "40",
            "NIDS_PORT_SCAN_THRESHOLD": "30",
        }):
            detector = NIDSModel(
                self.directory / "missing.pkl"
            )

        result = detector.predict({
            **self.features,
            "syn_rate": 25,
            "unique_ports": 20,
        })

        self.assertEqual(result["label"], "normal")

    def test_invalid_feature_numbers(self):
        for value in (-1, float("nan"), float("inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.detector.predict({
                        **self.features,
                        "syn_rate": value,
                    })

    def test_model_prediction_preserves_feature_order(self):
        model = self.fake_model([0.1, 0.9])
        self.detector.model = model

        result = self.detector.predict(self.features)

        self.assertEqual(result["label"], "port_scan")
        self.assertEqual(result["source"], "ml")
        self.assertEqual(result["probability"], 0.9)

        frame = model.predict_proba.call_args.args[0]

        self.assertEqual(
            list(frame.columns),
            FEATURE_ORDER,
        )

    def test_invalid_probabilities_disable_model(self):
        cases = [
            [0.8, 0.8],
            [float("nan"), 0.5],
            [-0.1, 1.1],
        ]

        for probabilities in cases:
            with self.subTest(probabilities=probabilities):
                self.detector.model = self.fake_model(
                    probabilities
                )

                result = self.detector.predict(self.features)

                self.assertIsNone(self.detector.model)
                self.assertEqual(result["source"], "rule")
                self.assertIsNone(result["probability"])

                self.assertIn(
                    "ML unavailable",
                    result["reason"],
                )

    def test_inference_exception_falls_back_to_rules(self):
        model = self.fake_model([0.5, 0.5])

        model.predict_proba.side_effect = RuntimeError(
            "Synthetic model failure"
        )

        self.detector.model = model
        result = self.detector.predict(self.features)

        self.assertEqual(result["source"], "rule")

        self.assertIn(
            "inference failed",
            self.detector.status,
        )

    def test_loader_checks_schema_and_feature_order(self):
        path = self.directory / "fixture.pkl"
        path.touch()

        bundle = {
            "model": self.fake_model([0.9, 0.1]),
            "schema_version": SCHEMA_VERSION,
            "features": FEATURE_ORDER,
            "window_seconds": WINDOW_SECONDS,
        }

        # Mock loading so no real pickle is executed.
        with patch("joblib.load", return_value=bundle):
            self.assertIsNotNone(NIDSModel(path).model)

        changes = [
            {"schema_version": "obsolete-schema"},
            {"features": list(reversed(FEATURE_ORDER))},
            {"window_seconds": WINDOW_SECONDS + 1},
        ]

        for change in changes:
            with self.subTest(change=change):
                with patch(
                    "joblib.load",
                    return_value={**bundle, **change},
                ):
                    self.assertIsNone(NIDSModel(path).model)


if __name__ == "__main__":
    unittest.main()