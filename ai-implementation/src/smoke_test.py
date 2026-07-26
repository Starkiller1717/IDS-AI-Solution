"""
Portability gate: prove this checkout can actually score traffic on THIS machine.

WHY THIS FILE EXISTS
--------------------
`pytest` proves the logic is right, but every test runs against fake or
monkeypatched models — the suite passes on a machine with no `detector.joblib`
at all. That is deliberate, but it means a green test run says nothing about
whether a teammate's clone can score a real flow.

This module is the missing check. It is the thing to run after a fresh clone,
after unzipping the model artifacts, and on the Suricata VM after deploying:

    python -m src.smoke_test

It exits 0 only if the real trained model loaded and produced sane predictions,
and non-zero otherwise, so it also works as a deployment health check.

WHAT IT DELIBERATELY DOES NOT NEED
----------------------------------
The CICIDS2017 CSVs. The live scoring path must never touch training data, so
this asserts that too (CHECK 2) rather than trusting that it stayed true.
"""

from __future__ import annotations

import platform
import sys

from src import config

# A flow shaped after a real CICIDS2017 PortScan row. demo.py uses the same
# numbers and documents them as scoring 100 against models/detector.joblib.
ATTACK_FLOW_EVENT = {
    "timestamp": "2026-06-07T14:32:10.000000+0000",
    "flow_id": 990001112223,
    "event_type": "flow",
    "src_ip": "10.0.0.66",
    "dest_ip": "10.0.0.1",
    "dest_port": 80,
    "proto": "TCP",
    "flow": {
        "pkts_toserver": 2,
        "pkts_toclient": 1,
        "bytes_toserver": 8,
        "bytes_toclient": 2,
        "start": "2026-06-07T14:32:10.000000+0000",
        "end": "2026-06-07T14:32:10.000738+0000",
    },
}

# An ordinary HTTPS session — the first flow in data/sample_eve.json. Included so
# the smoke test fails if the model starts alerting on everything, which a
# single attack-only check would not catch.
BENIGN_FLOW_EVENT = {
    "timestamp": "2026-06-07T14:30:00.000000+0000",
    "flow_id": 56709423455001,
    "event_type": "flow",
    "src_ip": "10.0.0.5",
    "dest_ip": "10.0.0.1",
    "dest_port": 443,
    "proto": "TCP",
    "flow": {
        "pkts_toserver": 12,
        "pkts_toclient": 14,
        "bytes_toserver": 1840,
        "bytes_toclient": 9210,
        "start": "2026-06-07T14:29:58.000000+0000",
        "end": "2026-06-07T14:30:00.000000+0000",
    },
}

TRAINING_MODULES = ("src.detector.train", "src.detector.evaluate_threshold")


class SmokeFailure(Exception):
    """A check that must pass for this checkout to be considered working."""


def _ok(message: str) -> None:
    print(f"  [ok]   {message}")


def _warn(message: str) -> None:
    print(f"  [warn] {message}")


def check_environment() -> None:
    """CHECK 1: report the versions that will load the pickle."""
    import joblib
    import numpy
    import pandas
    import sklearn

    print(f"  python       {platform.python_version()}  ({platform.system()})")
    print(f"  scikit-learn {sklearn.__version__}")
    print(f"  pandas       {pandas.__version__}")
    print(f"  numpy        {numpy.__version__}")
    print(f"  joblib       {joblib.__version__}")


def check_no_training_imports() -> None:
    """CHECK 2: the scoring path must not drag in training code.

    If an inference module imports train.py, train.py's module-level code runs
    on import, and anything it touches (the CICIDS2017 CSVs) becomes a runtime
    dependency. That turns a missing dataset into a crash on a machine that was
    only ever meant to score traffic.
    """
    leaked = [name for name in TRAINING_MODULES if name in sys.modules]
    if leaked:
        raise SmokeFailure(
            f"training modules were imported by the scoring path: {leaked}. "
            "Inference must never import train.py or evaluate_threshold.py."
        )
    _ok("scoring path imported no training modules")


def check_artifacts_present() -> None:
    """CHECK 3: fail with an actionable message rather than a stack trace."""
    if not config.MODEL_PATH.exists():
        raise SmokeFailure(
            f"no trained model at {config.MODEL_PATH}\n"
            "         The model is ~110 MB and is NOT in git. Either unzip the "
            "artifact bundle a\n         teammate sent you into models/, or "
            "train one with `python -m src.detector.train`."
        )
    size_mb = config.MODEL_PATH.stat().st_size / (1024 * 1024)
    _ok(f"model present ({size_mb:.0f} MB)")


def check_metadata() -> None:
    """CHECK 4: compare the artifact's build environment to this one.

    Loading a scikit-learn pickle under a different version than it was saved
    with is not a supported deployment path — it can load without error and
    still behave differently. A mismatch is reported as a warning rather than a
    failure because it usually still works; it is printed loudly because it is
    the first thing to suspect if predictions look wrong.
    """
    import json

    if not config.MODEL_METADATA_PATH.exists():
        _warn(
            f"no {config.MODEL_METADATA_PATH.name} next to the model — cannot verify "
            "which\n         environment built it. Retrain, or copy the file from "
            "whoever sent you the model."
        )
        return

    metadata = json.loads(config.MODEL_METADATA_PATH.read_text(encoding="utf-8"))
    _ok(
        f"metadata: model_version={metadata.get('model_version')} "
        f"built={metadata.get('created_utc')}"
    )

    if metadata.get("feature_columns") != list(config.SURICATA_ALIGNED_FEATURES):
        raise SmokeFailure(
            "metadata.json's feature_columns disagree with "
            "config.SURICATA_ALIGNED_FEATURES.\n"
            "         This model was built for a different feature set — retrain."
        )

    import joblib
    import numpy
    import pandas
    import sklearn

    live = {
        "scikit-learn": sklearn.__version__,
        "pandas": pandas.__version__,
        "numpy": numpy.__version__,
        "joblib": joblib.__version__,
    }
    built = metadata.get("environment", {})
    drifted = [
        f"{pkg}: built with {built[pkg]}, running {version}"
        for pkg, version in live.items()
        if pkg in built and built[pkg] != version
    ]
    if drifted:
        _warn("package versions differ from the ones that built this model:")
        for line in drifted:
            print(f"           {line}")
        print("           Install the pinned set: pip install -r requirements-lock.txt")
    else:
        _ok("package versions match the ones that built this model")


def check_predictions() -> None:
    """CHECK 5: run the real runtime path end to end on two known flows."""
    from src.detector.predict import predict
    from src.detector.suricata_reader import flow_to_features

    results = {}
    for name, event in (("attack", ATTACK_FLOW_EVENT), ("benign", BENIGN_FLOW_EVENT)):
        features = flow_to_features(event)
        missing = [f for f in config.SURICATA_ALIGNED_FEATURES if f not in features]
        if missing:
            raise SmokeFailure(
                f"flow_to_features() did not produce {missing} — the Suricata "
                "mapping and config.SURICATA_ALIGNED_FEATURES have drifted apart."
            )
        result = predict(features)
        results[name] = result
        _ok(
            f"{name:<6} flow -> classification={result['classification']:<6} "
            f"score={result['score']:<3} alert={result['is_alert_triggered']}"
        )

    if not results["attack"]["is_alert_triggered"]:
        raise SmokeFailure(
            "the known attack-shaped flow did not trigger an alert "
            f"(score {results['attack']['score']}, threshold {config.ALERT_THRESHOLD}). "
            "The model loaded but is not behaving as expected."
        )
    if results["benign"]["is_alert_triggered"]:
        raise SmokeFailure(
            "an ordinary HTTPS flow triggered a high-priority alert "
            f"(score {results['benign']['score']}). The model is over-alerting."
        )


CHECKS = (
    ("Environment", check_environment),
    ("No training imports", check_no_training_imports),
    ("Model artifact", check_artifacts_present),
    ("Build metadata", check_metadata),
    ("Predictions", check_predictions),
)


def main() -> int:
    print("=" * 70)
    print("SMOKE TEST — can this checkout score a network flow?")
    print("=" * 70)

    for index, (title, check) in enumerate(CHECKS, start=1):
        print(f"\n{index}. {title}")
        try:
            check()
        except SmokeFailure as failure:
            print(f"  [FAIL] {failure}")
            print("\n" + "=" * 70)
            print("SMOKE TEST FAILED")
            print("=" * 70)
            return 1

    print("\n" + "=" * 70)
    print("SMOKE TEST PASSED — model loaded and scored real flows, no dataset needed.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
