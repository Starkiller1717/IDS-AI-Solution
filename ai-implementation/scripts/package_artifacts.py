"""
Build the single zip that gets handed to a teammate or copied to the Suricata VM.

WHY THIS EXISTS
---------------
`detector.joblib` is ~110 MB and gitignored, so `git clone` can never produce a
working install on its own. Something has to carry the model out of band, and
doing that by hand produced three different zips in this directory with three
different names, one of them truncated and one of them empty.

This makes the bundle reproducible and self-describing instead:

    python scripts/package_artifacts.py

The output name carries the model version, so a stale bundle is obvious on sight.

WHAT GOES IN
------------
Only what the runtime needs to score traffic: the model, the feature order, and
the build metadata. No dataset, no source -- the source comes from git.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

# Allow `python scripts/package_artifacts.py` from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import config  # noqa: E402

DIST_DIR = config.PROJECT_ROOT / "dist"

INSTALL_NOTES = """\
Detector artifacts for the Suricata AI IDS
==========================================

These three files are everything the scoring path needs at runtime. They are NOT
in git -- detector.joblib is ~110 MB -- which is why they travel as a zip.

INSTALL
-------
1. Clone the repo and enter the ai-implementation/ directory.
2. Create a virtualenv and install the PINNED dependencies:

       python -m venv .venv
       .venv\\Scripts\\Activate.ps1          # Windows PowerShell
       source .venv/bin/activate            # Linux / macOS
       pip install -r requirements-lock.txt

   Use requirements-lock.txt, not requirements.txt. Loading a scikit-learn
   pickle under a different version than it was saved with is not a supported
   deployment path.

3. Unzip these files into the repo's models/ directory:

       models/detector.joblib
       models/feature_columns.json
       models/metadata.json

4. Verify the install actually works:

       python -m src.smoke_test

   That loads the model and scores two known flows without needing the
   CICIDS2017 dataset. It exits 0 on success. If it fails, the message says
   what to fix -- send it verbatim rather than guessing.

WHAT'S IN metadata.json
-----------------------
The package versions this model was built with, its feature list, and the
thresholds in force at build time. The smoke test compares that to your live
environment and warns on any drift.
"""


def main() -> int:
    required = {
        config.MODEL_PATH: "run `python -m src.detector.train`",
        config.FEATURE_COLUMNS_PATH: "run `python -m src.detector.train`",
        config.MODEL_METADATA_PATH: "run `python -m src.detector.train`",
    }
    missing = [(path, hint) for path, hint in required.items() if not path.exists()]
    if missing:
        for path, hint in missing:
            print(f"missing: {path}  ->  {hint}")
        return 1

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    bundle_path = DIST_DIR / f"detector-artifacts-{config.MODEL_VERSION}.zip"

    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in required:
            bundle.write(path, arcname=path.name)
        bundle.writestr("INSTALL.txt", INSTALL_NOTES)

    # Read it back. The truncated zip this script replaces looked fine on disk
    # and only failed when someone tried to open it -- which was, of course,
    # the teammate on the receiving end.
    with zipfile.ZipFile(bundle_path) as bundle:
        broken = bundle.testzip()
        if broken is not None:
            print(f"FAILED: bundle is corrupt at {broken}")
            return 1
        entries = bundle.namelist()

    size_mb = bundle_path.stat().st_size / (1024 * 1024)
    print(f"Wrote {bundle_path}  ({size_mb:.1f} MB)")
    for entry in entries:
        print(f"  - {entry}")
    print("\nVerified: bundle opens and every entry passes its CRC check.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
