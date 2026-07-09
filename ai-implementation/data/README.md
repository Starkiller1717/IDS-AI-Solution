# data/

Put the **CICIDS2017 "MachineLearningCVE" CSV files** in this folder.

- They are the flow-feature CSVs (one per day, ~80 columns + a `Label` column).
- A common source is the Kaggle mirror "CICIDS2017" (search for the
  `MachineLearningCVE` folder of `.csv` files). The official source is the
  University of New Brunswick CIC dataset page.
- The CSVs are large and are **gitignored** on purpose — do not commit them.

`src/detector/train.py` automatically loads every `*.csv` it finds under this
folder (including subfolders), so you can just drop the whole `MachineLearningCVE`
folder in here.

`sample_eve.json` (already here) is a tiny fake Suricata log used by the
`suricata_reader.py --demo` command — it is NOT the training data.
