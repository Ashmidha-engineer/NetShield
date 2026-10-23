
from pathlib import Path
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

warnings.filterwarnings("ignore")

DATA_DIR = Path("dataset/dns_arp_selected/CSV")
MODEL_DIR = Path("models")
MODEL_PATH = MODEL_DIR / "spoofing_flow_model.joblib"

LABELS = {
    "Benign_Final": "BENIGN",
    "MITM-ArpSpoofing": "ARP_SPOOFING",
    "DNS_Spoofing": "DNS_SPOOFING",
}

MAX_ROWS_PER_FILE = 12000
CHUNK_SIZE = 50000
RANDOM_STATE = 42


def load_sample(path, label):
    parts = []
    collected = 0

    for chunk in pd.read_csv(path, chunksize=CHUNK_SIZE, low_memory=True):
        chunk.columns = chunk.columns.str.strip()
        chunk = chunk.replace([np.inf, -np.inf], np.nan)

        # Use numeric traffic features only; labels come from source folders.
        chunk = chunk.apply(pd.to_numeric, errors="coerce")
        chunk = chunk.dropna(axis=1, how="all")

        if chunk.empty:
            continue

        remaining = MAX_ROWS_PER_FILE - collected
        if remaining <= 0:
            break

        take = min(500, remaining, len(chunk))
        parts.append(chunk.sample(n=take, random_state=RANDOM_STATE))
        collected += take

    if not parts:
        raise ValueError(f"No usable numeric rows found in {path}")

    result = pd.concat(parts, ignore_index=True)
    result["target"] = label
    print(f"{path.name}: sampled {len(result):,} rows as {label}")
    return result


def main():
    if not DATA_DIR.exists():
        raise FileNotFoundError(f"Dataset folder not found: {DATA_DIR}")

    frames = []
    for folder, label in LABELS.items():
        files = sorted((DATA_DIR / folder).glob("*.csv"))
        if not files:
            raise FileNotFoundError(f"No CSV found in {DATA_DIR / folder}")

        for path in files:
            frames.append(load_sample(path, label))

    # Keep only features present in every selected file.
    common_features = sorted(
        set.intersection(*(set(frame.columns) - {"target"} for frame in frames))
    )
    if not common_features:
        raise ValueError("No common feature columns across the selected CSV files.")

    data = pd.concat(
        [frame[common_features + ["target"]] for frame in frames],
        ignore_index=True,
    )
    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.dropna(subset=["target"])

    X = data[common_features]
    y = data["target"]

    print("\nClass counts:")
    print(y.value_counts().to_string())

    if y.nunique() < 2:
        raise ValueError("Need at least two classes to train.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.25,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    model = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=150,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
            max_features="sqrt",
        )),
    ])

    print("\nTraining model...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    print("\nPreliminary evaluation:")
    print(classification_report(y_test, predictions, zero_division=0))
    print("Confusion matrix (labels:", list(model.classes_), ")")
    print(confusion_matrix(y_test, predictions, labels=model.classes_))

    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump({
        "model": model,
        "features": common_features,
        "classes": list(model.classes_),
        "label_mapping": {
            "BENIGN": "BENIGN",
            "ARP_SPOOFING": "ATTACK",
            "DNS_SPOOFING": "ATTACK",
        },
    }, MODEL_PATH)

    print(f"\nSaved new model to: {MODEL_PATH}")
    print("Existing rf_model.joblib was not changed.")


if __name__ == "__main__":
    main()
