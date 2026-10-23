
from pathlib import Path
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

from ml_detector import model_info, predict_flow


DATA_DIR = Path(__file__).parent / "dataset" / "dns_arp_selected" / "CSV"

LABEL_FOLDERS = {
    "Benign_Final": "BENIGN",
    "MITM-ArpSpoofing": "ARP_SPOOFING",
    "DNS_Spoofing": "DNS_SPOOFING",
}


def load_validation_data(rows_per_file=200):
    """Load a small sample from each labelled CSV file."""
    features = model_info()["features"]
    frames = []

    for folder, label in LABEL_FOLDERS.items():
        csv_files = sorted((DATA_DIR / folder).glob("*.csv"))

        for csv_file in csv_files:
            df = pd.read_csv(csv_file, nrows=rows_per_file)

            missing = [name for name in features if name not in df.columns]
            if missing:
                raise ValueError(
                    f"{csv_file.name} is missing features: {missing}"
                )

            # Use exactly the model's expected columns and order.
            X = df[features].apply(pd.to_numeric, errors="coerce")

            # Drop rows where every feature is missing.
            X = X.dropna(how="all")

            if not X.empty:
                X = X.copy()
                X["actual_label"] = label
                X["source_file"] = csv_file.name
                frames.append(X)

    if not frames:
        raise ValueError(f"No usable CSV records found under {DATA_DIR}")

    return pd.concat(frames, ignore_index=True)


def validate_model(rows_per_file=200):
    """Run predictions and report agreement with dataset labels."""
    df = load_validation_data(rows_per_file)
    features = model_info()["features"]

    predictions = []

    for _, row in df.iterrows():
        flow = {
            feature: row[feature]
            for feature in features
        }
        result = predict_flow(flow)
        predictions.append(result["class_prediction"])

    actual = df["actual_label"].tolist()
    labels = ["BENIGN", "ARP_SPOOFING", "DNS_SPOOFING"]

    report = classification_report(
        actual,
        predictions,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(actual, predictions, labels=labels)

    results = df[["actual_label", "source_file"]].copy()
    results["predicted_label"] = predictions
    results["correct"] = (
        results["actual_label"] == results["predicted_label"]
    )

    return {
        "records_tested": len(results),
        "accuracy": accuracy_score(actual, predictions),
        "report": report,
        "confusion_matrix": pd.DataFrame(
            matrix,
            index=labels,
            columns=labels,
        ),
        "results": results,
    }
