
from pathlib import Path
import joblib
import pandas as pd

MODEL_PATH = (
    Path(__file__).parent / "models" / "spoofing_flow_model.joblib"
)

_bundle = joblib.load(MODEL_PATH)
_model = _bundle["model"]
_features = _bundle["features"]


def model_info():
    return {
        "dataset": "CICIoT2023 selected benign and spoofing CSVs",
        "feature_count": len(_features),
        "features": _features,
        "classes": list(_model.classes_),
    }


def predict_flow(features: dict) -> dict:
    row = pd.DataFrame(
        [{name: features.get(name, float("nan")) for name in _features}],
        columns=_features,
    )

    predicted_class = str(_model.predict(row)[0])
    probabilities = _model.predict_proba(row)[0]
    confidence = float(max(probabilities))

    attack_labels = {"ARP_SPOOFING", "DNS_SPOOFING"}

    return {
        "prediction": (
            "ATTACK" if predicted_class in attack_labels else "BENIGN"
        ),
        "attack_type": (
            predicted_class if predicted_class in attack_labels else None
        ),
        "class_prediction": predicted_class,
        "confidence": round(confidence, 4),
        "probabilities": {
            str(label): round(float(prob), 4)
            for label, prob in zip(_model.classes_, probabilities)
        },
    }
