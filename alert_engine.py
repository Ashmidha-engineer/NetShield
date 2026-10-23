
ATTACK_THRESHOLD = 0.70


def evaluate_prediction(result: dict) -> dict:
    prediction = result.get("prediction", "UNKNOWN")
    confidence = float(result.get("confidence", 0.0))
    attack_type = result.get("attack_type")

    if prediction == "ATTACK":
        if confidence >= ATTACK_THRESHOLD:
            status = "ATTACK ALERT"
            message = f"Potential {attack_type} detected."
        else:
            status = "SUSPICIOUS — REVIEW"
            message = (
                f"Possible {attack_type}; confidence is below "
                f"{ATTACK_THRESHOLD:.0%}."
            )
    elif prediction == "BENIGN":
        status = "MODEL SAYS BENIGN"
        message = "No attack predicted for this flow record."
    else:
        status = "REVIEW REQUIRED"
        message = "The model returned an unknown prediction."

    return {
        "status": status,
        "message": message,
        "confidence": confidence,
        "attack_type": attack_type,
    }
