
import json
import streamlit as st
import pandas as pd
from pathlib import Path
from datetime import datetime
from historical_event_analysis import analyze_historical_events
# ---------------- CONFIGURATION ----------------

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "events.jsonl"

st.set_page_config(
    page_title="NetShield | Network Threat Monitor",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- EVENT STORAGE ----------------

def load_events():
    """Load valid JSON events from the shared JSONL file."""
    events = []

    if not LOG_FILE.exists():
        return events

    try:
        with LOG_FILE.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        events.append(event)
                except json.JSONDecodeError:
                    continue

    except OSError as error:
        st.error(f"Unable to read event log: {error}")

    return events


def append_event(event):
    """Append an event without replacing existing monitor records."""
    try:
        with LOG_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")
    except OSError as error:
        st.error(f"Unable to write event log: {error}")


def clear_test_events():
    """Remove simulated test events while preserving real monitor events."""
    events = load_events()
    real_events = [
        event for event in events
        if event.get("source") != "TEST"
    ]

    try:
        with LOG_FILE.open("w", encoding="utf-8") as file:
            for event in real_events:
                file.write(json.dumps(event) + "\n")
    except OSError as error:
        st.error(f"Unable to clear test events: {error}")


def create_test_event(event_type):
    """Generate a clearly labelled simulated event."""
    timestamp = datetime.now().isoformat(timespec="seconds")

    if event_type == "ARP":
        event = {
            "timestamp": timestamp,
            "type": "ARP",
            "status": "ARP ANOMALY CANDIDATE",
            "ip": "192.0.2.10",
            "mac": "02:00:00:00:00:10",
            "previous_mac": "02:00:00:00:00:20",
            "source": "TEST"
        }
    else:
        event = {
            "timestamp": timestamp,
            "type": "DNS",
            "status": "DNS ANSWER CHANGE CANDIDATE",
            "source_ip": "192.0.2.25",
            "destination_ip": "192.0.2.53",
            "domain": "example.test",
            "dns_id": 12345,
            "answers": ["A:192.0.2.99"],
            "source": "TEST"
        }

    append_event(event)


# ---------------- DASHBOARD HEADER ----------------

st.title("🛡️ NetShield")
st.subheader("Network Spoofing Detection and Monitoring for ARP and DNS")
st.caption(
    "Passive ARP/DNS monitoring with rule-based anomaly indicators. "
    "Candidate alerts require investigation and are not proof of an attack."
)

st.divider()

# ---------------- ACTION BUTTONS ----------------

st.subheader("Test Controls")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("Generate test ARP alert", use_container_width=True):
        create_test_event("ARP")
        st.success("Simulated ARP test event added.")

with col2:
    if st.button("Generate test DNS alert", use_container_width=True):
        create_test_event("DNS")
        st.success("Simulated DNS test event added.")

with col3:
    if st.button("Clear test events", use_container_width=True):
        clear_test_events()
        st.success("Test events cleared; real monitor records preserved.")

if st.button("Refresh live events", type="primary"):
    st.rerun()

# Read after button actions so new events appear immediately.
events = load_events()

# ---------------- EVENT COUNTS ----------------

arp_events = [
    event for event in events
    if event.get("type") == "ARP"
]

dns_events = [
    event for event in events
    if event.get("type") == "DNS"
]


candidate_statuses = {
    "ARP ANOMALY CANDIDATE",
    "UNMATCHED_RESPONSE_CANDIDATE"
}
candidate_events = [
    event for event in events
    if event.get("status") in candidate_statuses
]

real_events = [
    event for event in events
    if event.get("source") != "TEST"
]

# ---------------- SUMMARY METRICS ----------------

st.divider()
st.subheader("Network Overview")

m1, m2, m3, m4 = st.columns(4)

m1.metric("Total Events", len(events))
m2.metric("ARP Events", len(arp_events))
m3.metric("DNS Events", len(dns_events))
m4.metric("Candidate Alerts", len(candidate_events))

st.caption(
    f"{len(real_events)} observed monitor events | "
    f"{len(events) - len(real_events)} simulated test events"
)

# ---------------- ALERTS ----------------

st.divider()
st.subheader("Potential Threat Indicators")

if candidate_events:
    st.warning(
        f"{len(candidate_events)} candidate anomaly event(s) logged. "
        "Review the details before deciding whether they indicate an attack."
    )

    for event in reversed(candidate_events[-10:]):
        event_type = event.get("type", "Network")
        status = event.get("status", "Unknown")
        timestamp = event.get("timestamp", "Unknown time")

        with st.expander(f"{event_type}: {status} — {timestamp}"):
            st.json(event)
else:
    st.info("No candidate anomaly events are currently logged.")

# ---------------- ARP EVENTS ----------------

st.divider()
st.subheader("ARP Monitor Events")

if arp_events:
    st.dataframe(
        list(reversed(arp_events[-100:])),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No ARP events logged yet. Check that arp_monitor.py is running.")

# ---------------- DNS EVENTS ----------------

st.divider()
st.subheader("DNS Monitor Events")

if dns_events:
    st.dataframe(
        list(reversed(dns_events[-100:])),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No DNS events logged yet. Check that dns_monitor.py is running.")


# ---------------- HISTORICAL ARP/DNS ANALYSIS ----------------

st.header("Historical ARP/DNS Analysis")
st.caption(
    "Analyzes previously captured event records. "
    "Findings are indicators for review, not proof of spoofing."
)

if st.button("Analyze Existing Events", key="analyze_historical_events"):
    st.session_state["historical_analysis"] = analyze_historical_events(events)

analysis = st.session_state.get("historical_analysis")

if analysis:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events Analyzed", analysis["total_events"])
    c2.metric("ARP Events", analysis["arp_event_count"])
    c3.metric("DNS Events", analysis["dns_event_count"])
    c4.metric("Candidate Alerts", analysis["candidate_event_count"])

    st.subheader("ARP Mapping Review")
    if analysis["arp_mapping_changes"]:
        st.warning(
            "Multiple MAC addresses were recorded for the same IP. "
            "This can have legitimate causes and needs investigation."
        )
        st.dataframe(
            analysis["arp_mapping_changes"],
            use_container_width=True,
        )
    else:
        st.info("No multiple-MAC mappings were found in the stored ARP records.")

    st.subheader("DNS Activity")
    st.write("DNS event statuses", analysis["dns_status_counts"])
    st.write("Most frequently observed domains", analysis["top_domains"])

    st.subheader("DNS Response Review")
    if analysis["unmatched_responses"]:
        st.dataframe(
            analysis["unmatched_responses"],
            use_container_width=True,
        )
    else:
        st.info("No excess unmatched responses were found using the available fields.")

    st.subheader("Domains with Multiple Observed Answers")
    if analysis["domains_with_multiple_answers"]:
        st.dataframe(
            analysis["domains_with_multiple_answers"],
            use_container_width=True,
        )
    else:
        st.info(
            "No domains with multiple non-empty recorded answers were found. "
            "Empty answer lists limit this analysis."
        )
else:
    st.info("Click Analyze Existing Events to analyze the stored event history.")

# ---------------- ALL EVENTS ----------------

st.divider()
st.subheader("All Network Events")

if events:
    st.dataframe(
        list(reversed(events[-200:])),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("The event log is empty.")

# ---------------- FOOTER ----------------

st.divider()
st.caption(
    "NetShield Lab Project | ARP/DNS monitoring | "
    "Candidate alerts are heuristic indicators, not confirmed attacks."
)




# --------------------------------------------------
# Spoofing ML Classifier
# --------------------------------------------------

from ml_detector import model_info, predict_flow
from alert_engine import evaluate_prediction

st.divider()
st.header("ARP/DNS Spoofing — ML Classifier")

try:
    info = model_info()

    st.success("Spoofing model loaded")
    st.write("**Dataset:**", info["dataset"])
    st.write("**Features required:**", info["feature_count"])
    st.write("**Classes:**", ", ".join(info["classes"]))

    with st.expander("Test a network-flow record", expanded=True):
        st.caption(
            "Manual dataset-style flow test only. This is not live "
            "ARP/DNS packet classification."
        )

        with st.form("spoofing_classifier_form"):
            flow_features = {}

            defaults = {
                "Header_Length": 40,
                "Protocol Type": 17,
                "Time_To_Live": 64,
                "Rate": 10,
                "DNS": 1,
                "ARP": 0,
                "UDP": 1,
                "TCP": 0,
                "Tot size": 512,
                "IAT": 1000,
                "Number": 10,
            }

            for feature in info["features"]:
                flow_features[feature] = st.number_input(
                    feature,
                    value=float(defaults.get(feature, 0)),
                    key=f"spoof_{feature}",
                )

            submitted = st.form_submit_button("Classify traffic")

        if submitted:
            result = predict_flow(flow_features)
            alert = evaluate_prediction(result)

            st.subheader("Classification result")
            st.write("**Predicted class:**", result["class_prediction"])
            st.write("**Confidence:**", f"{result['confidence']:.2%}")
            st.write("**Alert status:**", alert["status"])
            st.write(alert["message"])

            if alert["status"] == "ATTACK ALERT":
                st.error(alert["status"])
            elif alert["status"] == "SUSPICIOUS — REVIEW":
                st.warning(alert["status"])
            elif result["prediction"] == "BENIGN":
                st.success("Model prediction: BENIGN")
            else:
                st.info(alert["status"])

            st.write("**Model probabilities**")
            st.json(result["probabilities"])

            st.warning(
                "Experimental model. Predictions on manually entered "
                "values do not establish whether live network traffic "
                "is malicious."
            )

except Exception as exc:
    st.error(f"Spoofing model unavailable: {exc}")




# --------------------------------------------------
# LIVE ML PREDICTIONS
# --------------------------------------------------

import json
from pathlib import Path

st.divider()
st.header("Live Network ML Predictions")
st.caption(
    "Predictions generated from captured packet windows by "
    "live_ml_collector.py. Experimental results, not proof of an attack."
)

LIVE_PREDICTIONS_FILE = Path(__file__).resolve().parent / "live_predictions.jsonl"


def load_live_predictions():
    records = []

    if not LIVE_PREDICTIONS_FILE.exists():
        return records

    try:
        with LIVE_PREDICTIONS_FILE.open("r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    records.append(record)
                except json.JSONDecodeError:
                    continue
    except OSError as error:
        st.error(f"Cannot read live prediction log: {error}")

    return records


if st.button("Refresh Live Predictions", key="refresh_live_predictions"):
    st.rerun()

live_predictions = load_live_predictions()

if not live_predictions:
    st.info(
        "No live ML predictions found yet. Start live_ml_collector.py "
        "in a separate terminal and wait for a complete packet window."
    )
else:
    latest = live_predictions[-1]

    st.subheader("Latest Prediction")

    prediction = latest.get("class_prediction", "UNKNOWN")
    confidence = latest.get("confidence", 0.0)
    timestamp = latest.get("timestamp", "Unknown")
    missing_features = latest.get("missing_features", [])

    c1, c2, c3 = st.columns(3)
    c1.metric("Predicted Class", prediction)
    c2.metric("Model Confidence", f"{confidence:.2%}")
    c3.metric("Packets in Window", latest.get("packets_in_window", "—"))

    st.write("**Prediction timestamp:**", timestamp)

    if prediction in ("ARP_SPOOFING", "DNS_SPOOFING"):
        st.warning(
            f"Experimental model flag: {prediction}. "
            "Investigate the underlying traffic before drawing conclusions."
        )
    elif prediction == "BENIGN":
        st.success(
            "The model classified this window as BENIGN. "
            "This does not guarantee that the traffic is safe."
        )
    else:
        st.info("The model returned an unknown or unrecognized class.")

    st.subheader("Class Probabilities")
    probabilities = latest.get("probabilities", {})

    if probabilities:
        probability_frame = pd.DataFrame(
            [
                {"Class": label, "Probability": float(value)}
                for label, value in probabilities.items()
            ]
        ).sort_values("Probability", ascending=False)

        st.bar_chart(
            probability_frame.set_index("Class"),
            y="Probability",
        )
        st.dataframe(
            probability_frame,
            hide_index=True,
            use_container_width=True,
        )
    else:
        st.info("No class probability values were recorded.")

    if missing_features:
        st.warning(
            "Some model features were missing: "
            + ", ".join(missing_features)
            + ". The prediction may be unreliable."
        )

    if latest.get("warning"):
        st.caption("Model limitation: " + latest["warning"])

    st.subheader("Recent Live Predictions")

    history_rows = []
    for record in reversed(live_predictions[-50:]):
        history_rows.append({
            "Timestamp": record.get("timestamp", ""),
            "Class": record.get("class_prediction", "UNKNOWN"),
            "Confidence": (
                f'{record.get("confidence", 0.0):.2%}'
            ),
            "Packets": record.get("packets_in_window", ""),
            "Missing Features": len(record.get("missing_features", [])),
        })

    st.dataframe(
        pd.DataFrame(history_rows),
        hide_index=True,
        use_container_width=True,
    )

    st.caption(
        f"Showing up to 50 recent predictions from "
        f"{LIVE_PREDICTIONS_FILE.name}. "
        "Refresh to load newer records."
    )



# --------------------------------------------------
# ML MODEL VALIDATION — LABELLED DATASET
# --------------------------------------------------

import pandas as pd
import streamlit as st

from ml_validation import validate_model

st.divider()
st.header("ML Model Validation")
st.caption(
    "Tests the trained classifier against labelled CSV records. "
    "This is a dataset validation test, not live traffic detection."
)

if st.button("Run Dataset Validation", key="run_ml_validation"):
    with st.spinner("Running predictions on labelled records..."):
        try:
            validation = validate_model(rows_per_file=200)

            st.metric(
                "Records tested",
                validation["records_tested"],
            )
            st.metric(
                "Sample accuracy",
                f'{validation["accuracy"] * 100:.2f}%',
            )

            st.subheader("Confusion Matrix")
            st.caption(
                "Rows are actual labels; columns are predicted labels."
            )
            st.dataframe(
                validation["confusion_matrix"],
                use_container_width=True,
            )

            st.subheader("Per-Class Performance")
            report = validation["report"]

            metrics = []
            for label in ["BENIGN", "ARP_SPOOFING", "DNS_SPOOFING"]:
                values = report[label]
                metrics.append({
                    "Class": label,
                    "Precision": round(values["precision"], 3),
                    "Recall": round(values["recall"], 3),
                    "F1-score": round(values["f1-score"], 3),
                    "Support": int(values["support"]),
                })

            st.dataframe(
                pd.DataFrame(metrics),
                hide_index=True,
                use_container_width=True,
            )

            st.subheader("Sample Predictions")
            st.dataframe(
                validation["results"].head(30),
                hide_index=True,
                use_container_width=True,
            )

            st.warning(
                "These records are sampled from the same source files "
                "used for model training. Treat the metrics as a "
                "smoke test, not an independent performance benchmark."
            )

        except Exception as error:
            st.error(f"Validation failed: {error}")
