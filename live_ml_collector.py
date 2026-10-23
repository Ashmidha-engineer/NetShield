
import json
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import mean, pstdev, pvariance

from scapy.all import sniff, IP, IPv6, TCP, UDP, ARP, DNS
from ml_detector import model_info, predict_flow

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = BASE_DIR / "live_predictions.jsonl"
WINDOW_SIZE = 10

FEATURES = model_info()["features"]


def packet_protocol(packet):
    if ARP in packet:
        return "ARP"
    if DNS in packet or (
        (UDP in packet and (packet[UDP].sport == 53 or packet[UDP].dport == 53))
        or (TCP in packet and (packet[TCP].sport == 53 or packet[TCP].dport == 53))
    ):
        return "DNS"
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if IP in packet or IPv6 in packet:
        return "IPv"
    return "OTHER"


def extract_window_features(packets):
    """Extract observable features; leave unavailable features missing."""
    lengths = [len(p) for p in packets]
    timestamps = sorted(float(p.time) for p in packets)
    intervals = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    protocols = Counter(packet_protocol(p) for p in packets)
    tcp_packets = [p for p in packets if TCP in p]
    udp_packets = [p for p in packets if UDP in p]
    arp_packets = [p for p in packets if ARP in p]
    dns_packets = [p for p in packets if DNS in p]

    # Start with missing values, not invented zeros.
    features = {name: float("nan") for name in FEATURES}

    # Directly observable counts and packet-size statistics.
    observed = {
        "ARP": len(arp_packets),
        "DNS": len(dns_packets),
        "TCP": len(tcp_packets),
        "UDP": len(udp_packets),
        "IPv": sum(IP in p or IPv6 in p for p in packets),
        "Number": len(packets),
        "Min": min(lengths),
        "Max": max(lengths),
        "AVG": mean(lengths),
        "Std": pstdev(lengths),
        "Variance": pvariance(lengths),
        "Tot size": sum(lengths),
        "Tot sum": sum(lengths),
        "Header_Length": sum(
            len(p) - len(bytes(p.payload)) for p in packets
        ),
        "IAT": mean(intervals) if intervals else float("nan"),
        "Rate": (
            len(packets) / (timestamps[-1] - timestamps[0])
            if len(timestamps) > 1 and timestamps[-1] > timestamps[0]
            else float("nan")
        ),
        "Protocol Type": (
            6 if tcp_packets else 17 if udp_packets else float("nan")
        ),
        "ack_count": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x10
        ),
        "fin_count": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x01
        ),
        "rst_count": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x04
        ),
        "ack_flag_number": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x10
        ),
        "fin_flag_number": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x01
        ),
        "syn_flag_number": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x02
        ),
        "rst_flag_number": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x04
        ),
        "psh_flag_number": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x08
        ),
        "urg_flag_number": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x20
        ),
        "ece_flag_number": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x40
        ),
        "cwr_flag_number": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x80
        ),
        "syn_count": sum(
            1 for p in tcp_packets if int(p[TCP].flags) & 0x02
        ),
        "HTTP": sum(
            1 for p in packets
            if TCP in p and (p[TCP].sport in (80, 8080) or p[TCP].dport in (80, 8080))
        ),
        "HTTPS": sum(
            1 for p in packets
            if TCP in p and (p[TCP].sport == 443 or p[TCP].dport == 443)
        ),
        "SSH": sum(
            1 for p in packets
            if TCP in p and (p[TCP].sport == 22 or p[TCP].dport == 22)
        ),
        "Telnet": sum(
            1 for p in packets
            if TCP in p and (p[TCP].sport == 23 or p[TCP].dport == 23)
        ),
        "SMTP": sum(
            1 for p in packets
            if TCP in p and (p[TCP].sport in (25, 465, 587) or p[TCP].dport in (25, 465, 587))
        ),
        "DHCP": sum(
            1 for p in udp_packets
            if p[UDP].sport in (67, 68) or p[UDP].dport in (67, 68)
        ),
        "ICMP": sum(
            1 for p in packets
            if IP in p and p[IP].proto == 1
        ),
        "IGMP": sum(
            1 for p in packets
            if IP in p and p[IP].proto == 2
        ),
        "LLC": 0,
        "IRC": sum(
            1 for p in packets
            if TCP in p and (p[TCP].sport == 6667 or p[TCP].dport == 6667)
        ),
        "Time_To_Live": mean([
            p[IP].ttl for p in packets if IP in p
        ]) if any(IP in p for p in packets) else float("nan"),
    }

    for name, value in observed.items():
        if name in features:
            features[name] = value

    return features


def write_prediction(packets):
    features = extract_window_features(packets)
    missing = [
        name for name, value in features.items()
        if value != value  # NaN check
    ]

    try:
        result = predict_flow(features)
        record = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "packets_in_window": len(packets),
            "prediction": result["prediction"],
            "attack_type": result["attack_type"],
            "class_prediction": result["class_prediction"],
            "confidence": result["confidence"],
            "probabilities": result["probabilities"],
            "missing_features": missing,
            "warning": "Experimental: approximate packet-window features; not validated as equivalent to training features.",
        }

        with OUTPUT_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record) + "\n")

        print(
            f"[LIVE ML] {record['timestamp']} | "
            f"{record['class_prediction']} | "
            f"confidence={record['confidence']:.1%} | "
            f"missing_features={len(missing)}"
        )
    except Exception as error:
        print(f"[ML PREDICTION ERROR] {error}")


def main():
    print("NetShield experimental live ML collector")
    print(f"Model features: {len(FEATURES)}")
    print(f"Output: {OUTPUT_FILE}")
    print("Captures ARP and DNS traffic; Ctrl+C stops capture.")
    print("Predictions are experimental until feature parity is validated.")

    window = []

    def on_packet(packet):
        window.append(packet)
        if len(window) >= WINDOW_SIZE:
            write_prediction(window.copy())
            window.clear()

    try:
        sniff(
            filter="arp or udp port 53 or tcp port 53",
            prn=on_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nLive ML collector stopped.")


if __name__ == "__main__":
    main()
