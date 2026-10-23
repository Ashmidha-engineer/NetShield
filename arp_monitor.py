
from scapy.all import sniff, ARP
from datetime import datetime
from pathlib import Path
import json

LOG_FILE = Path(__file__).resolve().parent / "events.jsonl"
baseline = {}
def write_event(status, ip, mac, previous_mac=None):
    event = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "type": "ARP",
        "status": status,
        "ip": ip,
        "mac": mac,
        "previous_mac": previous_mac,
    }
    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")
        file.flush()
def inspect_arp(packet):
    if ARP not in packet:
        return
    arp = packet[ARP]
    # Observe ARP replies only.
    if arp.op != 2:
        return
    ip = arp.psrc
    mac = arp.hwsrc.lower()
    if not ip or ip == "0.0.0.0":
        return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if ip not in baseline:
        baseline[ip] = mac
        status = "BASELINE"
        previous_mac = None
    elif baseline[ip] == mac:
        status = "NORMAL"
        previous_mac = None
    else:
        status = "ARP ANOMALY CANDIDATE"
        previous_mac = baseline[ip]
    print(f"[{status}] {timestamp} {ip} is-at {mac}")
    if status == "ARP ANOMALY CANDIDATE":
        print(f"  Previous MAC: {previous_mac}")
    try:
        write_event(status, ip, mac, previous_mac)
    except OSError as error:
        print(f"[LOG WRITE ERROR] {error}")
if __name__ == "__main__":
    print("NetShield ARP monitor starting...")
    print(f"Event log: {LOG_FILE}")
    print("Press Ctrl+C to stop.")
    try:
        sniff(filter="arp", prn=inspect_arp, store=False)
    except KeyboardInterrupt:
        print("\nARP monitor stopped.")
