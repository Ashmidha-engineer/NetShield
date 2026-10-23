
from collections import Counter
from datetime import datetime
from statistics import mean, pstdev, pvariance
from arp_monitor import inspect_arp
from dns_monitor import inspect_dns
from scapy.all import sniff, IP, IPv6, TCP, UDP, ARP, DNS, DNSQR, DNSRR

WINDOW_SIZE = 10


def is_dns_packet(packet):
    """Identify DNS packets using the DNS layer or port 53."""
    if DNS in packet:
        return True

    if UDP in packet:
        return packet[UDP].sport == 53 or packet[UDP].dport == 53

    if TCP in packet:
        return packet[TCP].sport == 53 or packet[TCP].dport == 53

    return False


def packet_protocol(packet):
    if ARP in packet:
        return "ARP"
    if is_dns_packet(packet):
        return "DNS"
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if IP in packet or IPv6 in packet:
        return "IP"
    return "OTHER"


def dns_details(packet):
    """Extract basic DNS query names and response answer IPs."""
    details = {}

    if DNS not in packet:
        return details

    dns = packet[DNS]

    if dns.qdcount and DNSQR in packet:
        try:
            details["query"] = packet[DNSQR].qname.decode(
                "utf-8", errors="replace"
            ).rstrip(".")
        except Exception:
            details["query"] = "unreadable"

    answers = []
    answer = dns.an

    for _ in range(int(dns.ancount or 0)):
        if not isinstance(answer, DNSRR):
            break

        if answer.type in (1, 28):  # A or AAAA record
            answers.append(str(answer.rdata))

        answer = answer.payload

    if answers:
        details["answers"] = answers

    return details


def summarize_window(packets):
    if not packets:
        return None

    lengths = [len(packet) for packet in packets]
    timestamps = sorted(float(packet.time) for packet in packets)
    intervals = [
        timestamps[i] - timestamps[i - 1]
        for i in range(1, len(timestamps))
    ]

    protocols = Counter(packet_protocol(packet) for packet in packets)

    dns_packets = []
    for packet in packets:
        if is_dns_packet(packet):
            info = dns_details(packet)
            if info:
                dns_packets.append(info)

    arp_observations = []
    for packet in packets:
        if ARP in packet:
            arp = packet[ARP]
            arp_observations.append({
                "operation": "reply" if arp.op == 2 else "request",
                "sender_ip": arp.psrc,
                "sender_mac": arp.hwsrc,
                "target_ip": arp.pdst,
            })

    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "packet_count": len(packets),
        "total_bytes": sum(lengths),
        "min_packet_bytes": min(lengths),
        "max_packet_bytes": max(lengths),
        "mean_packet_bytes": round(mean(lengths), 2),
        "packet_size_stddev": round(pstdev(lengths), 2),
        "packet_size_variance": round(pvariance(lengths), 2),
        "mean_interarrival_seconds": (
            round(mean(intervals), 6) if intervals else None
        ),
        "protocol_counts": dict(protocols),
        "arp_packets": protocols["ARP"],
        "dns_packets": protocols["DNS"],
        "arp_observations": arp_observations,
        "dns_observations": dns_packets,
    }



def inspect_packet(packet):
    # Send each captured packet to both existing detection handlers.
    # Their existing logic decides whether the packet is relevant.
    try:
        inspect_arp(packet)
    except Exception as error:
        print(f"[ARP HANDLER ERROR] {error}")

    try:
        inspect_dns(packet)
    except Exception as error:
        print(f"[DNS HANDLER ERROR] {error}")

    # Preserve the existing 10-packet summary behavior.
    if not hasattr(inspect_packet, "window"):
        inspect_packet.window = []

    inspect_packet.window.append(packet)

    if len(inspect_packet.window) >= WINDOW_SIZE:
        summary = summarize_window(inspect_packet.window)
        if summary is not None:
            print("[FLOW WINDOW]", summary)

        inspect_packet.window = []



def main():
    print("NetShield ARP/DNS packet collector")
    print("Capture filter: ARP and DNS (UDP/TCP port 53)")
    print("Passive capture only; press Ctrl+C to stop.")

    try:
        sniff(
            filter="arp or udp port 53 or tcp port 53",
            prn=inspect_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nCollector stopped.")


if __name__ == "__main__":
    main()
