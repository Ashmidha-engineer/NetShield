
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, IPv6
from datetime import datetime
from pathlib import Path
import json
import time

LOG_FILE = Path(__file__).resolve().parent / "events.jsonl"
# Queries observed during this monitor run.
pending_queries = {}
# Different answer sets observed for each domain.
known_answer_sets = {}
def get_ip_addresses(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst
    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst
    return "unknown", "unknown"
def get_domain(dns):
    if dns.qd and getattr(dns.qd, "qname", None):
        name = dns.qd.qname
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        return str(name).rstrip(".").lower()
    return "unknown"

def get_answers(dns):
    """Extract DNS answer records from Scapy's answer section."""
    answers = []
    answer_section = dns.an

    if not answer_section:
        return answers

    # Scapy may expose the answer section as a list of records.
    if isinstance(answer_section, (list, tuple)):
        records = answer_section
    else:
        # Also support a linked DNS resource-record chain.
        records = []
        rr = answer_section

        while isinstance(rr, DNSRR):
            records.append(rr)
            next_rr = rr.payload

            if next_rr is rr or not isinstance(next_rr, DNSRR):
                break

            rr = next_rr

    type_names = {
        1: "A",
        28: "AAAA",
        5: "CNAME",
        2: "NS",
        15: "MX",
        16: "TXT",
        33: "SRV",
        12: "PTR",
        6: "SOA",
        65: "HTTPS",
        64: "SVCB",
    }

    for rr in records:
        record_type = int(getattr(rr, "type", 0))
        kind = type_names.get(record_type, f"TYPE{record_type}")

        value = getattr(rr, "rdata", None)

        # HTTPS/SVCB records use structured fields in Scapy.
        if value is None and record_type in (64, 65):
            priority = getattr(rr, "svc_priority", "?")
            target = getattr(rr, "target_name", b".")
            if isinstance(target, bytes):
                target = target.decode("utf-8", errors="replace")

            value = f"priority={priority};target={target}"

        if value is None:
            value = rr.summary()

        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")

        answers.append(f"{kind}:{value}")

    return sorted(set(answers))

def write_event(status, src, dst, domain, dns_id, answers=None):
    event = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "type": "DNS",
        "status": status,
        "source": src,
        "destination": dst,
        "domain": domain,
        "dns_id": int(dns_id),
        "answers": answers or []
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")
        file.flush()

    print(f"[DNS {status}] {src} -> {dst} | {domain} | {answers or []}")


def inspect_dns(packet):
    if DNS not in packet:
        return

    dns = packet[DNS]
    src, dst = get_ip_addresses(packet)
    domain = get_domain(dns)
    dns_id = int(dns.id)

    now = time.monotonic()

    # Remove queries older than 30 seconds.
    for key, timestamp in list(pending_queries.items()):
        if now - timestamp > 30:
            del pending_queries[key]

    if dns.qr == 0:
        # DNS query: client -> resolver
        key = (src, dst, dns_id, domain)
        pending_queries[key] = now

        write_event("QUERY", src, dst, domain, dns_id)
        return

    key = (dst, src, dns_id, domain)
    answers = get_answers(dns)

    if key in pending_queries:
        del pending_queries[key]
        status = "RESPONSE"
    else:
        status = "UNMATCHED_RESPONSE_CANDIDATE"

    if answers:
        answer_set = tuple(answers)
        previous_sets = known_answer_sets.setdefault(domain, set())

        
        if previous_sets and answer_set not in previous_sets:
            status = "DNS ANSWER CHANGE OBSERVATION"
        previous_sets.add(answer_set)

    write_event(status, src, dst, domain, dns_id, answers)


if __name__ == "__main__":
    print("NetShield DNS monitor starting...")
    print(f"Appending events to: {LOG_FILE}")
    print("Monitoring DNS traffic on port 53. Press Ctrl+C to stop.")

    try:
        sniff(
            filter="udp port 53 or tcp port 53",
            prn=inspect_dns,
            store=False
        )
    except KeyboardInterrupt:
        print("\nDNS monitor stopped.")
