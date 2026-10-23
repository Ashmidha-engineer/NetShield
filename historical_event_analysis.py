
from collections import Counter, defaultdict
from datetime import datetime


CANDIDATE_STATUSES = {
    "ARP ANOMALY CANDIDATE",
    "DNS ANSWERCHANGE CANDIDATE",
    "DNS UNMATCHED RESPONSE",
}


def analyze_historical_events(events):
    """Analyze existing ARP/DNS records without changing the source log."""

    arp_events = [
        e for e in events
        if e.get("type") == "ARP" and e.get("source") != "TEST"
    ]
    dns_events = [
        e for e in events
        if e.get("type") == "DNS" and e.get("source") != "TEST"
    ]

    # Summarize ARP observations by IP and MAC address.
    arp_by_ip = defaultdict(set)
    arp_status_counts = Counter()

    for event in arp_events:
        ip = event.get("ip")
        mac = event.get("mac")

        if ip and mac:
            arp_by_ip[ip].add(mac)

        arp_status_counts[event.get("status", "UNKNOWN")] += 1

    arp_mapping_changes = [
        {
            "ip": ip,
            "mac_addresses_observed": sorted(macs),
            "distinct_mac_count": len(macs),
        }
        for ip, macs in arp_by_ip.items()
        if len(macs) > 1
    ]

    # Summarize DNS activity by domain and response matching key.
    dns_domain_counts = Counter()
    dns_status_counts = Counter()
    dns_queries = Counter()
    dns_responses = Counter()
    dns_answer_sets = defaultdict(set)

    for event in dns_events:
        domain = event.get("domain")
        status = str(event.get("status", "UNKNOWN")).upper()
        dns_id = event.get("dns_id")
        source = event.get("source")
        destination = event.get("destination")

        if domain:
            dns_domain_counts[domain] += 1

        dns_status_counts[status] += 1

        # Query and response endpoints are reversed in a normal exchange.
        if dns_id is not None and source and destination:
            if status == "QUERY":
                key = (dns_id, source, destination, domain)
                dns_queries[key] += 1
            elif status == "RESPONSE":
                key = (dns_id, destination, source, domain)
                dns_responses[key] += 1

        answers = event.get("answers") or []
        if domain and answers:
            for answer in answers:
                dns_answer_sets[domain].add(str(answer))

    unmatched_responses = []
    for key, response_count in dns_responses.items():
        if response_count > dns_queries.get(key, 0):
            unmatched_responses.append({
                "dns_id": key[0],
                "client": key[1],
                "resolver": key[2],
                "domain": key[3],
                "excess_responses": response_count - dns_queries.get(key, 0),
            })

    domains_with_multiple_answers = [
        {
            "domain": domain,
            "observed_answers": sorted(answers),
        }
        for domain, answers in dns_answer_sets.items()
        if len(answers) > 1
    ]

    candidate_events = [
        e for e in events
        if e.get("source") != "TEST"
        and e.get("status") in CANDIDATE_STATUSES
    ]

    return {
        "total_events": len(events),
        "arp_event_count": len(arp_events),
        "dns_event_count": len(dns_events),
        "arp_status_counts": dict(arp_status_counts),
        "arp_mapping_changes": arp_mapping_changes,
        "dns_status_counts": dict(dns_status_counts),
        "top_domains": dns_domain_counts.most_common(15),
        "unmatched_responses": unmatched_responses,
        "domains_with_multiple_answers": domains_with_multiple_answers,
        "candidate_event_count": len(candidate_events),
    }
