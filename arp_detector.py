from collections import defaultdict

class ARPDetector:
    def __init__(self):
        self.baseline = {}

    def inspect(self, ip, mac):
        """
        Record the first observed MAC for an IP.
        Flag later changes for investigation.
        """
        mac = mac.lower()
        previous_mac = self.baseline.get(ip)

        if previous_mac is None:
            self.baseline[ip] = mac
            return {
                "status": "BASELINE",
                "ip": ip,
                "mac": mac,
                "message": "First observed mapping recorded."
            }

        if previous_mac != mac:
            return {
                "status": "ALERT",
                "ip": ip,
                "mac": mac,
                "previous_mac": previous_mac,
                "message": (
                    "IP-to-MAC mapping changed. "
                    "Investigate; this is not proof of spoofing."
                )
            }

        return {
            "status": "NORMAL",
            "ip": ip,
            "mac": mac,
            "message": "Mapping matches the observed baseline."
        }


if __name__ == "__main__":
    detector = ARPDetector()

    # Simulated data for testing only; no packets are transmitted.
    test_events = [
        ("192.0.2.10", "02:00:00:00:00:01"),
        ("192.0.2.20", "02:00:00:00:00:02"),
        ("192.0.2.10", "02:00:00:00:00:01"),
        ("192.0.2.10", "02:00:00:00:00:99"),
    ]

    for ip, mac in test_events:
        result = detector.inspect(ip, mac)
        print(f"[{result['status']}] {result['ip']} - {result['message']}")

        if result["status"] == "ALERT":
            print(f"  Expected MAC: {result['previous_mac']}")
            print(f"  Observed MAC: {result['mac']}")
