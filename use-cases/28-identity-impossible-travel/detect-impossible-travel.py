#!/usr/bin/env python3
"""Detect impossible travel from normalized identity authentication events."""

import json
import math
from datetime import datetime
from pathlib import Path


INPUT_FILE = Path("normalized-events.json")
OUTPUT_FILE = Path("detections.json")
MIN_DISTANCE_KM = 750
MIN_SPEED_KMH = 900


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def distance_km(first, second):
    radius_km = 6371.0
    lat1 = math.radians(first["latitude"])
    lon1 = math.radians(first["longitude"])
    lat2 = math.radians(second["latitude"])
    lon2 = math.radians(second["longitude"])
    delta_lat = lat2 - lat1
    delta_lon = lon2 - lon1

    haversine = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(delta_lon / 2) ** 2
    )
    return radius_km * 2 * math.atan2(math.sqrt(haversine), math.sqrt(1 - haversine))


def is_risky_context(event):
    return (
        event["risk_score"] >= 70
        or event["mfa_result"] in {"not_challenged", "failed", "bypassed"}
        or event["device_trust"] in {"unknown", "unmanaged"}
        or event["asn_reputation"] in {"anonymous_proxy", "hosting_provider", "suspicious"}
    )


def detect(events):
    detections = []
    events_by_user = {}

    for event in events:
        if event["event_type"] != "identity_authentication":
            continue
        if event["auth_result"] != "success":
            continue
        events_by_user.setdefault(event["user_id"], []).append(event)

    for user_id, user_events in events_by_user.items():
        user_events.sort(key=lambda event: event["event_time"])

        for previous, current in zip(user_events, user_events[1:]):
            elapsed_hours = (
                parse_time(current["event_time"]) - parse_time(previous["event_time"])
            ).total_seconds() / 3600
            if elapsed_hours <= 0:
                continue

            trip_distance_km = distance_km(previous, current)
            speed_kmh = trip_distance_km / elapsed_hours

            if trip_distance_km < MIN_DISTANCE_KM or speed_kmh < MIN_SPEED_KMH:
                continue

            detections.append({
                "detection_type": "IMPOSSIBLE_TRAVEL_IDENTITY_COMPROMISE",
                "severity": "CRITICAL" if is_risky_context(current) else "HIGH",
                "user_id": user_id,
                "previous_source": previous["source_system"],
                "current_source": current["source_system"],
                "previous_city": previous["city"],
                "current_city": current["city"],
                "previous_time": previous["event_time"],
                "current_time": current["event_time"],
                "elapsed_minutes": round(elapsed_hours * 60, 1),
                "distance_km": round(trip_distance_km, 1),
                "speed_kmh": round(speed_kmh, 1),
                "current_ip": current["src_ip"],
                "mfa_result": current["mfa_result"],
                "device_trust": current["device_trust"],
                "asn_reputation": current["asn_reputation"],
                "risk_score": current["risk_score"],
            })

    return detections


def main():
    if not INPUT_FILE.exists():
        raise SystemExit("normalized-events.json not found. Run normalize.py first.")

    with open(INPUT_FILE, "r") as f:
        events = json.load(f)

    detections = detect(events)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(detections, f, indent=2)

    if not detections:
        print("[OK] No impossible travel detections")
        return

    for detection in detections:
        print(f"[DETECTION] {detection['detection_type']}")
        print(f"User: {detection['user_id']}")
        print(
            "Travel: "
            f"{detection['previous_city']} -> {detection['current_city']} "
            f"in {detection['elapsed_minutes']} minutes"
        )
        print(f"Sources: {detection['previous_source']} -> {detection['current_source']}")
        print(f"Speed: {detection['speed_kmh']} km/h")
        print(f"Risk: MFA={detection['mfa_result']}, Device={detection['device_trust']}, ASN={detection['asn_reputation']}")
        print(f"Severity: {detection['severity']}")

    print(f"[OK] Wrote {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
