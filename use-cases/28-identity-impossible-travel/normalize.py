#!/usr/bin/env python3
"""Normalize vendor identity logs into one OpenTelemetry-style schema."""

import json
from pathlib import Path


RAW_DIR = Path("raw-events")
OUTPUT_FILE = Path("normalized-events.json")


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def normalize_entra(event):
    coordinates = event["location"]["geoCoordinates"]
    risk_level = event.get("riskLevelAggregated", "none")

    return {
        "event_time": event["createdDateTime"],
        "event_type": "identity_authentication",
        "source_system": "entra_id",
        "user_id": event["userPrincipalName"].lower(),
        "src_ip": event["ipAddress"],
        "city": event["location"]["city"],
        "country": event["location"]["countryOrRegion"],
        "latitude": coordinates["latitude"],
        "longitude": coordinates["longitude"],
        "auth_result": "success" if event["status"]["errorCode"] == 0 else "failure",
        "mfa_result": "passed" if event.get("conditionalAccessStatus") == "success" else "unknown",
        "device_trust": "managed" if event.get("deviceDetail", {}).get("trustType") else "unknown",
        "asn_reputation": "business_isp",
        "risk_score": {"none": 0, "low": 15, "medium": 55, "high": 90}.get(risk_level, 0),
    }


def normalize_okta(event):
    geo = event["client"]["geographicalContext"]
    risk_score = int(event.get("debugContext", {}).get("debugData", {}).get("riskScore", 0))
    as_org = event.get("securityContext", {}).get("asOrg", "").lower()

    return {
        "event_time": event["published"],
        "event_type": "identity_authentication",
        "source_system": "okta",
        "user_id": event["actor"]["alternateId"].lower(),
        "src_ip": event["client"]["ipAddress"],
        "city": geo["city"],
        "country": geo["country"],
        "latitude": geo["geolocation"]["lat"],
        "longitude": geo["geolocation"]["lon"],
        "auth_result": "success" if event["outcome"]["result"] == "SUCCESS" else "failure",
        "mfa_result": "not_challenged",
        "device_trust": "unknown",
        "asn_reputation": "hosting_provider" if "hosting" in as_org else "unknown",
        "risk_score": risk_score,
    }


def normalize_vpn(event):
    return {
        "event_time": event["timestamp"],
        "event_type": "identity_authentication",
        "source_system": "vpn",
        "user_id": event["username"].lower(),
        "src_ip": event["remote_ip"],
        "city": event["geo_city"],
        "country": event["geo_country"],
        "latitude": event["geo_lat"],
        "longitude": event["geo_lon"],
        "auth_result": "success" if event["result"] == "allow" else "failure",
        "mfa_result": event.get("mfa", "unknown"),
        "device_trust": event.get("device_posture", "unknown"),
        "asn_reputation": event.get("asn_reputation", "unknown"),
        "risk_score": event.get("risk", 0),
    }


def normalize_active_directory(event):
    username = event["TargetUserName"]
    if "@" not in username:
        username = f"{username}@example.com"

    return {
        "event_time": event["TimeCreated"],
        "event_type": "identity_authentication",
        "source_system": "active_directory",
        "user_id": username.lower(),
        "src_ip": event["IpAddress"],
        "city": event["geo"]["city"],
        "country": event["geo"]["country"],
        "latitude": event["geo"]["lat"],
        "longitude": event["geo"]["lon"],
        "auth_result": "success" if event["Status"] == "0x0" else "failure",
        "mfa_result": "not_applicable",
        "device_trust": "managed",
        "asn_reputation": "internal",
        "risk_score": 5,
    }


NORMALIZERS = {
    "entra-id.json": normalize_entra,
    "okta.json": normalize_okta,
    "vpn.json": normalize_vpn,
    "active-directory.json": normalize_active_directory,
}


def main():
    normalized_events = []

    for filename, normalizer in NORMALIZERS.items():
        for event in load_json(RAW_DIR / filename):
            normalized_events.append(normalizer(event))

    normalized_events.sort(key=lambda event: event["event_time"])

    with open(OUTPUT_FILE, "w") as f:
        json.dump(normalized_events, f, indent=2)

    print(f"[OK] Normalized {len(normalized_events)} identity events")
    print(f"[OK] Wrote {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
