#!/usr/bin/env python3
"""
Layer 2: Multi-Signal Correlation Engine
UC-04: Backup / Snapshot Targeting

Correlates backup contact, admin protocol usage, and destructive recovery
actions into a high-confidence ransomware preparation detection.
"""

import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List


class BackupTargetingCorrelationEngine:
    """Multi-signal ransomware recovery impairment correlation."""

    def __init__(self, rules_file="rules.json", signals_file="../signals-output.json"):
        self.rules_file = Path(rules_file)
        self.signals_file = Path(signals_file)
        self.db_path = Path("../../../output/ransomware-detections.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.detections = []
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database."""
        db_path_str = str(self.db_path.absolute())
        conn = sqlite3.connect(db_path_str)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ransomware_detections (
                detection_id TEXT PRIMARY KEY,
                detection_type TEXT,
                src_ip TEXT,
                severity TEXT,
                confidence TEXT,
                signal_count INTEGER,
                backup_target_count INTEGER,
                admin_service_count INTEGER,
                destructive_action_count INTEGER,
                timestamp TEXT,
                signals_json TEXT
            )
        """)

        conn.commit()
        conn.close()
        print(f"[INFO] Database initialized: {db_path_str}")

    def load_rules(self):
        """Load correlation rules."""
        print(f"[INFO] Loading rules: {self.rules_file}")
        with open(self.rules_file, "r") as f:
            rules = json.load(f)
        print(f"[INFO] Loaded rule: {rules['rule_name']}")
        return rules

    def load_signals(self):
        """Load signals from Layer 1."""
        print(f"[INFO] Loading signals: {self.signals_file}")

        if not self.signals_file.exists():
            print("[ERROR] No signals found. Run Layer 1 first.")
            return []

        with open(self.signals_file, "r") as f:
            signals = json.load(f)

        print(f"[INFO] Loaded {len(signals)} signals")
        return signals

    def correlate(self, signals: List[Dict], rules: Dict):
        """Correlate ransomware backup targeting signals by source IP."""
        print("\n" + "=" * 60)
        print("LAYER 2: Backup / Snapshot Targeting Correlation")
        print("=" * 60)

        required_signals = set(rules["required_signals"])
        time_window_minutes = rules["time_window_minutes"]

        signals_by_ip = {}
        for signal in signals:
            src_ip = signal.get("src_ip")
            if src_ip:
                signals_by_ip.setdefault(src_ip, []).append(signal)

        for src_ip, ip_signals in signals_by_ip.items():
            print(f"\n[CHECK] Source IP: {src_ip}")

            signal_types = {signal["signal_type"] for signal in ip_signals}
            print(f"  Signals present: {signal_types}")
            print(f"  Required: {required_signals}")

            if required_signals.issubset(signal_types):
                print("  All signals matched!")

                if self._validate_time_window(ip_signals, time_window_minutes):
                    detection = self._create_detection(src_ip, ip_signals, rules)
                    self.detections.append(detection)

                    print(f"\n[DETECTION] {detection['detection_type']}")
                    print(f"  Source: {detection['src_ip']}")
                    print(f"  Severity: {detection['severity']}")
                    print(f"  Signals: {detection['signal_count']}")
                    print(f"  Backup Targets: {detection['backup_target_count']}")
                    print(f"  Destructive Actions: {detection['destructive_action_count']}")
                else:
                    print("  Signals outside time window")
            else:
                missing = required_signals - signal_types
                print(f"  Missing signals: {missing}")

    def _validate_time_window(self, signals: List[Dict], window_minutes: int) -> bool:
        """Validate all signals occurred within the configured time window."""
        timestamps = [
            datetime.fromisoformat(signal["timestamp"].replace("Z", "+00:00"))
            for signal in signals
            if signal.get("timestamp")
        ]

        if not timestamps:
            return False

        min_time = min(timestamps)
        max_time = max(timestamps)
        delta = (max_time - min_time).total_seconds() / 60

        print(f"  Time delta: {delta:.1f} minutes (max: {window_minutes})")
        return delta <= window_minutes

    def _create_detection(self, src_ip: str, signals: List[Dict], rules: Dict) -> Dict:
        """Create a ransomware backup targeting detection record."""
        backup_target_count = 0
        admin_service_count = 0
        destructive_action_count = 0

        for signal in signals:
            signal_type = signal["signal_type"]
            if signal_type == "BACKUP_SERVER_CONTACT":
                backup_target_count = signal.get("backup_target_count", 0)
            elif signal_type == "ADMIN_MANAGEMENT_PROTOCOL":
                admin_service_count = signal.get("admin_service_count", 0)
            elif signal_type == "DESTRUCTIVE_RECOVERY_ACTION":
                destructive_action_count = signal.get("destructive_action_count", 0)

        return {
            "detection_id": f"{rules['rule_id']}-{int(time.time())}",
            "detection_type": rules["detection_type"],
            "src_ip": src_ip,
            "severity": rules["severity"],
            "confidence": rules["confidence"],
            "signal_count": len(signals),
            "backup_target_count": backup_target_count,
            "admin_service_count": admin_service_count,
            "destructive_action_count": destructive_action_count,
            "timestamp": datetime.now().isoformat(),
            "signals": signals
        }

    def save_detections(self):
        """Save detections to SQLite."""
        if not self.detections:
            print("[WARN] No detections to save")
            return

        db_path_str = str(self.db_path.absolute())
        print(f"[DEBUG] Saving to: {db_path_str}")

        conn = sqlite3.connect(db_path_str)
        cursor = conn.cursor()

        try:
            for detection in self.detections:
                cursor.execute("""
                    INSERT OR REPLACE INTO ransomware_detections
                    (detection_id, detection_type, src_ip, severity, confidence,
                     signal_count, backup_target_count, admin_service_count,
                     destructive_action_count, timestamp, signals_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    detection["detection_id"],
                    detection["detection_type"],
                    detection["src_ip"],
                    detection["severity"],
                    detection["confidence"],
                    detection["signal_count"],
                    detection["backup_target_count"],
                    detection["admin_service_count"],
                    detection["destructive_action_count"],
                    detection["timestamp"],
                    json.dumps(detection["signals"])
                ))

            conn.commit()
            count = cursor.execute(
                "SELECT COUNT(*) FROM ransomware_detections"
            ).fetchone()[0]
            print(f"[VERIFY] {count} ransomware detection(s) in database")
        except Exception as exc:
            print(f"[ERROR] Failed to save: {exc}")
            conn.rollback()
            raise
        finally:
            conn.close()

        print(f"[INFO] Detections saved to SQLite: {db_path_str}")

    def run(self):
        """Main execution."""
        rules = self.load_rules()
        signals = self.load_signals()

        if not signals:
            print("\n[ERROR] No signals to correlate")
            return

        self.correlate(signals, rules)

        if self.detections:
            self.save_detections()
            self._print_summary()
        else:
            print("\n[INFO] No detections generated (signals did not correlate)")

    def _print_summary(self):
        """Print detection summary."""
        print("\n" + "=" * 60)
        print("Backup / Snapshot Targeting Detection Summary")
        print("=" * 60)

        for detection in self.detections:
            print(f"\nDetection ID: {detection['detection_id']}")
            print(f"Type: {detection['detection_type']}")
            print(f"Source: {detection['src_ip']}")
            print(f"Severity: {detection['severity']}")
            print(f"Confidence: {detection['confidence']}")
            print(f"Signals: {detection['signal_count']}")
            print(f"Backup Targets: {detection['backup_target_count']}")
            print(f"Admin Services: {detection['admin_service_count']}")
            print(f"Destructive Actions: {detection['destructive_action_count']}")

            print("\nContributing Signals:")
            for signal in detection["signals"]:
                print(f"  - {signal['signal_type']}: {signal.get('severity', 'N/A')}")


def main():
    engine = BackupTargetingCorrelationEngine()
    engine.run()


if __name__ == "__main__":
    main()
