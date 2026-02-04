#!/usr/bin/env python3
"""
Layer 2: Multi-Signal Correlation Engine - C2 Beaconing Detection
Correlates signals from Layer 1 into high-confidence C2 detections

Storage: SQLite (demo)
Production: Add Redis for distributed state
"""

import json
import sqlite3
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List

class C2CorrelationEngine:
    """
    C2 Beaconing correlation with time-window validation
    
    Demo: Uses in-memory state + SQLite storage
    Production: Uses Redis for state + PostgreSQL for detections
    """
    
    def __init__(self, rules_file="rules.json", signals_file="../signals-output.json"):
        self.rules_file = Path(rules_file)
        self.signals_file = Path(signals_file)
        
        # In-memory state (demo)
        # Production: Replace with Redis
        self.state = {}
        
        # SQLite for final detections
        self.db_path = Path("../../../output/c2-detections.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        
        self.detections = []
    
    def _init_db(self):
        """Initialize SQLite database"""
        db_path_str = str(self.db_path.absolute())
        conn = sqlite3.connect(db_path_str)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS c2_detections (
                detection_id TEXT PRIMARY KEY,
                detection_type TEXT,
                src_ip TEXT,
                dest_ip TEXT,
                severity TEXT,
                confidence TEXT,
                signal_count INTEGER,
                timestamp TEXT,
                signals_json TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"[INFO] Database initialized: {db_path_str}")
    
    def load_rules(self):
        """Load correlation rules"""
        print(f"[INFO] Loading rules: {self.rules_file}")
        with open(self.rules_file, 'r') as f:
            rules = json.load(f)
        print(f"[INFO] Loaded rule: {rules['rule_name']}")
        return rules
    
    def load_signals(self):
        """Load signals from Layer 1"""
        print(f"[INFO] Loading signals: {self.signals_file}")
        
        if not self.signals_file.exists():
            print("[ERROR] No signals found. Run Layer 1 first.")
            return []
        
        with open(self.signals_file, 'r') as f:
            signals = json.load(f)
        
        print(f"[INFO] Loaded {len(signals)} signals")
        return signals
    
    def correlate(self, signals: List[Dict], rules: Dict):
        """
        Multi-stage C2 correlation logic
        
        Demo: Uses in-memory dict
        Production: Uses Redis with TTL keys
        """
        print("\n" + "=" * 60)
        print("LAYER 2: C2 Beaconing Correlation")
        print("=" * 60)
        
        required_signals = set(rules['required_signals'])
        time_window_minutes = rules['time_window_minutes']
        
        # Group signals by source-destination pair
        signals_by_pair = {}
        for signal in signals:
            src_ip = signal.get('src_ip')
            dest_ip = signal.get('dest_ip')
            pair_key = f"{src_ip}->{dest_ip}"
            
            if pair_key not in signals_by_pair:
                signals_by_pair[pair_key] = []
            signals_by_pair[pair_key].append(signal)
        
        # Check correlation for each pair
        for pair_key, pair_signals in signals_by_pair.items():
            src_ip, dest_ip = pair_key.split('->')
            print(f"\n[CHECK] Connection: {pair_key}")
            
            signal_types = {s['signal_type'] for s in pair_signals}
            print(f"  Signals present: {signal_types}")
            print(f"  Required: {required_signals}")
            
            # Check if all required signals present
            if required_signals.issubset(signal_types):
                print(f"  ✓ All signals matched!")
                
                # Validate time window
                if self._validate_time_window(pair_signals, time_window_minutes):
                    detection = self._create_detection(src_ip, dest_ip, pair_signals, rules)
                    self.detections.append(detection)
                    
                    print(f"\n[DETECTION] 🚨 {detection['detection_type']}")
                    print(f"  Source: {detection['src_ip']}")
                    print(f"  Destination: {detection['dest_ip']}")
                    print(f"  Severity: {detection['severity']}")
                    print(f"  Signals: {detection['signal_count']}")
                else:
                    print(f"  ✗ Signals outside time window")
            else:
                missing = required_signals - signal_types
                print(f"  ✗ Missing: {missing}")
    
    def _validate_time_window(self, signals: List[Dict], window_minutes: int) -> bool:
        """
        Validate all signals occurred within time window
        
        Production: Redis TTL handles this automatically
        """
        timestamps = [datetime.fromisoformat(s['timestamp'].replace('Z', '+00:00')) 
                     for s in signals]
        
        min_time = min(timestamps)
        max_time = max(timestamps)
        delta = (max_time - min_time).total_seconds() / 60
        
        print(f"  Time delta: {delta:.1f} minutes (max: {window_minutes})")
        return delta <= window_minutes
    
    def _create_detection(self, src_ip: str, dest_ip: str, signals: List[Dict], rules: Dict) -> Dict:
        """Create C2 detection record"""
        return {
            'detection_id': f"{rules['rule_id']}-{int(time.time())}",
            'detection_type': rules['detection_type'],
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'severity': rules['severity'],
            'confidence': rules['confidence'],
            'signal_count': len(signals),
            'timestamp': datetime.now().isoformat(),
            'signals': signals
        }
    
    def save_detections(self):
        """Save detections to SQLite"""
        if not self.detections:
            print("[WARN] No detections to save")
            return
        
        db_path_str = str(self.db_path.absolute())
        print(f"[DEBUG] Saving to: {db_path_str}")
        
        conn = sqlite3.connect(db_path_str)
        cursor = conn.cursor()
        
        try:
            for detection in self.detections:
                print(f"[DEBUG] Detection: {detection['detection_id']}")
                cursor.execute('''
                    INSERT OR REPLACE INTO c2_detections 
                    (detection_id, detection_type, src_ip, dest_ip, severity, 
                     confidence, signal_count, timestamp, signals_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    detection['detection_id'],
                    detection['detection_type'],
                    detection['src_ip'],
                    detection['dest_ip'],
                    detection['severity'],
                    detection['confidence'],
                    detection['signal_count'],
                    detection['timestamp'],
                    json.dumps(detection['signals'])
                ))
            
            conn.commit()
            print(f"[DEBUG] Committed transaction")
            
            count = cursor.execute("SELECT COUNT(*) FROM c2_detections").fetchone()[0]
            print(f"[VERIFY] {count} detection(s) in database")
            
        except Exception as e:
            print(f"[ERROR] Failed to save: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise
        finally:
            conn.close()
        
        print(f"[INFO] Detections saved: {db_path_str}")
    
    def run(self):
        """Main execution"""
        rules = self.load_rules()
        signals = self.load_signals()
        
        if not signals:
            print("\n[ERROR] No signals to correlate")
            return
        
        self.correlate(signals, rules)
        
        if self.detections:
            self.save_detections()
            self._print_summary()
    
    def _print_summary(self):
        """Print detection summary"""
        print("\n" + "=" * 60)
        print("C2 Detection Summary")
        print("=" * 60)
        
        for detection in self.detections:
            print(f"\nDetection ID: {detection['detection_id']}")
            print(f"Type: {detection['detection_type']}")
            print(f"Source: {detection['src_ip']} → {detection['dest_ip']}")
            print(f"Severity: {detection['severity']}")
            print(f"Confidence: {detection['confidence']}")
            print(f"Signals: {detection['signal_count']}")
            
            print("\nContributing Signals:")
            for signal in detection['signals']:
                print(f"  • {signal['signal_type']}: {signal.get('severity', 'N/A')}")

def main():
    engine = C2CorrelationEngine()
    engine.run()

if __name__ == "__main__":
    main()
