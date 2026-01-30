#!/usr/bin/env python3
"""
Layer 2: Multi-Signal Correlation Engine
Correlates signals from Layer 1 into high-confidence detections

Storage: SQLite (demo)
Production: Add Redis for distributed state
"""

import json
import sqlite3
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List

class CorrelationEngine:
    """
    Multi-signal correlation with time-window validation
    
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
        self.db_path = Path("../../../output/detections.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        
        self.detections = []
    
    def _init_db(self):
        """Initialize SQLite database"""
        # Convert Path to absolute string - SQLite needs a string, not Path object
        db_path_str = str(self.db_path.absolute())
        conn = sqlite3.connect(db_path_str)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                detection_id TEXT PRIMARY KEY,
                detection_type TEXT,
                src_ip TEXT,
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
        Multi-stage correlation logic
        
        Demo: Uses in-memory dict
        Production: Uses Redis with TTL keys
        """
        print("\n" + "=" * 60)
        print("LAYER 2: Multi-Signal Correlation")
        print("=" * 60)
        
        required_signals = set(rules['required_signals'])
        time_window_minutes = rules['time_window_minutes']
        
        # Group signals by source IP
        signals_by_ip = {}
        for signal in signals:
            src_ip = signal.get('src_ip')
            if src_ip not in signals_by_ip:
                signals_by_ip[src_ip] = []
            signals_by_ip[src_ip].append(signal)
        
        # Check correlation for each IP
        for src_ip, ip_signals in signals_by_ip.items():
            print(f"\n[CHECK] Source IP: {src_ip}")
            
            signal_types = {s['signal_type'] for s in ip_signals}
            print(f"  Signals present: {signal_types}")
            print(f"  Required: {required_signals}")
            
            # Check if all required signals present
            if required_signals.issubset(signal_types):
                print(f"  ✓ All signals matched!")
                
                # Validate time window
                if self._validate_time_window(ip_signals, time_window_minutes):
                    detection = self._create_detection(src_ip, ip_signals, rules)
                    self.detections.append(detection)
                    
                    print(f"\n[DETECTION] 🚨 {detection['detection_type']}")
                    print(f"  Source: {detection['src_ip']}")
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
    
    def _create_detection(self, src_ip: str, signals: List[Dict], rules: Dict) -> Dict:
        """Create detection record"""
        return {
            'detection_id': f"{rules['rule_id']}-{int(time.time())}",
            'detection_type': rules['detection_type'],
            'src_ip': src_ip,
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
        
        # Convert Path to absolute string - CRITICAL: SQLite needs string, not Path
        db_path_str = str(self.db_path.absolute())
        print(f"[DEBUG] Saving to: {db_path_str}")
        
        conn = sqlite3.connect(db_path_str)
        cursor = conn.cursor()
        
        try:
            for detection in self.detections:
                print("detection .....................")
                print(detection)
                cursor.execute('''
                    INSERT OR REPLACE INTO detections 
                    (detection_id, detection_type, src_ip, severity, confidence, signal_count, timestamp, signals_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    detection['detection_id'],
                    detection['detection_type'],
                    detection['src_ip'],
                    detection['severity'],
                    detection['confidence'],
                    detection['signal_count'],
                    detection['timestamp'],
                    json.dumps(detection['signals'])
                ))
                print(f"[DEBUG] Inserting: {detection['detection_id']}")
            
            # Commit the transaction
            conn.commit()
            print(f"[DEBUG] Committed transaction")
            
            # Verify insert worked
            count = cursor.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            print(f"[VERIFY] {count} detection(s) in database")
            
        except Exception as e:
            print(f"[ERROR] Failed to save: {e}")
            import traceback
            traceback.print_exc()
            conn.rollback()
            raise
        finally:
            conn.close()
        
        # Reopen to verify data persisted to disk
        conn2 = sqlite3.connect(db_path_str)
        cursor2 = conn2.cursor()
        count_after = cursor2.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        cursor2.close()
        conn2.close()
        print(f"[VERIFY] {count_after} detection(s) after reopen")
        
        print(f"[INFO] Detections saved to SQLite: {db_path_str}")
    
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
        print("Detection Summary")
        print("=" * 60)
        
        for detection in self.detections:
            print(f"\nDetection ID: {detection['detection_id']}")
            print(f"Type: {detection['detection_type']}")
            print(f"Source: {detection['src_ip']}")
            print(f"Severity: {detection['severity']}")
            print(f"Confidence: {detection['confidence']}")
            print(f"Signals: {detection['signal_count']}")
            
            print("\nContributing Signals:")
            for signal in detection['signals']:
                print(f"  • {signal['signal_type']}: {signal.get('severity', 'N/A')}")

def main():
    engine = CorrelationEngine()
    engine.run()

if __name__ == "__main__":
    main()
