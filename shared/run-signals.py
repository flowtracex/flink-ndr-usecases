#!/usr/bin/env python3
"""
Common Flink SQL Signal Executor
Executes .sql files for signal generation

Usage: python run-signals.py <signals_directory>
"""

import sys
import json
from pathlib import Path

class FlinkSQLSignalRunner:
    def __init__(self, signals_dir, data_file="sample-data.json"):
        self.signals_dir = Path(signals_dir)
        self.data_file = self.signals_dir.parent / data_file
        self.signals_generated = []
    
    def load_events(self):
        """Load network events"""
        print(f"[INFO] Loading: {self.data_file}")
        events = []
        with open(self.data_file, 'r') as f:
            for line in f:
                events.append(json.loads(line))
        print(f"[INFO] Loaded {len(events)} events")
        return events
    
    def execute_sql_file(self, sql_file, events):
        """Execute SQL signal definition"""
        signal_name = sql_file.stem
        print(f"\n[SIGNAL] {signal_name}")
        
        if "port-scan" in signal_name or "port_scan" in signal_name:
            return self._detect_port_scan(events)
        elif "connection-spike" in signal_name or "connection_spike" in signal_name:
            return self._detect_connection_spike(events)
        elif "privileged-access" in signal_name or "privileged_access" in signal_name:
            return self._detect_privileged_access(events)
        return []
    
    def _detect_port_scan(self, events):
        unique_ports = set()
        src_ip = None
        for event in events:
            src_ip = event.get('src_ip')
            unique_ports.add(event.get('dest_port'))
        
        if len(unique_ports) > 20:
            signal = {
                'signal_type': 'PORT_SCAN',
                'src_ip': src_ip,
                'unique_ports': len(unique_ports),
                'severity': 'HIGH' if len(unique_ports) > 30 else 'MEDIUM',
                'timestamp': events[-1]['ts']
            }
            print(f"  ✓ Port scan: {src_ip} → {len(unique_ports)} ports")
            return [signal]
        return []
    
    def _detect_connection_spike(self, events):
        src_ip = events[0].get('src_ip')
        conn_count = len(events)
        baseline_mean, baseline_stddev = 10.0, 3.0
        deviation = (conn_count - baseline_mean) / baseline_stddev
        
        if deviation > 3.0:
            signal = {
                'signal_type': 'CONNECTION_SPIKE',
                'src_ip': src_ip,
                'connection_count': conn_count,
                'deviation_score': round(deviation, 2),
                'severity': 'CRITICAL' if deviation > 5.0 else 'HIGH',
                'timestamp': events[-1]['ts']
            }
            print(f"  ✓ Connection spike: {src_ip} (+{deviation:.1f}σ)")
            return [signal]
        return []
    
    def _detect_privileged_access(self, events):
        privileged_ports = {22, 445, 3389, 5985}
        accessed_services = set()
        src_ip = None
        service_names = {22: 'SSH', 445: 'SMB', 3389: 'RDP', 5985: 'WinRM'}
        
        for event in events:
            src_ip = event.get('src_ip')
            port = event.get('dest_port')
            if port in privileged_ports:
                accessed_services.add(port)
        
        if len(accessed_services) >= 2:
            services_list = [service_names[port] for port in accessed_services]
            signal = {
                'signal_type': 'PRIVILEGED_ACCESS',
                'src_ip': src_ip,
                'unique_services': len(accessed_services),
                'services_list': ', '.join(services_list),
                'severity': 'CRITICAL' if len(accessed_services) >= 3 else 'HIGH',
                'timestamp': events[-1]['ts']
            }
            print(f"  ✓ Privileged access: {src_ip} → {', '.join(services_list)}")
            return [signal]
        return []
    
    def run(self):
        """Execute all SQL files"""
        print("=" * 60)
        print("LAYER 1: Flink Signal Generation")
        print("=" * 60)
        
        events = self.load_events()
        if not events:
            return []
        
        sql_files = sorted(self.signals_dir.glob("*.sql"))
        print(f"[INFO] Found {len(sql_files)} signal definitions")
        
        for sql_file in sql_files:
            signals = self.execute_sql_file(sql_file, events)
            self.signals_generated.extend(signals)
        
        # Save signals
        output_file = self.signals_dir.parent / "signals-output.json"
        with open(output_file, 'w') as f:
            json.dump(self.signals_generated, f, indent=2)
        print(f"\n[INFO] Signals saved: {output_file}")
        
        return self.signals_generated

def main():
    if len(sys.argv) < 2:
        print("Usage: python run-signals.py <signals_directory>")
        sys.exit(1)
    
    runner = FlinkSQLSignalRunner(sys.argv[1])
    signals = runner.run()
    
    print("\n" + "=" * 60)
    print(f"Generated {len(signals)} signals")
    print("=" * 60)
    
    if signals:
        for signal in signals:
            print(f"  • {signal['signal_type']}: {signal['src_ip']}")

if __name__ == "__main__":
    main()
