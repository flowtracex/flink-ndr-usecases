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
            content = f.read().strip()
            # Try to parse as JSON array first
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    events = data
                else:
                    # Single object, wrap in list
                    events = [data]
            except json.JSONDecodeError:
                # Fall back to newline-delimited JSON
                for line in content.split('\n'):
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
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
        elif "data-staging" in signal_name or "data_staging" in signal_name:
            return self._detect_data_staging(events)
        elif "outbound-spike" in signal_name or "outbound_spike" in signal_name:
            return self._detect_outbound_spike(events)
        elif "destination-diversity" in signal_name or "destination_diversity" in signal_name:
            return self._detect_destination_diversity(events)
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
    
    def _detect_data_staging(self, events):
        """Detect internal data staging behavior"""
        # Group by src_ip
        staging_by_ip = {}
        
        for event in events:
            src_ip = event.get('src_ip')
            dest_ip = event.get('dest_ip')
            is_outbound = event.get('is_outbound', False)
            bytes_transferred = event.get('bytes_transferred', 0)
            
            # Internal-to-internal transfers only
            if (not is_outbound and 
                src_ip and dest_ip and
                (src_ip.startswith('10.') or src_ip.startswith('172.16.') or src_ip.startswith('192.168.')) and
                (dest_ip.startswith('10.') or dest_ip.startswith('172.16.') or dest_ip.startswith('192.168.'))):
                if src_ip not in staging_by_ip:
                    staging_by_ip[src_ip] = {'bytes': 0, 'count': 0, 'last_time': ''}
                staging_by_ip[src_ip]['bytes'] += bytes_transferred
                staging_by_ip[src_ip]['count'] += 1
                # Track latest timestamp
                event_time = event.get('event_time') or event.get('ts') or ''
                if event_time > staging_by_ip[src_ip]['last_time']:
                    staging_by_ip[src_ip]['last_time'] = event_time
        
        signals = []
        for src_ip, data in staging_by_ip.items():
            total_bytes = data['bytes']
            if total_bytes > 500000000:  # >500MB threshold
                signal = {
                    'signal_type': 'DATA_STAGING',
                    'src_ip': src_ip,
                    'total_bytes_staged': total_bytes,
                    'transfer_count': data['count'],
                    'severity': 'HIGH' if total_bytes > 1000000000 else 'MEDIUM',
                    'timestamp': data['last_time'] or (events[-1].get('event_time') if events else '') or (events[-1].get('ts') if events else '')
                }
                print(f"  ✓ Data staging: {src_ip} → {total_bytes / 1000000000:.2f} GB")
                signals.append(signal)
        return signals
    
    def _detect_outbound_spike(self, events):
        """Detect outbound volume spike"""
        # Group by src_ip
        traffic_by_ip = {}
        
        for event in events:
            src_ip = event.get('src_ip')
            is_outbound = event.get('is_outbound', False)
            bytes_transferred = event.get('bytes_transferred', 0)
            
            if src_ip:
                if src_ip not in traffic_by_ip:
                    traffic_by_ip[src_ip] = {'outbound': 0, 'inbound': 0, 'last_time': ''}
                if is_outbound:
                    traffic_by_ip[src_ip]['outbound'] += bytes_transferred
                else:
                    traffic_by_ip[src_ip]['inbound'] += bytes_transferred
                # Track latest timestamp
                event_time = event.get('event_time') or event.get('ts') or ''
                if event_time > traffic_by_ip[src_ip]['last_time']:
                    traffic_by_ip[src_ip]['last_time'] = event_time
        
        signals = []
        for src_ip, data in traffic_by_ip.items():
            outbound_bytes = data['outbound']
            inbound_bytes = data['inbound']
            
            # Calculate upload ratio
            upload_ratio = outbound_bytes / inbound_bytes if inbound_bytes > 0 else 999.0
            
            # Deviation score (simplified)
            baseline = 50000000.0  # 50MB
            stddev = 25000000.0    # 25MB
            deviation_score = (outbound_bytes - baseline) / stddev if stddev > 0 else 0
            
            # Check thresholds
            if (outbound_bytes > 1000000000 or  # >1GB absolute
                deviation_score > 3.0 or        # >3 std deviations
                upload_ratio > 10.0):           # Upload >> download
                
                signal = {
                    'signal_type': 'OUTBOUND_SPIKE',
                    'src_ip': src_ip,
                    'bytes_uploaded': outbound_bytes,
                    'bytes_downloaded': inbound_bytes,
                    'upload_ratio': round(upload_ratio, 2),
                    'deviation_score': round(deviation_score, 2),
                    'severity': 'CRITICAL' if outbound_bytes > 2000000000 else 'HIGH',
                    'timestamp': data['last_time'] or (events[-1].get('event_time') if events else '') or (events[-1].get('ts') if events else '')
                }
                print(f"  ✓ Outbound spike: {src_ip} → {outbound_bytes / 1000000000:.2f} GB (ratio: {upload_ratio:.1f}x)")
                signals.append(signal)
        return signals
    
    def _detect_destination_diversity(self, events):
        """Detect high destination diversity"""
        # Group by src_ip
        diversity_by_ip = {}
        
        for event in events:
            src_ip = event.get('src_ip')
            dest_ip = event.get('dest_ip')
            is_outbound = event.get('is_outbound', False)
            bytes_transferred = event.get('bytes_transferred', 0)
            
            # External destinations only
            if (is_outbound and 
                src_ip and dest_ip and
                (src_ip.startswith('10.') or src_ip.startswith('172.16.') or src_ip.startswith('192.168.')) and
                not (dest_ip.startswith('10.') or dest_ip.startswith('172.16.') or dest_ip.startswith('192.168.'))):
                if src_ip not in diversity_by_ip:
                    diversity_by_ip[src_ip] = {'destinations': set(), 'bytes': 0, 'last_time': ''}
                diversity_by_ip[src_ip]['destinations'].add(dest_ip)
                diversity_by_ip[src_ip]['bytes'] += bytes_transferred
                # Track latest timestamp
                event_time = event.get('event_time') or event.get('ts') or ''
                if event_time > diversity_by_ip[src_ip]['last_time']:
                    diversity_by_ip[src_ip]['last_time'] = event_time
        
        signals = []
        for src_ip, data in diversity_by_ip.items():
            unique_destinations = len(data['destinations'])
            total_bytes = data['bytes']
            
            if unique_destinations >= 5 and total_bytes > 50000000:  # 5+ destinations and >50MB
                signal = {
                    'signal_type': 'DESTINATION_DIVERSITY',
                    'src_ip': src_ip,
                    'unique_destinations': unique_destinations,
                    'total_bytes_sent': total_bytes,
                    'severity': 'HIGH' if unique_destinations > 15 else 'MEDIUM',
                    'timestamp': data['last_time'] or (events[-1].get('event_time') if events else '') or (events[-1].get('ts') if events else '')
                }
                print(f"  ✓ Destination diversity: {src_ip} → {unique_destinations} unique destinations")
                signals.append(signal)
        return signals
    
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
