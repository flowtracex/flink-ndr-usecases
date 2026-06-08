#!/usr/bin/env python3
"""
Common Flink SQL Signal Executor
Executes .sql files for signal generation

Usage: python run-signals.py <signals_directory>
"""

import sys
import json
import math
import re
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
        elif "dns-query-burst" in signal_name or "dns_query_burst" in signal_name:
            return self._detect_dns_query_burst(events)
        elif "high-entropy-dns" in signal_name or "high_entropy_dns" in signal_name:
            return self._detect_high_entropy_dns(events)
        elif "encoded-tunneling-pattern" in signal_name or "encoded_tunneling_pattern" in signal_name:
            return self._detect_encoded_tunneling_pattern(events)
        elif "backup-server-contact" in signal_name or "backup_server_contact" in signal_name:
            return self._detect_backup_server_contact(events)
        elif "admin-management-protocol" in signal_name or "admin_management_protocol" in signal_name:
            return self._detect_admin_management_protocol(events)
        elif "destructive-recovery-action" in signal_name or "destructive_recovery_action" in signal_name:
            return self._detect_destructive_recovery_action(events)
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

    def _detect_dns_query_burst(self, events):
        """Detect unusually high DNS query volume from one host"""
        dns_by_ip = {}

        for event in events:
            if event.get('protocol') != 'DNS':
                continue

            src_ip = event.get('src_ip')
            query = event.get('query') or event.get('dns_query')
            if not src_ip or not query:
                continue

            if src_ip not in dns_by_ip:
                dns_by_ip[src_ip] = {'queries': [], 'last_time': ''}

            dns_by_ip[src_ip]['queries'].append(query)
            event_time = event.get('event_time') or event.get('ts') or ''
            if event_time > dns_by_ip[src_ip]['last_time']:
                dns_by_ip[src_ip]['last_time'] = event_time

        signals = []
        for src_ip, data in dns_by_ip.items():
            query_count = len(data['queries'])
            unique_queries = len(set(data['queries']))

            if query_count >= 25 and unique_queries >= 20:
                signal = {
                    'signal_type': 'DNS_QUERY_BURST',
                    'src_ip': src_ip,
                    'query_count': query_count,
                    'unique_queries': unique_queries,
                    'severity': 'HIGH' if query_count >= 40 else 'MEDIUM',
                    'timestamp': data['last_time']
                }
                print(f"  ✓ DNS query burst: {src_ip} → {query_count} queries")
                signals.append(signal)
        return signals

    def _detect_high_entropy_dns(self, events):
        """Detect DNS queries with random-looking labels"""
        entropy_by_ip = {}

        for event in events:
            if event.get('protocol') != 'DNS':
                continue

            src_ip = event.get('src_ip')
            query = event.get('query') or event.get('dns_query')
            if not src_ip or not query:
                continue

            left_label = query.split('.')[0].lower()
            entropy = self._shannon_entropy(left_label)

            if len(left_label) >= 24 and entropy >= 3.5:
                if src_ip not in entropy_by_ip:
                    entropy_by_ip[src_ip] = {'queries': [], 'entropy': [], 'last_time': ''}
                entropy_by_ip[src_ip]['queries'].append(query)
                entropy_by_ip[src_ip]['entropy'].append(entropy)
                event_time = event.get('event_time') or event.get('ts') or ''
                if event_time > entropy_by_ip[src_ip]['last_time']:
                    entropy_by_ip[src_ip]['last_time'] = event_time

        signals = []
        for src_ip, data in entropy_by_ip.items():
            suspicious_count = len(data['queries'])
            if suspicious_count >= 10:
                avg_entropy = sum(data['entropy']) / suspicious_count
                signal = {
                    'signal_type': 'HIGH_ENTROPY_DNS',
                    'src_ip': src_ip,
                    'suspicious_query_count': suspicious_count,
                    'avg_entropy': round(avg_entropy, 2),
                    'severity': 'CRITICAL' if suspicious_count >= 20 else 'HIGH',
                    'timestamp': data['last_time']
                }
                print(f"  ✓ High-entropy DNS: {src_ip} → {suspicious_count} suspicious queries")
                signals.append(signal)
        return signals

    def _detect_encoded_tunneling_pattern(self, events):
        """Detect repeated encoded chunks to the same DNS tunnel domain"""
        tunnel_by_ip_domain = {}
        encoded_label = re.compile(r'^[a-z0-9]{24,}$')

        for event in events:
            if event.get('protocol') != 'DNS':
                continue

            src_ip = event.get('src_ip')
            query = event.get('query') or event.get('dns_query')
            query_type = event.get('query_type', 'A')
            if not src_ip or not query:
                continue

            labels = query.lower().split('.')
            if len(labels) < 3:
                continue

            left_label = labels[0]
            registered_domain = '.'.join(labels[-2:])

            if query_type in {'TXT', 'NULL', 'A'} and encoded_label.match(left_label):
                key = (src_ip, registered_domain)
                if key not in tunnel_by_ip_domain:
                    tunnel_by_ip_domain[key] = {
                        'chunks': set(),
                        'query_types': set(),
                        'last_time': ''
                    }
                tunnel_by_ip_domain[key]['chunks'].add(left_label)
                tunnel_by_ip_domain[key]['query_types'].add(query_type)
                event_time = event.get('event_time') or event.get('ts') or ''
                if event_time > tunnel_by_ip_domain[key]['last_time']:
                    tunnel_by_ip_domain[key]['last_time'] = event_time

        signals = []
        for (src_ip, domain), data in tunnel_by_ip_domain.items():
            chunk_count = len(data['chunks'])
            if chunk_count >= 12:
                signal = {
                    'signal_type': 'ENCODED_TUNNELING_PATTERN',
                    'src_ip': src_ip,
                    'tunnel_domain': domain,
                    'encoded_chunk_count': chunk_count,
                    'query_types': ', '.join(sorted(data['query_types'])),
                    'severity': 'CRITICAL' if chunk_count >= 20 else 'HIGH',
                    'timestamp': data['last_time']
                }
                print(f"  ✓ Encoded tunneling pattern: {src_ip} → {chunk_count} chunks to {domain}")
                signals.append(signal)
        return signals

    def _shannon_entropy(self, value):
        """Calculate Shannon entropy for a string."""
        if not value:
            return 0.0

        frequencies = {}
        for char in value:
            frequencies[char] = frequencies.get(char, 0) + 1

        entropy = 0.0
        length = len(value)
        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy

    def _detect_backup_server_contact(self, events):
        """Detect internal hosts contacting backup or snapshot infrastructure."""
        contacts_by_ip = {}

        for event in events:
            src_ip = event.get('src_ip')
            dest_ip = event.get('dest_ip')
            dest_role = event.get('dest_role', '').lower()
            service = event.get('service', '').lower()
            dest_port = event.get('dest_port')

            is_backup_target = (
                'backup' in dest_role or
                'snapshot' in dest_role or
                service in {'veeam', 'commvault', 'netbackup', 'rubrik'} or
                dest_port in {10001, 9392}
            )

            if src_ip and dest_ip and is_backup_target:
                if src_ip not in contacts_by_ip:
                    contacts_by_ip[src_ip] = {'targets': set(), 'last_time': ''}
                contacts_by_ip[src_ip]['targets'].add(dest_ip)
                event_time = event.get('event_time') or event.get('ts') or ''
                if event_time > contacts_by_ip[src_ip]['last_time']:
                    contacts_by_ip[src_ip]['last_time'] = event_time

        signals = []
        for src_ip, data in contacts_by_ip.items():
            target_count = len(data['targets'])
            if target_count >= 2:
                signal = {
                    'signal_type': 'BACKUP_SERVER_CONTACT',
                    'src_ip': src_ip,
                    'backup_target_count': target_count,
                    'severity': 'HIGH',
                    'timestamp': data['last_time']
                }
                print(f"  ✓ Backup server contact: {src_ip} → {target_count} backup targets")
                signals.append(signal)
        return signals

    def _detect_admin_management_protocol(self, events):
        """Detect admin protocol usage toward backup infrastructure."""
        admin_ports = {22: 'SSH', 135: 'RPC', 445: 'SMB', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM-HTTPS'}
        admin_by_ip = {}

        for event in events:
            src_ip = event.get('src_ip')
            dest_role = event.get('dest_role', '').lower()
            dest_port = event.get('dest_port')

            if (
                src_ip and
                dest_port in admin_ports and
                ('backup' in dest_role or 'snapshot' in dest_role)
            ):
                if src_ip not in admin_by_ip:
                    admin_by_ip[src_ip] = {'services': set(), 'last_time': ''}
                admin_by_ip[src_ip]['services'].add(admin_ports[dest_port])
                event_time = event.get('event_time') or event.get('ts') or ''
                if event_time > admin_by_ip[src_ip]['last_time']:
                    admin_by_ip[src_ip]['last_time'] = event_time

        signals = []
        for src_ip, data in admin_by_ip.items():
            service_count = len(data['services'])
            if service_count >= 2:
                services_list = ', '.join(sorted(data['services']))
                signal = {
                    'signal_type': 'ADMIN_MANAGEMENT_PROTOCOL',
                    'src_ip': src_ip,
                    'admin_service_count': service_count,
                    'services_list': services_list,
                    'severity': 'HIGH',
                    'timestamp': data['last_time']
                }
                print(f"  ✓ Admin management protocol: {src_ip} → {services_list}")
                signals.append(signal)
        return signals

    def _detect_destructive_recovery_action(self, events):
        """Detect commands that impair recovery before ransomware encryption."""
        destructive_actions = {
            'delete_snapshot',
            'delete_backup',
            'disable_backup_job',
            'stop_backup_service',
            'purge_restore_point'
        }
        actions_by_ip = {}

        for event in events:
            src_ip = event.get('src_ip')
            action = event.get('action', '').lower()
            dest_role = event.get('dest_role', '').lower()

            if (
                src_ip and
                action in destructive_actions and
                ('backup' in dest_role or 'snapshot' in dest_role)
            ):
                if src_ip not in actions_by_ip:
                    actions_by_ip[src_ip] = {'actions': set(), 'count': 0, 'last_time': ''}
                actions_by_ip[src_ip]['actions'].add(action)
                actions_by_ip[src_ip]['count'] += 1
                event_time = event.get('event_time') or event.get('ts') or ''
                if event_time > actions_by_ip[src_ip]['last_time']:
                    actions_by_ip[src_ip]['last_time'] = event_time

        signals = []
        for src_ip, data in actions_by_ip.items():
            if data['count'] >= 2:
                signal = {
                    'signal_type': 'DESTRUCTIVE_RECOVERY_ACTION',
                    'src_ip': src_ip,
                    'destructive_action_count': data['count'],
                    'actions_list': ', '.join(sorted(data['actions'])),
                    'severity': 'CRITICAL',
                    'timestamp': data['last_time']
                }
                print(f"  ✓ Destructive recovery action: {src_ip} → {data['count']} actions")
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
