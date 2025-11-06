"""
Protocol Analyzer
Advanced protocol analysis and statistics
"""

from collections import defaultdict, Counter
import time
from datetime import datetime

class ProtocolAnalyzer:
    """Enterprise protocol analyzer with deep packet inspection"""
    
    def __init__(self):
        self.protocol_stats = defaultdict(int)
        self.flow_table = {}
        self.bandwidth_history = []
        self.last_update = time.time()
        self.last_packet_count = 0
        
    def analyze(self, packet):
        """Perform deep protocol analysis"""
        analysis = []
        analysis.append("=" * 80)
        analysis.append("PROTOCOL ANALYSIS")
        analysis.append("=" * 80)
        analysis.append("")
        
        protocol = packet.get('protocol', 'UNKNOWN')
        
        # Protocol-specific analysis
        if protocol == 'TCP':
            analysis.extend(self._analyze_tcp(packet))
        elif protocol == 'UDP':
            analysis.extend(self._analyze_udp(packet))
        elif protocol == 'ICMP':
            analysis.extend(self._analyze_icmp(packet))
        elif protocol == 'ARP':
            analysis.extend(self._analyze_arp(packet))
        elif protocol == 'DNS':
            analysis.extend(self._analyze_dns(packet))
            
        # Security analysis
        analysis.append("\nSECURITY ANALYSIS:")
        analysis.extend(self._security_analysis(packet))
        
        # Performance metrics
        analysis.append("\nPERFORMANCE METRICS:")
        analysis.extend(self._performance_analysis(packet))
        
        return '\n'.join(analysis)
        
    def _analyze_tcp(self, packet):
        """Analyze TCP protocol specifics"""
        analysis = []
        analysis.append("TCP PROTOCOL ANALYSIS:")
        analysis.append("")
        
        flags = packet.get('tcp_flags', '').split(',')
        
        # Connection state analysis
        if 'SYN' in flags and 'ACK' not in flags:
            analysis.append("  Connection State: SYN - Connection Initiation")
        elif 'SYN' in flags and 'ACK' in flags:
            analysis.append("  Connection State: SYN-ACK - Connection Acknowledgment")
        elif 'FIN' in flags:
            analysis.append("  Connection State: FIN - Connection Termination")
        elif 'RST' in flags:
            analysis.append("  Connection State: RST - Connection Reset (Abnormal)")
        elif 'ACK' in flags:
            analysis.append("  Connection State: ACK - Data Transfer/Acknowledgment")
            
        # Flag analysis
        analysis.append(f"  Flags Set: {', '.join(flags) if flags else 'None'}")
        
        # Window size analysis
        window = packet.get('tcp_window', 0)
        analysis.append(f"  Window Size: {window} bytes")
        if window == 0:
            analysis.append("  ⚠️  WARNING: Zero window - Receiver buffer full")
        elif window < 1024:
            analysis.append("  ⚠️  WARNING: Small window - Potential performance issue")
            
        # Port analysis
        sport = packet.get('tcp_sport', 0)
        dport = packet.get('tcp_dport', 0)
        analysis.append(f"  Source Port: {sport} ({self._identify_service(sport)})")
        analysis.append(f"  Destination Port: {dport} ({self._identify_service(dport)})")
        
        # Sequence analysis
        seq = packet.get('tcp_seq', 0)
        ack = packet.get('tcp_ack', 0)
        analysis.append(f"  Sequence Number: {seq}")
        analysis.append(f"  Acknowledgment Number: {ack}")
        
        return analysis
        
    def _analyze_udp(self, packet):
        """Analyze UDP protocol specifics"""
        analysis = []
        analysis.append("UDP PROTOCOL ANALYSIS:")
        analysis.append("")
        analysis.append("  Protocol: Connectionless, Unreliable Datagram")
        
        sport = packet.get('udp_sport', 0)
        dport = packet.get('udp_dport', 0)
        length = packet.get('udp_len', 0)
        
        analysis.append(f"  Source Port: {sport} ({self._identify_service(sport)})")
        analysis.append(f"  Destination Port: {dport} ({self._identify_service(dport)})")
        analysis.append(f"  Datagram Length: {length} bytes")
        
        # Check for common UDP-based protocols
        if dport == 53 or sport == 53:
            analysis.append("  Application: DNS (Domain Name System)")
        elif dport == 67 or dport == 68:
            analysis.append("  Application: DHCP (Dynamic Host Configuration)")
        elif dport == 123:
            analysis.append("  Application: NTP (Network Time Protocol)")
        elif dport == 161 or dport == 162:
            analysis.append("  Application: SNMP (Simple Network Management)")
            
        return analysis
        
    def _analyze_icmp(self, packet):
        """Analyze ICMP protocol specifics"""
        analysis = []
        analysis.append("ICMP PROTOCOL ANALYSIS:")
        analysis.append("")
        
        icmp_type = packet.get('icmp_type', 0)
        icmp_code = packet.get('icmp_code', 0)
        
        type_meanings = {
            0: "Echo Reply (Ping Response)",
            3: "Destination Unreachable",
            4: "Source Quench (Congestion Control)",
            5: "Redirect Message",
            8: "Echo Request (Ping)",
            9: "Router Advertisement",
            10: "Router Solicitation",
            11: "Time Exceeded",
            12: "Parameter Problem",
            13: "Timestamp Request",
            14: "Timestamp Reply"
        }
        
        analysis.append(f"  Type: {icmp_type} - {type_meanings.get(icmp_type, 'Unknown')}")
        analysis.append(f"  Code: {icmp_code}")
        
        if icmp_type == 3:
            code_meanings = {
                0: "Network Unreachable",
                1: "Host Unreachable",
                2: "Protocol Unreachable",
                3: "Port Unreachable",
                4: "Fragmentation Needed",
                5: "Source Route Failed"
            }
            analysis.append(f"  Meaning: {code_meanings.get(icmp_code, 'Unknown Error')}")
            
        return analysis
        
    def _analyze_arp(self, packet):
        """Analyze ARP protocol specifics"""
        analysis = []
        analysis.append("ARP PROTOCOL ANALYSIS:")
        analysis.append("")
        
        op = packet.get('arp_op', 0)
        analysis.append(f"  Operation: {'Request' if op == 1 else 'Reply' if op == 2 else 'Unknown'}")
        analysis.append(f"  Hardware Type: {packet.get('arp_hwtype', 'N/A')}")
        analysis.append(f"  Protocol Type: {packet.get('arp_ptype', 'N/A')}")
        analysis.append(f"  Sender MAC: {packet.get('arp_hwsrc', 'N/A')}")
        analysis.append(f"  Sender IP: {packet.get('arp_psrc', 'N/A')}")
        analysis.append(f"  Target MAC: {packet.get('arp_hwdst', 'N/A')}")
        analysis.append(f"  Target IP: {packet.get('arp_pdst', 'N/A')}")
        
        return analysis
        
    def _analyze_dns(self, packet):
        """Analyze DNS protocol specifics"""
        analysis = []
        analysis.append("DNS PROTOCOL ANALYSIS:")
        analysis.append("")
        
        qr = packet.get('dns_qr', 0)
        analysis.append(f"  Type: {'Query' if qr == 0 else 'Response'}")
        analysis.append(f"  Transaction ID: {packet.get('dns_id', 'N/A')}")
        analysis.append(f"  Questions: {packet.get('dns_qdcount', 0)}")
        analysis.append(f"  Answers: {packet.get('dns_ancount', 0)}")
        analysis.append(f"  Authority Records: {packet.get('dns_nscount', 0)}")
        analysis.append(f"  Additional Records: {packet.get('dns_arcount', 0)}")
        
        return analysis
        
    def _security_analysis(self, packet):
        """Perform security analysis on packet"""
        analysis = []
        alerts = []
        
        # Check for suspicious patterns
        protocol = packet.get('protocol', '')
        
        # Port scanning detection
        if protocol == 'TCP':
            flags = packet.get('tcp_flags', '')
            if 'SYN' in flags and 'ACK' not in flags:
                dport = packet.get('tcp_dport', 0)
                if dport < 1024:
                    alerts.append("⚠️  Possible port scan - SYN to privileged port")
            if 'RST' in flags:
                alerts.append("ℹ️  Connection reset detected")
                
        # Fragmentation analysis
        if 'ip_flags' in packet:
            flags = packet.get('ip_flags', '')
            if 'MF' in str(flags):
                alerts.append("ℹ️  Fragmented packet detected")
                
        # TTL analysis
        ttl = packet.get('ttl', 0)
        if isinstance(ttl, int):
            if ttl < 10:
                alerts.append("⚠️  Abnormally low TTL - Possible routing loop")
            elif ttl > 200:
                alerts.append("⚠️  Unusually high TTL - Possible spoofing")
                
        # Broadcast/Multicast analysis
        dst = packet.get('destination', '')
        if dst.startswith('255.255.255.255') or dst.startswith('224.'):
            alerts.append("ℹ️  Broadcast/Multicast packet")
            
        if alerts:
            analysis.extend(alerts)
        else:
            analysis.append("  ✓ No security concerns detected")
            
        return analysis
        
    def _performance_analysis(self, packet):
        """Analyze packet performance metrics"""
        analysis = []
        
        length = packet.get('length', 0)
        analysis.append(f"  Packet Size: {length} bytes")
        
        if length < 64:
            analysis.append("  ⚠️  Small packet - Possible overhead inefficiency")
        elif length > 1500:
            analysis.append("  ℹ️  Jumbo frame detected")
            
        # Protocol efficiency
        protocol = packet.get('protocol', '')
        if protocol == 'TCP':
            analysis.append("  Protocol Overhead: ~40 bytes (TCP/IP headers)")
            efficiency = ((length - 40) / length * 100) if length > 0 else 0
            analysis.append(f"  Payload Efficiency: {efficiency:.1f}%")
        elif protocol == 'UDP':
            analysis.append("  Protocol Overhead: ~28 bytes (UDP/IP headers)")
            efficiency = ((length - 28) / length * 100) if length > 0 else 0
            analysis.append(f"  Payload Efficiency: {efficiency:.1f}%")
            
        return analysis
        
    def _identify_service(self, port):
        """Identify common services by port number"""
        services = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
            25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
            143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP", 179: "BGP",
            194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
            465: "SMTPS", 514: "SYSLOG", 515: "LPR", 520: "RIP",
            587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "ORACLE", 3306: "MYSQL", 3389: "RDP",
            5432: "POSTGRESQL", 5900: "VNC", 6379: "REDIS", 8080: "HTTP-PROXY",
            8443: "HTTPS-ALT", 27017: "MONGODB"
        }
        return services.get(port, "Unknown")
        
    def get_statistics(self, packets):
        """Calculate comprehensive statistics"""
        if not packets:
            return {
                'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'arp': 0,
                'rate': 0, 'bandwidth': 0
            }
            
        protocol_count = Counter()
        total_bytes = 0
        
        for packet in packets:
            protocol = packet.get('protocol', 'OTHER')
            protocol_count[protocol] += 1
            total_bytes += packet.get('length', 0)
            
        # Calculate packet rate
        current_time = time.time()
        time_diff = current_time - self.last_update
        if time_diff >= 1.0:
            packet_diff = len(packets) - self.last_packet_count
            rate = packet_diff / time_diff if time_diff > 0 else 0
            bandwidth = (total_bytes / 1024) / time_diff if time_diff > 0 else 0
            
            self.last_update = current_time
            self.last_packet_count = len(packets)
        else:
            rate = 0
            bandwidth = 0
            
        return {
            'total': len(packets),
            'tcp': protocol_count.get('TCP', 0),
            'udp': protocol_count.get('UDP', 0),
            'icmp': protocol_count.get('ICMP', 0),
            'arp': protocol_count.get('ARP', 0),
            'rate': round(rate, 2),
            'bandwidth': round(bandwidth, 2)
        }
        
    def format_statistics(self, stats):
        """Format statistics for display"""
        text = []
        text.append("=" * 80)
        text.append("COMPREHENSIVE PACKET STATISTICS")
        text.append("=" * 80)
        text.append("")
        text.append(f"Total Packets Captured: {stats['total']}")
        text.append(f"Capture Rate: {stats['rate']} packets/second")
        text.append(f"Bandwidth Usage: {stats['bandwidth']} KB/s")
        text.append("")
        text.append("PROTOCOL DISTRIBUTION:")
        text.append(f"  TCP Packets: {stats['tcp']} ({self._percentage(stats['tcp'], stats['total'])}%)")
        text.append(f"  UDP Packets: {stats['udp']} ({self._percentage(stats['udp'], stats['total'])}%)")
        text.append(f"  ICMP Packets: {stats['icmp']} ({self._percentage(stats['icmp'], stats['total'])}%)")
        text.append(f"  ARP Packets: {stats['arp']} ({self._percentage(stats['arp'], stats['total'])}%)")
        text.append("")
        
        return '\n'.join(text)
        
    def analyze_flows(self, packets):
        """Analyze network flows"""
        flows = defaultdict(lambda: {'count': 0, 'bytes': 0, 'protocols': set()})
        
        for packet in packets:
            src = packet.get('source', '')
            dst = packet.get('destination', '')
            if src and dst:
                flow_key = f"{src} <-> {dst}"
                flows[flow_key]['count'] += 1
                flows[flow_key]['bytes'] += packet.get('length', 0)
                flows[flow_key]['protocols'].add(packet.get('protocol', ''))
                
        # Format flow analysis
        text = []
        text.append("=" * 80)
        text.append("NETWORK FLOW ANALYSIS")
        text.append("=" * 80)
        text.append("")
        text.append(f"Total Flows Detected: {len(flows)}")
        text.append("")
        text.append("TOP 10 FLOWS BY PACKET COUNT:")
        text.append("")
        
        sorted_flows = sorted(flows.items(), key=lambda x: x[1]['count'], reverse=True)
        for i, (flow, data) in enumerate(sorted_flows[:10], 1):
            text.append(f"{i}. {flow}")
            text.append(f"   Packets: {data['count']}")
            text.append(f"   Bytes: {data['bytes']}")
            text.append(f"   Protocols: {', '.join(data['protocols'])}")
            text.append("")
            
        return '\n'.join(text)
        
    def _percentage(self, part, total):
        """Calculate percentage"""
        return round((part / total * 100), 2) if total > 0 else 0