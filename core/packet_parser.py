"""
Packet Parser
Packet parsing for all network protocols
"""

from scapy.all import *
from datetime import datetime
import binascii

class PacketParser:
    """Enterprise-grade packet parser supporting all protocols"""
    
    def __init__(self):
        self.protocol_handlers = {
            'Ether': self._parse_ethernet,
            'IP': self._parse_ip,
            'IPv6': self._parse_ipv6,
            'TCP': self._parse_tcp,
            'UDP': self._parse_udp,
            'ICMP': self._parse_icmp,
            'ARP': self._parse_arp,
            'DNS': self._parse_dns,
            'HTTP': self._parse_http,
            'HTTPS': self._parse_https,
            'FTP': self._parse_ftp,
            'SSH': self._parse_ssh,
            'SMTP': self._parse_smtp,
            'DHCP': self._parse_dhcp,
            'BGP': self._parse_bgp,
            'OSPF': self._parse_ospf,
            'RIP': self._parse_rip,
            'STP': self._parse_stp,
            'VLAN': self._parse_vlan,
            'MPLS': self._parse_mpls
        }
        
    def parse(self, packet):
        """Parse packet and extract all information"""
        parsed = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'raw_packet': packet,
            'length': len(packet),
            'protocol': self._get_protocol(packet),
            'layers': self._get_layers(packet),
            'source': '',
            'destination': '',
            'ttl': '',
            'flags': '',
            'info': '',
            'payload': bytes(packet)
        }
        
        # Parse each layer
        for layer_name, handler in self.protocol_handlers.items():
            if packet.haslayer(layer_name):
                layer_data = handler(packet)
                parsed.update(layer_data)
                
        # Extract common fields
        if packet.haslayer(IP):
            parsed['source'] = packet[IP].src
            parsed['destination'] = packet[IP].dst
            parsed['ttl'] = packet[IP].ttl
        elif packet.haslayer(IPv6):
            parsed['source'] = packet[IPv6].src
            parsed['destination'] = packet[IPv6].dst
            parsed['ttl'] = packet[IPv6].hlim
        elif packet.haslayer(ARP):
            parsed['source'] = packet[ARP].psrc
            parsed['destination'] = packet[ARP].pdst
            
        return parsed
        
    def _get_protocol(self, packet):
        """Determine primary protocol"""
        if packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            return 'UDP'
        elif packet.haslayer(ICMP):
            return 'ICMP'
        elif packet.haslayer(ARP):
            return 'ARP'
        elif packet.haslayer(IPv6):
            return 'IPv6'
        elif packet.haslayer(IP):
            return 'IP'
        else:
            return 'OTHER'
            
    def _get_layers(self, packet):
        """Get all protocol layers in packet"""
        layers = []
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            layers.append(layer.name)
            counter += 1
        return layers
        
    def _parse_ethernet(self, packet):
        """Parse Ethernet layer"""
        eth = packet[Ether]
        return {
            'eth_src': eth.src,
            'eth_dst': eth.dst,
            'eth_type': hex(eth.type)
        }
        
    def _parse_ip(self, packet):
        """Parse IP layer"""
        ip = packet[IP]
        return {
            'ip_version': ip.version,
            'ip_ihl': ip.ihl,
            'ip_tos': ip.tos,
            'ip_len': ip.len,
            'ip_id': ip.id,
            'ip_flags': str(ip.flags),
            'ip_frag': ip.frag,
            'ip_ttl': ip.ttl,
            'ip_proto': ip.proto,
            'ip_chksum': hex(ip.chksum),
            'ip_src': ip.src,
            'ip_dst': ip.dst
        }
        
    def _parse_ipv6(self, packet):
        """Parse IPv6 layer"""
        ipv6 = packet[IPv6]
        return {
            'ipv6_version': ipv6.version,
            'ipv6_tc': ipv6.tc,
            'ipv6_fl': ipv6.fl,
            'ipv6_plen': ipv6.plen,
            'ipv6_nh': ipv6.nh,
            'ipv6_hlim': ipv6.hlim,
            'ipv6_src': ipv6.src,
            'ipv6_dst': ipv6.dst
        }
        
    def _parse_tcp(self, packet):
        """Parse TCP layer"""
        tcp = packet[TCP]
        flags = []
        if tcp.flags.F: flags.append('FIN')
        if tcp.flags.S: flags.append('SYN')
        if tcp.flags.R: flags.append('RST')
        if tcp.flags.P: flags.append('PSH')
        if tcp.flags.A: flags.append('ACK')
        if tcp.flags.U: flags.append('URG')
        
        return {
            'tcp_sport': tcp.sport,
            'tcp_dport': tcp.dport,
            'tcp_seq': tcp.seq,
            'tcp_ack': tcp.ack,
            'tcp_dataofs': tcp.dataofs,
            'tcp_flags': ','.join(flags),
            'flags': ','.join(flags),
            'tcp_window': tcp.window,
            'tcp_chksum': hex(tcp.chksum),
            'tcp_urgptr': tcp.urgptr,
            'info': f'{tcp.sport} → {tcp.dport} [{",".join(flags)}]'
        }
        
    def _parse_udp(self, packet):
        """Parse UDP layer"""
        udp = packet[UDP]
        return {
            'udp_sport': udp.sport,
            'udp_dport': udp.dport,
            'udp_len': udp.len,
            'udp_chksum': hex(udp.chksum),
            'info': f'{udp.sport} → {udp.dport}'
        }
        
    def _parse_icmp(self, packet):
        """Parse ICMP layer"""
        icmp = packet[ICMP]
        return {
            'icmp_type': icmp.type,
            'icmp_code': icmp.code,
            'icmp_chksum': hex(icmp.chksum),
            'icmp_id': icmp.id if hasattr(icmp, 'id') else 0,
            'icmp_seq': icmp.seq if hasattr(icmp, 'seq') else 0,
            'info': f'Type {icmp.type} Code {icmp.code}'
        }
        
    def _parse_arp(self, packet):
        """Parse ARP layer"""
        arp = packet[ARP]
        op_name = {1: 'request', 2: 'reply'}.get(arp.op, 'unknown')
        return {
            'arp_hwtype': arp.hwtype,
            'arp_ptype': hex(arp.ptype),
            'arp_hwlen': arp.hwlen,
            'arp_plen': arp.plen,
            'arp_op': arp.op,
            'arp_hwsrc': arp.hwsrc,
            'arp_psrc': arp.psrc,
            'arp_hwdst': arp.hwdst,
            'arp_pdst': arp.pdst,
            'info': f'Who has {arp.pdst}? Tell {arp.psrc}' if arp.op == 1 
                    else f'{arp.psrc} is at {arp.hwsrc}'
        }
        
    def _parse_dns(self, packet):
        """Parse DNS layer"""
        if packet.haslayer(DNS):
            dns = packet[DNS]
            return {
                'dns_id': dns.id,
                'dns_qr': dns.qr,
                'dns_opcode': dns.opcode,
                'dns_aa': dns.aa,
                'dns_tc': dns.tc,
                'dns_rd': dns.rd,
                'dns_ra': dns.ra,
                'dns_z': dns.z,
                'dns_rcode': dns.rcode,
                'dns_qdcount': dns.qdcount,
                'dns_ancount': dns.ancount,
                'dns_nscount': dns.nscount,
                'dns_arcount': dns.arcount,
                'info': f'DNS Query/Response ID: {dns.id}'
            }
        return {}
        
    def _parse_http(self, packet):
        """Parse HTTP layer"""
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if payload.startswith('GET') or payload.startswith('POST') or payload.startswith('HTTP'):
                return {'http_payload': payload[:200], 'info': 'HTTP Traffic'}
        return {}
        
    def _parse_https(self, packet):
        """Parse HTTPS/TLS layer"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
            return {'info': 'HTTPS/TLS Traffic'}
        return {}
        
    def _parse_ftp(self, packet):
        """Parse FTP layer"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 21 or packet[TCP].sport == 21):
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                return {'ftp_payload': payload, 'info': 'FTP Traffic'}
        return {}
        
    def _parse_ssh(self, packet):
        """Parse SSH layer"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 22 or packet[TCP].sport == 22):
            return {'info': 'SSH Traffic'}
        return {}
        
    def _parse_smtp(self, packet):
        """Parse SMTP layer"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 25 or packet[TCP].sport == 25):
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                return {'smtp_payload': payload, 'info': 'SMTP Traffic'}
        return {}
        
    def _parse_dhcp(self, packet):
        """Parse DHCP layer"""
        if packet.haslayer(DHCP):
            return {'info': 'DHCP Traffic'}
        return {}
        
    def _parse_bgp(self, packet):
        """Parse BGP layer"""
        if packet.haslayer(TCP) and (packet[TCP].dport == 179 or packet[TCP].sport == 179):
            return {'info': 'BGP Traffic'}
        return {}
        
    def _parse_ospf(self, packet):
        """Parse OSPF layer"""
        if packet.haslayer(IP) and packet[IP].proto == 89:
            return {'info': 'OSPF Traffic'}
        return {}
        
    def _parse_rip(self, packet):
        """Parse RIP layer"""
        if packet.haslayer(UDP) and packet[UDP].dport == 520:
            return {'info': 'RIP Traffic'}
        return {}
        
    def _parse_stp(self, packet):
        """Parse STP layer"""
        if packet.haslayer(Ether) and packet[Ether].dst == '01:80:c2:00:00:00':
            return {'info': 'STP/RSTP Traffic'}
        return {}
        
    def _parse_vlan(self, packet):
        """Parse VLAN layer"""
        if packet.haslayer(Dot1Q):
            vlan = packet[Dot1Q]
            return {
                'vlan_prio': vlan.prio,
                'vlan_id': vlan.vlan,
                'vlan_type': hex(vlan.type),
                'info': f'VLAN {vlan.vlan}'
            }
        return {}
        
    def _parse_mpls(self, packet):
        """Parse MPLS layer"""
        if packet.haslayer(MPLS):
            mpls = packet[MPLS]
            return {
                'mpls_label': mpls.label,
                'mpls_cos': mpls.cos,
                'mpls_s': mpls.s,
                'mpls_ttl': mpls.ttl,
                'info': f'MPLS Label {mpls.label}'
            }
        return {}
        
    def format_details(self, packet):
        """Format packet details for display"""
        details = []
        details.append("=" * 80)
        details.append(f"PACKET DETAILS - {packet.get('timestamp', 'N/A')}")
        details.append("=" * 80)
        details.append(f"\nLength: {packet.get('length', 0)} bytes")
        details.append(f"Protocol: {packet.get('protocol', 'UNKNOWN')}")
        details.append(f"Layers: {' > '.join(packet.get('layers', []))}")
        details.append("")
        
        # Ethernet Layer
        if 'eth_src' in packet:
            details.append("ETHERNET LAYER:")
            details.append(f"  Source MAC: {packet.get('eth_src', 'N/A')}")
            details.append(f"  Destination MAC: {packet.get('eth_dst', 'N/A')}")
            details.append(f"  Type: {packet.get('eth_type', 'N/A')}")
            details.append("")
            
        # IP Layer
        if 'ip_src' in packet:
            details.append("IP LAYER:")
            details.append(f"  Version: {packet.get('ip_version', 'N/A')}")
            details.append(f"  Source IP: {packet.get('ip_src', 'N/A')}")
            details.append(f"  Destination IP: {packet.get('ip_dst', 'N/A')}")
            details.append(f"  TTL: {packet.get('ip_ttl', 'N/A')}")
            details.append(f"  Protocol: {packet.get('ip_proto', 'N/A')}")
            details.append(f"  Flags: {packet.get('ip_flags', 'N/A')}")
            details.append("")
            
        # TCP Layer
        if 'tcp_sport' in packet:
            details.append("TCP LAYER:")
            details.append(f"  Source Port: {packet.get('tcp_sport', 'N/A')}")
            details.append(f"  Destination Port: {packet.get('tcp_dport', 'N/A')}")
            details.append(f"  Sequence Number: {packet.get('tcp_seq', 'N/A')}")
            details.append(f"  Acknowledgment: {packet.get('tcp_ack', 'N/A')}")
            details.append(f"  Flags: {packet.get('tcp_flags', 'N/A')}")
            details.append(f"  Window Size: {packet.get('tcp_window', 'N/A')}")
            details.append("")
            
        # UDP Layer
        if 'udp_sport' in packet:
            details.append("UDP LAYER:")
            details.append(f"  Source Port: {packet.get('udp_sport', 'N/A')}")
            details.append(f"  Destination Port: {packet.get('udp_dport', 'N/A')}")
            details.append(f"  Length: {packet.get('udp_len', 'N/A')}")
            details.append("")
            
        return '\n'.join(details)
        
    def format_hex_dump(self, packet):
        """Format packet as hex dump"""
        if 'payload' not in packet:
            return "No payload data available"
            
        payload = packet['payload']
        hex_dump = []
        hex_dump.append("=" * 80)
        hex_dump.append("HEX DUMP")
        hex_dump.append("=" * 80)
        hex_dump.append("")
        
        for i in range(0, len(payload), 16):
            hex_part = ' '.join(f'{b:02x}' for b in payload[i:i+16])
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload[i:i+16])
            hex_dump.append(f'{i:08x}  {hex_part:<48}  {ascii_part}')
            
        return '\n'.join(hex_dump)