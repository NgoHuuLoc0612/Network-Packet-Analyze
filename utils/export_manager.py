"""
Export Manager
Export analysis to multiple formats (PDF, CSV, JSON, HTML)
"""

import json
import csv
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

class ExportManager:
    """Enterprise export manager supporting multiple formats"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        
    def export(self, file_path, packets, statistics):
        """Export to specified format based on file extension"""
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext == '.pdf':
            return self.export_to_pdf(file_path, packets, statistics)
        elif file_ext == '.csv':
            return self.export_to_csv(file_path, packets)
        elif file_ext == '.json':
            return self.export_to_json(file_path, packets, statistics)
        elif file_ext == '.html':
            return self.export_to_html(file_path, packets, statistics)
        else:
            raise ValueError(f"Unsupported export format: {file_ext}")
            
    def export_to_pdf(self, file_path, packets, statistics):
        """Export comprehensive PDF report"""
        try:
            doc = SimpleDocTemplate(file_path, pagesize=A4)
            story = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#00ff88'),
                spaceAfter=30,
                alignment=1  # Center
            )
            
            title = Paragraph("Network Packet Analysis Report", title_style)
            story.append(title)
            story.append(Spacer(1, 0.3*inch))
            
            # Report metadata
            metadata = [
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Total Packets Analyzed: {statistics['total']}",
                f"Analysis Duration: N/A"
            ]
            
            for line in metadata:
                story.append(Paragraph(line, self.styles['Normal']))
            
            story.append(Spacer(1, 0.5*inch))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", self.styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            summary_data = [
                ['Metric', 'Value'],
                ['Total Packets', str(statistics['total'])],
                ['TCP Packets', f"{statistics['tcp']} ({self._percentage(statistics['tcp'], statistics['total'])}%)"],
                ['UDP Packets', f"{statistics['udp']} ({self._percentage(statistics['udp'], statistics['total'])}%)"],
                ['ICMP Packets', f"{statistics['icmp']} ({self._percentage(statistics['icmp'], statistics['total'])}%)"],
                ['ARP Packets', f"{statistics['arp']} ({self._percentage(statistics['arp'], statistics['total'])}%)"],
                ['Packet Rate', f"{statistics['rate']} pkt/s"],
                ['Bandwidth', f"{statistics['bandwidth']} KB/s"]
            ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a2550')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00ff88')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#0f1535')),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#00ff88'))
            ]))
            
            story.append(summary_table)
            story.append(PageBreak())
            
            # Detailed Packet List
            story.append(Paragraph("Packet Details (First 50 Packets)", self.styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            packet_data = [['No.', 'Time', 'Source', 'Dest', 'Protocol', 'Length']]
            
            for i, packet in enumerate(packets[:50], 1):
                packet_data.append([
                    str(i),
                    packet.get('timestamp', 'N/A')[-12:],  # Time only
                    packet.get('source', 'N/A')[:20],
                    packet.get('destination', 'N/A')[:20],
                    packet.get('protocol', 'N/A'),
                    str(packet.get('length', 0))
                ])
            
            packet_table = Table(packet_data, colWidths=[0.4*inch, 1*inch, 1.5*inch, 1.5*inch, 0.8*inch, 0.7*inch])
            packet_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a2550')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#00ff88')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#0f1535')),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#00ff88')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#0f1535'), colors.HexColor('#12183a')])
            ]))
            
            story.append(packet_table)
            
            # Build PDF
            doc.build(story)
            return True
            
        except Exception as e:
            raise Exception(f"Error exporting to PDF: {str(e)}")
            
    def export_to_csv(self, file_path, packets):
        """Export packets to CSV format"""
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'No', 'Timestamp', 'Source', 'Destination', 'Protocol',
                    'Length', 'TTL', 'Flags', 'Info'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for i, packet in enumerate(packets, 1):
                    writer.writerow({
                        'No': i,
                        'Timestamp': packet.get('timestamp', ''),
                        'Source': packet.get('source', ''),
                        'Destination': packet.get('destination', ''),
                        'Protocol': packet.get('protocol', ''),
                        'Length': packet.get('length', 0),
                        'TTL': packet.get('ttl', ''),
                        'Flags': packet.get('flags', ''),
                        'Info': packet.get('info', '')
                    })
                    
            return True
            
        except Exception as e:
            raise Exception(f"Error exporting to CSV: {str(e)}")
            
    def export_to_json(self, file_path, packets, statistics):
        """Export complete analysis to JSON format"""
        try:
            export_data = {
                'metadata': {
                    'export_time': datetime.now().isoformat(),
                    'total_packets': len(packets),
                    'format_version': '3.0'
                },
                'statistics': statistics,
                'packets': []
            }
            
            for i, packet in enumerate(packets, 1):
                packet_data = {
                    'number': i,
                    'timestamp': packet.get('timestamp', ''),
                    'source': packet.get('source', ''),
                    'destination': packet.get('destination', ''),
                    'protocol': packet.get('protocol', ''),
                    'length': packet.get('length', 0),
                    'ttl': packet.get('ttl', ''),
                    'flags': packet.get('flags', ''),
                    'info': packet.get('info', ''),
                    'layers': packet.get('layers', [])
                }
                
                # Add protocol-specific fields
                for key, value in packet.items():
                    if key.startswith(('tcp_', 'udp_', 'ip_', 'icmp_', 'arp_', 'dns_')):
                        packet_data[key] = str(value) if not isinstance(value, (int, float, bool)) else value
                        
                export_data['packets'].append(packet_data)
                
            with open(file_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
                
            return True
            
        except Exception as e:
            raise Exception(f"Error exporting to JSON: {str(e)}")
            
    def export_to_html(self, file_path, packets, statistics):
        """Export interactive HTML report"""
        try:
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Packet Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Consolas', 'Monaco', monospace;
            background: linear-gradient(135deg, #0a0e27 0%, #1a2550 100%);
            color: #00ff88;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(15, 21, 53, 0.8);
            border: 2px solid #00ff88;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 0 30px rgba(0, 255, 136, 0.3);
        }}
        
        h1 {{
            text-align: center;
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(0, 255, 136, 0.5);
        }}
        
        .subtitle {{
            text-align: center;
            color: #00ffff;
            margin-bottom: 30px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: #1a2550;
            border: 2px solid #00ff88;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0, 255, 136, 0.3);
        }}
        
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #00ffff;
            font-size: 0.9em;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        th {{
            background: #1a2550;
            color: #00ff88;
            padding: 12px;
            text-align: left;
            border: 1px solid #00ff88;
            font-weight: bold;
        }}
        
        td {{
            padding: 10px;
            border: 1px solid #1a2550;
            background: #0f1535;
        }}
        
        tr:hover {{
            background: rgba(0, 255, 136, 0.1);
        }}
        
        .protocol-tcp {{ color: #ff6b6b; }}
        .protocol-udp {{ color: #4ecdc4; }}
        .protocol-icmp {{ color: #ffe66d; }}
        .protocol-arp {{ color: #a8dadc; }}
        
        .search-box {{
            width: 100%;
            padding: 12px;
            margin-bottom: 20px;
            background: #0f1535;
            border: 2px solid #00ff88;
            border-radius: 5px;
            color: #00ff88;
            font-family: 'Consolas', monospace;
            font-size: 1em;
        }}
        
        .search-box:focus {{
            outline: none;
            box-shadow: 0 0 15px rgba(0, 255, 136, 0.5);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>⚡ Network Packet Analysis Report ⚡</h1>
        <p class="subtitle">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{statistics['total']}</div>
                <div class="stat-label">Total Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{statistics['tcp']}</div>
                <div class="stat-label">TCP Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{statistics['udp']}</div>
                <div class="stat-label">UDP Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{statistics['icmp']}</div>
                <div class="stat-label">ICMP Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{statistics['arp']}</div>
                <div class="stat-label">ARP Packets</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{statistics['rate']}</div>
                <div class="stat-label">Packets/Second</div>
            </div>
        </div>
        
        <h2>📦 Packet Details</h2>
        <input type="text" id="searchBox" class="search-box" placeholder="Search packets (protocol, IP, port...)">
        
        <table id="packetTable">
            <thead>
                <tr>
                    <th>No.</th>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Length</th>
                    <th>Info</th>
                </tr>
            </thead>
            <tbody>
"""
            
            for i, packet in enumerate(packets, 1):
                protocol = packet.get('protocol', 'OTHER')
                protocol_class = f'protocol-{protocol.lower()}'
                
                html_content += f"""
                <tr>
                    <td>{i}</td>
                    <td>{packet.get('timestamp', 'N/A')}</td>
                    <td>{packet.get('source', 'N/A')}</td>
                    <td>{packet.get('destination', 'N/A')}</td>
                    <td class="{protocol_class}">{protocol}</td>
                    <td>{packet.get('length', 0)}</td>
                    <td>{packet.get('info', 'N/A')}</td>
                </tr>
"""
            
            html_content += """
            </tbody>
        </table>
    </div>
    
    <script>
        // Search functionality
        document.getElementById('searchBox').addEventListener('keyup', function() {
            const searchTerm = this.value.toLowerCase();
            const rows = document.querySelectorAll('#packetTable tbody tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        });
    </script>
</body>
</html>
"""
            
            with open(file_path, 'w', encoding='utf-8') as htmlfile:
                htmlfile.write(html_content)
                
            return True
            
        except Exception as e:
            raise Exception(f"Error exporting to HTML: {str(e)}")
            
    def _percentage(self, part, total):
        """Calculate percentage"""
        return round((part / total * 100), 2) if total > 0 else 0