# Network Packet Analyzer v3.0

## 🚀 Overview

Professional-grade network packet analyzer with real-time capture, deep protocol analysis, and advanced visualization capabilities. Built for network security and monitoring.

## ✨ Features

### Core Capabilities
- ⚡ **Real-time Packet Capture** - Live capture across all network interfaces
- 🔍 **Deep Packet Inspection** - Comprehensive protocol analysis
- 📊 **Advanced Visualization** - Multiple chart types and interactive displays
- 💾 **Multi-format Support** - PCAP, PCAPNG, CAP file formats
- 📈 **Live Statistics** - Real-time metrics with auto-refresh
- 🎯 **Protocol Filtering** - Filter by TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, and more

### Protocol Support
- **Transport Layer**: TCP, UDP, SCTP
- **Network Layer**: IPv4, IPv6, ICMP, ICMPv6, ARP
- **Application Layer**: HTTP, HTTPS, DNS, FTP, SSH, SMTP, POP3, IMAP, DHCP
- **Routing Protocols**: BGP, OSPF, RIP, EIGRP
- **Data Link**: Ethernet, VLAN (802.1Q), STP, MPLS
- **And many more...**

### Analysis Features
- Protocol distribution analysis
- Traffic flow identification
- Top talkers detection
- Port scanning detection
- Security anomaly alerts
- Performance metrics
- Bandwidth monitoring

### Export Formats
- 📄 **PDF Reports** - Comprehensive analysis reports
- 📊 **CSV Export** - Spreadsheet-compatible data
- 🔧 **JSON Export** - Structured data for integration
- 🌐 **HTML Reports** - Interactive web-based reports

## 📋 Requirements

- Python 3.8 or higher
- Administrator/Root privileges (for packet capture)
- Network interface card

### System Requirements
- **OS**: Windows 10/11, Linux (Ubuntu 20.04+), macOS 11+
- **RAM**: Minimum 4GB (8GB recommended)
- **CPU**: Multi-core processor recommended
- **Network**: Active network interface

## 🛠️ Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourcompany/packet-analyzer.git
cd packet-analyzer
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Platform-Specific Setup

#### Linux
```bash
# Install libpcap
sudo apt-get install libpcap-dev

# Grant capture permissions (optional, to avoid running as root)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python)
```

#### Windows
```bash
# Install Npcap from: https://npcap.com/#download
# Ensure "WinPcap API-compatible Mode" is enabled during installation
```

#### macOS
```bash
# Install libpcap (usually pre-installed)
brew install libpcap
```

## 🚀 Usage

### Starting the Application
```bash
# Run with administrator/root privileges
sudo python packet_analyzer.py  # Linux/macOS
python packet_analyzer.py       # Windows (run as Administrator)
```

### Basic Operations

#### 1. Start Capture
1. Select network interface from dropdown
2. Choose protocol filter (optional)
3. Click **START CAPTURE**
4. Packets appear in real-time

#### 2. Stop Capture
- Click **STOP CAPTURE** button
- All captured packets remain in table

#### 3. Load Existing Capture
- Click **LOAD FILE**
- Select PCAP/PCAPNG file
- Packets load automatically

#### 4. Save Capture
- Click **SAVE CAPTURE**
- Choose format (PCAP/PCAPNG)
- Specify filename and location

#### 5. Export Analysis
- Click **EXPORT ANALYSIS**
- Choose format: PDF, CSV, JSON, or HTML
- Select save location

#### 6. Visualize Data
- Click **VISUALIZE**
- View multiple charts:
  - Protocol distribution
  - Traffic timeline
  - Top talkers
  - Port analysis
  - Packet size distribution

### Advanced Features

#### Protocol Filtering
Select from dropdown to filter specific protocols:
- ALL (show everything)
- TCP, UDP, ICMP
- HTTP, HTTPS, DNS
- FTP, SSH, SMTP
- BGP, OSPF, RIP
- And more...

#### Packet Analysis
Click any packet in the table to view:
- **Packet Details**: Full layer-by-layer breakdown
- **Hex Dump**: Raw packet data in hexadecimal
- **Protocol Analysis**: Deep protocol inspection
- **Statistics**: Real-time traffic statistics
- **Flow Analysis**: Connection flow information

#### Real-time Monitoring
- Automatic refresh every 100ms
- Live packet counter
- Real-time protocol distribution
- Dynamic bandwidth monitoring
- Packet rate calculation

## 📁 Project Structure

```
packet-analyzer/
├── packet_analyzer.py          # Main application entry point
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── ui/
│   └── main_window.py         # Main window UI implementation
│
├── core/
│   ├── packet_capture.py     # Packet capture engine
│   ├── packet_parser.py      # Packet parsing logic
│   └── protocol_analyzer.py  # Protocol analysis engine
│
├── utils/
│   ├── file_handler.py       # File I/O operations
│   └── export_manager.py     # Export functionality
│
└── visualization/
    └── packet_visualizer.py  # Visualization components
```

## 🔧 Configuration

### Capture Settings
Edit in `core/packet_capture.py`:
```python
# Buffer size for packet capture
CAPTURE_BUFFER_SIZE = 65536

# Capture timeout (milliseconds)
CAPTURE_TIMEOUT = 1000

# Maximum packets in memory
MAX_PACKETS_IN_MEMORY = 100000
```

### UI Settings
Edit in `ui/main_window.py`:
```python
# Auto-refresh interval (milliseconds)
AUTO_REFRESH_INTERVAL = 100

# Maximum table rows before cleanup
MAX_TABLE_ROWS = 10000
```

## 🛡️ Security Considerations

- **Root Privileges**: Required for packet capture
- **Data Privacy**: Captured packets may contain sensitive information
- **Network Impact**: Capturing on busy networks may affect performance
- **Storage**: Large captures can consume significant disk space

## 🐛 Troubleshooting

### Common Issues

#### "Permission Denied" Error
**Solution**: Run with administrator/root privileges
```bash
sudo python packet_analyzer.py
```

#### No Network Interfaces Shown
**Solution**: 
- Ensure Npcap/libpcap is installed
- Check network adapters are enabled
- Restart application with elevated privileges

#### Slow Performance
**Solution**:
- Apply protocol filters to reduce packet load
- Increase AUTO_REFRESH_INTERVAL
- Clear packets periodically using CLEAR ALL

#### Cannot Load PCAP File
**Solution**:
- Verify file format (PCAP/PCAPNG)
- Check file is not corrupted
- Ensure sufficient memory available

## 📊 Performance Tips

1. **Use Protocol Filters**: Reduce overhead by filtering unwanted traffic
2. **Limit Capture Duration**: Stop capture when sufficient data collected
3. **Regular Cleanup**: Use CLEAR ALL to free memory
4. **Export Large Captures**: Save to file rather than keeping in memory
5. **Close Unused Tabs**: Reduce visualization overhead

## 🔄 Updates & Maintenance

### Updating Dependencies
```bash
pip install --upgrade -r requirements.txt
```

## 📚 Additional Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [PyQt6 Documentation](https://www.riverbankcomputing.com/static/Docs/PyQt6/)
- [Network Protocol Reference](https://www.iana.org/protocols)

## ⚠️ Disclaimer

This tool is intended for authorized network analysis and security testing only. Unauthorized interception of network traffic may be illegal in your jurisdiction. Always obtain proper authorization before capturing network traffic.

---

**Built with ❤️ for Network Security Professionals**
