"""
Main Window UI Implementation
Enterprise-grade interface with real-time packet capture and analysis
"""

from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QTableWidget, QTableWidgetItem, QComboBox,
                             QLabel, QTabWidget, QTextEdit, QFileDialog, QLineEdit,
                             QSplitter, QHeaderView, QProgressBar, QMessageBox)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from core.packet_capture import PacketCaptureEngine
from core.packet_parser import PacketParser
from core.protocol_analyzer import ProtocolAnalyzer
from visualization.packet_visualizer import PacketVisualizer
from utils.file_handler import FileHandler
from utils.export_manager import ExportManager
import datetime

class MainWindow(QMainWindow):
    """Main application window with futuristic UI"""
    
    packet_received = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.capture_engine = PacketCaptureEngine()
        self.packet_parser = PacketParser()
        self.protocol_analyzer = ProtocolAnalyzer()
        self.file_handler = FileHandler()
        self.export_manager = ExportManager()
        self.visualizer = PacketVisualizer()
        
        self.captured_packets = []
        self.is_capturing = False
        self.packet_count = 0
        
        self.init_ui()
        self.setup_auto_refresh()
        self.connect_signals()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Enterprise Network Packet Analyzer v3.0")
        self.setGeometry(100, 100, 1600, 900)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Top control panel
        control_panel = self.create_control_panel()
        main_layout.addLayout(control_panel)
        
        # Statistics bar
        stats_bar = self.create_statistics_bar()
        main_layout.addLayout(stats_bar)
        
        # Main content splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Packet table
        self.packet_table = self.create_packet_table()
        splitter.addWidget(self.packet_table)
        
        # Tabbed detail panel
        self.detail_tabs = self.create_detail_tabs()
        splitter.addWidget(self.detail_tabs)
        
        splitter.setSizes([500, 300])
        main_layout.addWidget(splitter)
        
        # Bottom status bar
        self.status_bar = self.create_status_bar()
        main_layout.addLayout(self.status_bar)
        
    def create_control_panel(self):
        """Create top control panel with capture controls"""
        layout = QHBoxLayout()
        
        # Interface selection
        layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.load_network_interfaces()
        layout.addWidget(self.interface_combo)
        
        # Protocol filter
        layout.addWidget(QLabel("Protocol Filter:"))
        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems([
            "ALL", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS",
            "FTP", "SSH", "TELNET", "SMTP", "POP3", "IMAP", "DHCP", 
            "BGP", "OSPF", "RIP", "EIGRP", "STP", "VLAN", "MPLS"
        ])
        self.protocol_filter.currentTextChanged.connect(self.apply_filter)
        layout.addWidget(self.protocol_filter)
        
        # Capture controls
        self.start_btn = QPushButton("⬤ START CAPTURE")
        self.start_btn.clicked.connect(self.start_capture)
        layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⬛ STOP CAPTURE")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        layout.addWidget(self.stop_btn)
        
        # File operations
        self.load_btn = QPushButton("📁 LOAD FILE")
        self.load_btn.clicked.connect(self.load_capture_file)
        layout.addWidget(self.load_btn)
        
        self.save_btn = QPushButton("💾 SAVE CAPTURE")
        self.save_btn.clicked.connect(self.save_capture)
        layout.addWidget(self.save_btn)
        
        self.export_btn = QPushButton("📊 EXPORT ANALYSIS")
        self.export_btn.clicked.connect(self.export_analysis)
        layout.addWidget(self.export_btn)
        
        # Visualization
        self.viz_btn = QPushButton("📈 VISUALIZE")
        self.viz_btn.clicked.connect(self.show_visualization)
        layout.addWidget(self.viz_btn)
        
        # Clear button
        self.clear_btn = QPushButton("🗑️ CLEAR ALL")
        self.clear_btn.clicked.connect(self.clear_all)
        layout.addWidget(self.clear_btn)
        
        layout.addStretch()
        
        return layout
        
    def create_statistics_bar(self):
        """Create statistics display bar"""
        layout = QHBoxLayout()
        
        self.total_packets_label = QLabel("Total Packets: 0")
        layout.addWidget(self.total_packets_label)
        
        self.tcp_count_label = QLabel("TCP: 0")
        layout.addWidget(self.tcp_count_label)
        
        self.udp_count_label = QLabel("UDP: 0")
        layout.addWidget(self.udp_count_label)
        
        self.icmp_count_label = QLabel("ICMP: 0")
        layout.addWidget(self.icmp_count_label)
        
        self.arp_count_label = QLabel("ARP: 0")
        layout.addWidget(self.arp_count_label)
        
        self.data_rate_label = QLabel("Rate: 0 pkt/s")
        layout.addWidget(self.data_rate_label)
        
        self.bandwidth_label = QLabel("Bandwidth: 0 KB/s")
        layout.addWidget(self.bandwidth_label)
        
        layout.addStretch()
        
        return layout
        
    def create_packet_table(self):
        """Create packet display table"""
        table = QTableWidget()
        table.setColumnCount(9)
        table.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", 
            "Length", "TTL", "Flags", "Info"
        ])
        
        # Configure table appearance
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        
        # Set column widths
        table.setColumnWidth(0, 60)
        table.setColumnWidth(1, 120)
        table.setColumnWidth(2, 150)
        table.setColumnWidth(3, 150)
        table.setColumnWidth(4, 100)
        table.setColumnWidth(5, 80)
        table.setColumnWidth(6, 60)
        table.setColumnWidth(7, 80)
        
        table.itemSelectionChanged.connect(self.on_packet_selected)
        
        return table
        
    def create_detail_tabs(self):
        """Create tabbed detail panel"""
        tabs = QTabWidget()
        
        # Packet details tab
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        self.packet_details.setFont(QFont("Consolas", 10))
        tabs.addTab(self.packet_details, "📦 Packet Details")
        
        # Hex dump tab
        self.hex_dump = QTextEdit()
        self.hex_dump.setReadOnly(True)
        self.hex_dump.setFont(QFont("Consolas", 10))
        tabs.addTab(self.hex_dump, "🔢 Hex Dump")
        
        # Protocol analysis tab
        self.protocol_analysis = QTextEdit()
        self.protocol_analysis.setReadOnly(True)
        self.protocol_analysis.setFont(QFont("Consolas", 10))
        tabs.addTab(self.protocol_analysis, "🔍 Protocol Analysis")
        
        # Statistics tab
        self.statistics_view = QTextEdit()
        self.statistics_view.setReadOnly(True)
        self.statistics_view.setFont(QFont("Consolas", 10))
        tabs.addTab(self.statistics_view, "📊 Statistics")
        
        # Flow analysis tab
        self.flow_analysis = QTextEdit()
        self.flow_analysis.setReadOnly(True)
        self.flow_analysis.setFont(QFont("Consolas", 10))
        tabs.addTab(self.flow_analysis, "🌊 Flow Analysis")
        
        return tabs
        
    def create_status_bar(self):
        """Create bottom status bar"""
        layout = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        layout.addStretch()
        
        return layout
        
    def load_network_interfaces(self):
        """Load available network interfaces"""
        interfaces = self.capture_engine.get_interfaces()
        self.interface_combo.addItems(interfaces)
        
    def setup_auto_refresh(self):
        """Setup automatic refresh timer"""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.update_display)
        self.refresh_timer.start(100)  # Update every 100ms for real-time feel
        
    def connect_signals(self):
        """Connect packet capture signals"""
        self.capture_engine.packet_captured.connect(self.on_packet_captured)
        self.packet_received.connect(self.add_packet_to_table)
        
    def start_capture(self):
        """Start packet capture"""
        interface = self.interface_combo.currentText()
        if not interface:
            QMessageBox.warning(self, "Warning", "Please select a network interface")
            return
            
        self.is_capturing = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText(f"Capturing on {interface}...")
        
        self.capture_engine.start_capture(interface)
        
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Capture stopped")
        
        self.capture_engine.stop_capture()
        
    def on_packet_captured(self, packet_data):
        """Handle captured packet"""
        parsed_packet = self.packet_parser.parse(packet_data)
        self.captured_packets.append(parsed_packet)
        self.packet_count += 1
        self.packet_received.emit(parsed_packet)
        
    def add_packet_to_table(self, packet):
        """Add packet to display table"""
        if not self.should_display_packet(packet):
            return
            
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(self.packet_count)))
        self.packet_table.setItem(row, 1, QTableWidgetItem(packet.get('timestamp', '')))
        self.packet_table.setItem(row, 2, QTableWidgetItem(packet.get('source', '')))
        self.packet_table.setItem(row, 3, QTableWidgetItem(packet.get('destination', '')))
        self.packet_table.setItem(row, 4, QTableWidgetItem(packet.get('protocol', '')))
        self.packet_table.setItem(row, 5, QTableWidgetItem(str(packet.get('length', 0))))
        self.packet_table.setItem(row, 6, QTableWidgetItem(str(packet.get('ttl', ''))))
        self.packet_table.setItem(row, 7, QTableWidgetItem(packet.get('flags', '')))
        self.packet_table.setItem(row, 8, QTableWidgetItem(packet.get('info', '')))
        
        self.packet_table.scrollToBottom()
        
    def should_display_packet(self, packet):
        """Check if packet should be displayed based on filter"""
        filter_protocol = self.protocol_filter.currentText()
        if filter_protocol == "ALL":
            return True
        return packet.get('protocol', '').upper() == filter_protocol
        
    def apply_filter(self):
        """Apply protocol filter to display"""
        self.packet_table.setRowCount(0)
        for packet in self.captured_packets:
            if self.should_display_packet(packet):
                self.packet_received.emit(packet)
                
    def on_packet_selected(self):
        """Handle packet selection"""
        selected_items = self.packet_table.selectedItems()
        if not selected_items:
            return
            
        row = selected_items[0].row()
        if row < len(self.captured_packets):
            packet = self.captured_packets[row]
            self.display_packet_details(packet)
            
    def display_packet_details(self, packet):
        """Display detailed packet information"""
        # Packet details
        details = self.packet_parser.format_details(packet)
        self.packet_details.setText(details)
        
        # Hex dump
        hex_data = self.packet_parser.format_hex_dump(packet)
        self.hex_dump.setText(hex_data)
        
        # Protocol analysis
        analysis = self.protocol_analyzer.analyze(packet)
        self.protocol_analysis.setText(analysis)
        
    def update_display(self):
        """Update display statistics in real-time"""
        stats = self.protocol_analyzer.get_statistics(self.captured_packets)
        
        self.total_packets_label.setText(f"Total Packets: {stats['total']}")
        self.tcp_count_label.setText(f"TCP: {stats['tcp']}")
        self.udp_count_label.setText(f"UDP: {stats['udp']}")
        self.icmp_count_label.setText(f"ICMP: {stats['icmp']}")
        self.arp_count_label.setText(f"ARP: {stats['arp']}")
        self.data_rate_label.setText(f"Rate: {stats['rate']} pkt/s")
        self.bandwidth_label.setText(f"Bandwidth: {stats['bandwidth']} KB/s")
        
        # Update statistics view
        stats_text = self.protocol_analyzer.format_statistics(stats)
        self.statistics_view.setText(stats_text)
        
        # Update flow analysis
        flow_text = self.protocol_analyzer.analyze_flows(self.captured_packets)
        self.flow_analysis.setText(flow_text)
        
    def load_capture_file(self):
        """Load capture file (pcap/pcapng)"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Capture File",
            "",
            "Capture Files (*.pcap *.pcapng *.cap);;All Files (*.*)"
        )
        
        if file_path:
            self.progress_bar.setVisible(True)
            self.status_label.setText("Loading capture file...")
            
            packets = self.file_handler.load_file(file_path, self.progress_bar)
            
            self.captured_packets = packets
            self.packet_table.setRowCount(0)
            self.packet_count = 0
            
            for packet in packets:
                self.packet_count += 1
                self.add_packet_to_table(packet)
                
            self.progress_bar.setVisible(False)
            self.status_label.setText(f"Loaded {len(packets)} packets from {file_path}")
            
    def save_capture(self):
        """Save captured packets to file"""
        if not self.captured_packets:
            QMessageBox.warning(self, "Warning", "No packets to save")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Capture File",
            "",
            "PCAP Files (*.pcap);;PCAPNG Files (*.pcapng)"
        )
        
        if file_path:
            self.file_handler.save_file(file_path, self.captured_packets)
            self.status_label.setText(f"Saved {len(self.captured_packets)} packets to {file_path}")
            
    def export_analysis(self):
        """Export analysis to various formats"""
        if not self.captured_packets:
            QMessageBox.warning(self, "Warning", "No packets to export")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis",
            "",
            "PDF Report (*.pdf);;CSV File (*.csv);;JSON File (*.json);;HTML Report (*.html)"
        )
        
        if file_path:
            stats = self.protocol_analyzer.get_statistics(self.captured_packets)
            self.export_manager.export(file_path, self.captured_packets, stats)
            self.status_label.setText(f"Exported analysis to {file_path}")
            
    def show_visualization(self):
        """Show visualization window"""
        if not self.captured_packets:
            QMessageBox.warning(self, "Warning", "No packets to visualize")
            return
            
        self.visualizer.show_visualization(self.captured_packets)
        
    def clear_all(self):
        """Clear all captured packets"""
        reply = QMessageBox.question(
            self,
            "Confirm Clear",
            "Are you sure you want to clear all captured packets?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.captured_packets.clear()
            self.packet_table.setRowCount(0)
            self.packet_count = 0
            self.packet_details.clear()
            self.hex_dump.clear()
            self.protocol_analysis.clear()
            self.status_label.setText("All packets cleared")