"""
Packet Visualizer
Advanced visualization for network traffic analysis
"""

import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QTabWidget, QWidget)
from PyQt6.QtCore import Qt
from collections import Counter, defaultdict
import numpy as np

class PacketVisualizer(QDialog):
    """Enterprise visualization for packet analysis"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Visualization")
        self.setGeometry(100, 100, 1400, 800)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup visualization UI"""
        layout = QVBoxLayout()
        
        # Tab widget for different visualizations
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_visualizations)
        button_layout.addWidget(refresh_btn)
        
        export_btn = QPushButton("💾 Export Charts")
        export_btn.clicked.connect(self.export_charts)
        button_layout.addWidget(export_btn)
        
        close_btn = QPushButton("✖ Close")
        close_btn.clicked.connect(self.close)
        button_layout.addWidget(close_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        self.apply_styling()
        
    def apply_styling(self):
        """Apply dark futuristic styling"""
        self.setStyleSheet("""
            QDialog {
                background-color: #0a0e27;
                color: #00ff88;
            }
            QPushButton {
                background-color: #1a2550;
                color: #00ff88;
                border: 2px solid #00ff88;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00ff8822;
            }
            QTabWidget::pane {
                border: 2px solid #00ff88;
                background-color: #0f1535;
            }
            QTabBar::tab {
                background-color: #1a2550;
                color: #00ff88;
                border: 2px solid #00ff88;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #00ff8822;
            }
        """)
        
    def show_visualization(self, packets):
        """Show all visualizations"""
        self.packets = packets
        self.create_visualizations()
        self.exec()
        
    def create_visualizations(self):
        """Create all visualization tabs"""
        # Clear existing tabs
        self.tabs.clear()
        
        # Protocol distribution
        protocol_tab = self.create_protocol_distribution()
        self.tabs.addTab(protocol_tab, "📊 Protocol Distribution")
        
        # Traffic timeline
        timeline_tab = self.create_traffic_timeline()
        self.tabs.addTab(timeline_tab, "📈 Traffic Timeline")
        
        # Top talkers
        talkers_tab = self.create_top_talkers()
        self.tabs.addTab(talkers_tab, "💬 Top Talkers")
        
        # Port analysis
        ports_tab = self.create_port_analysis()
        self.tabs.addTab(ports_tab, "🔌 Port Analysis")
        
        # Packet size distribution
        size_tab = self.create_packet_size_distribution()
        self.tabs.addTab(size_tab, "📦 Packet Size Distribution")
        
        # Geographic map (if IP geolocation available)
        geo_tab = self.create_geographic_visualization()
        self.tabs.addTab(geo_tab, "🗺️ Geographic Distribution")
        
    def create_protocol_distribution(self):
        """Create protocol distribution chart"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        fig = Figure(figsize=(12, 6), facecolor='#0a0e27')
        canvas = FigureCanvasQTAgg(fig)
        
        # Count protocols
        protocol_counts = Counter(p.get('protocol', 'OTHER') for p in self.packets)
        
        # Create pie chart
        ax1 = fig.add_subplot(121)
        ax1.set_facecolor('#0f1535')
        
        colors = ['#ff6b6b', '#4ecdc4', '#ffe66d', '#a8dadc', '#95e1d3']
        wedges, texts, autotexts = ax1.pie(
            protocol_counts.values(),
            labels=protocol_counts.keys(),
            autopct='%1.1f%%',
            colors=colors,
            startangle=90
        )
        
        for text in texts:
            text.set_color('#00ff88')
            text.set_fontsize(12)
        for autotext in autotexts:
            autotext.set_color('#0a0e27')
            autotext.set_fontsize(10)
            autotext.set_weight('bold')
            
        ax1.set_title('Protocol Distribution', color='#00ff88', fontsize=14, weight='bold')
        
        # Create bar chart
        ax2 = fig.add_subplot(122)
        ax2.set_facecolor('#0f1535')
        
        protocols = list(protocol_counts.keys())
        counts = list(protocol_counts.values())
        
        bars = ax2.bar(protocols, counts, color=colors[:len(protocols)])
        ax2.set_xlabel('Protocol', color='#00ff88', fontsize=12)
        ax2.set_ylabel('Packet Count', color='#00ff88', fontsize=12)
        ax2.set_title('Protocol Packet Count', color='#00ff88', fontsize=14, weight='bold')
        ax2.tick_params(colors='#00ff88')
        ax2.spines['bottom'].set_color('#00ff88')
        ax2.spines['left'].set_color('#00ff88')
        ax2.spines['top'].set_visible(False)
        ax2.spines['right'].set_visible(False)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}',
                    ha='center', va='bottom', color='#00ff88', fontsize=10)
        
        fig.tight_layout()
        layout.addWidget(canvas)
        widget.setLayout(layout)
        
        return widget
        
    def create_traffic_timeline(self):
        """Create traffic timeline chart"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        fig = Figure(figsize=(12, 6), facecolor='#0a0e27')
        canvas = FigureCanvasQTAgg(fig)
        
        ax = fig.add_subplot(111)
        ax.set_facecolor('#0f1535')
        
        # Group packets by time buckets
        time_buckets = defaultdict(int)
        for packet in self.packets:
            timestamp = packet.get('timestamp', '')
            if timestamp:
                time_key = timestamp[:19]  # Group by second
                time_buckets[time_key] += 1
                
        times = sorted(time_buckets.keys())
        counts = [time_buckets[t] for t in times]
        
        if times and counts:
            # Plot timeline
            ax.plot(range(len(times)), counts, color='#00ff88', linewidth=2, marker='o', markersize=4)
            ax.fill_between(range(len(times)), counts, alpha=0.3, color='#00ff88')
            
            ax.set_xlabel('Time', color='#00ff88', fontsize=12)
            ax.set_ylabel('Packets per Second', color='#00ff88', fontsize=12)
            ax.set_title('Traffic Timeline', color='#00ff88', fontsize=14, weight='bold')
            ax.tick_params(colors='#00ff88')
            ax.spines['bottom'].set_color('#00ff88')
            ax.spines['left'].set_color('#00ff88')
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.grid(True, alpha=0.2, color='#00ff88')
            
            # Set x-axis labels (show every nth label to avoid crowding)
            step = max(1, len(times) // 10)
            ax.set_xticks(range(0, len(times), step))
            ax.set_xticklabels([times[i][-8:] for i in range(0, len(times), step)], rotation=45)
        
        fig.tight_layout()
        layout.addWidget(canvas)
        widget.setLayout(layout)
        
        return widget
        
    def create_top_talkers(self):
        """Create top talkers visualization"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        fig = Figure(figsize=(12, 6), facecolor='#0a0e27')
        canvas = FigureCanvasQTAgg(fig)
        
        # Count source IPs
        src_counts = Counter(p.get('source', 'Unknown') for p in self.packets if p.get('source'))
        top_sources = src_counts.most_common(10)
        
        # Count destination IPs
        dst_counts = Counter(p.get('destination', 'Unknown') for p in self.packets if p.get('destination'))
        top_destinations = dst_counts.most_common(10)
        
        # Create source chart
        ax1 = fig.add_subplot(121)
        ax1.set_facecolor('#0f1535')
        
        if top_sources:
            sources = [s[0][:20] for s in top_sources]
            counts = [s[1] for s in top_sources]
            
            bars = ax1.barh(sources, counts, color='#ff6b6b')
            ax1.set_xlabel('Packet Count', color='#00ff88', fontsize=12)
            ax1.set_title('Top Source IPs', color='#00ff88', fontsize=14, weight='bold')
            ax1.tick_params(colors='#00ff88')
            ax1.spines['bottom'].set_color('#00ff88')
            ax1.spines['left'].set_color('#00ff88')
            ax1.spines['top'].set_visible(False)
            ax1.spines['right'].set_visible(False)
            
        # Create destination chart
        ax2 = fig.add_subplot(122)
        ax2.set_facecolor('#0f1535')
        
        if top_destinations:
            destinations = [d[0][:20] for d in top_destinations]
            counts = [d[1] for d in top_destinations]
            
            bars = ax2.barh(destinations, counts, color='#4ecdc4')
            ax2.set_xlabel('Packet Count', color='#00ff88', fontsize=12)
            ax2.set_title('Top Destination IPs', color='#00ff88', fontsize=14, weight='bold')
            ax2.tick_params(colors='#00ff88')
            ax2.spines['bottom'].set_color('#00ff88')
            ax2.spines['left'].set_color('#00ff88')
            ax2.spines['top'].set_visible(False)
            ax2.spines['right'].set_visible(False)
        
        fig.tight_layout()
        layout.addWidget(canvas)
        widget.setLayout(layout)
        
        return widget
        
    def create_port_analysis(self):
        """Create port analysis visualization"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        fig = Figure(figsize=(12, 6), facecolor='#0a0e27')
        canvas = FigureCanvasQTAgg(fig)
        
        # Collect ports
        src_ports = []
        dst_ports = []
        
        for packet in self.packets:
            if 'tcp_sport' in packet:
                src_ports.append(packet['tcp_sport'])
                dst_ports.append(packet['tcp_dport'])
            elif 'udp_sport' in packet:
                src_ports.append(packet['udp_sport'])
                dst_ports.append(packet['udp_dport'])
                
        # Count ports
        src_port_counts = Counter(src_ports)
        dst_port_counts = Counter(dst_ports)
        
        top_src_ports = src_port_counts.most_common(15)
        top_dst_ports = dst_port_counts.most_common(15)
        
        # Create source ports chart
        ax1 = fig.add_subplot(121)
        ax1.set_facecolor('#0f1535')
        
        if top_src_ports:
            ports = [str(p[0]) for p in top_src_ports]
            counts = [p[1] for p in top_src_ports]
            
            bars = ax1.bar(ports, counts, color='#ffe66d')
            ax1.set_xlabel('Source Port', color='#00ff88', fontsize=12)
            ax1.set_ylabel('Count', color='#00ff88', fontsize=12)
            ax1.set_title('Top Source Ports', color='#00ff88', fontsize=14, weight='bold')
            ax1.tick_params(colors='#00ff88')
            ax1.spines['bottom'].set_color('#00ff88')
            ax1.spines['left'].set_color('#00ff88')
            ax1.spines['top'].set_visible(False)
            ax1.spines['right'].set_visible(False)
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45)
            
        # Create destination ports chart
        ax2 = fig.add_subplot(122)
        ax2.set_facecolor('#0f1535')
        
        if top_dst_ports:
            ports = [str(p[0]) for p in top_dst_ports]
            counts = [p[1] for p in top_dst_ports]
            
            bars = ax2.bar(ports, counts, color='#a8dadc')
            ax2.set_xlabel('Destination Port', color='#00ff88', fontsize=12)
            ax2.set_ylabel('Count', color='#00ff88', fontsize=12)
            ax2.set_title('Top Destination Ports', color='#00ff88', fontsize=14, weight='bold')
            ax2.tick_params(colors='#00ff88')
            ax2.spines['bottom'].set_color('#00ff88')
            ax2.spines['left'].set_color('#00ff88')
            ax2.spines['top'].set_visible(False)
            ax2.spines['right'].set_visible(False)
            plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45)
        
        fig.tight_layout()
        layout.addWidget(canvas)
        widget.setLayout(layout)
        
        return widget
        
    def create_packet_size_distribution(self):
        """Create packet size distribution chart"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        fig = Figure(figsize=(12, 6), facecolor='#0a0e27')
        canvas = FigureCanvasQTAgg(fig)
        
        ax = fig.add_subplot(111)
        ax.set_facecolor('#0f1535')
        
        sizes = [p.get('length', 0) for p in self.packets if p.get('length')]
        
        if sizes:
            # Create histogram
            n, bins, patches = ax.hist(sizes, bins=50, color='#95e1d3', edgecolor='#00ff88', alpha=0.7)
            
            ax.set_xlabel('Packet Size (bytes)', color='#00ff88', fontsize=12)
            ax.set_ylabel('Frequency', color='#00ff88', fontsize=12)
            ax.set_title('Packet Size Distribution', color='#00ff88', fontsize=14, weight='bold')
            ax.tick_params(colors='#00ff88')
            ax.spines['bottom'].set_color('#00ff88')
            ax.spines['left'].set_color('#00ff88')
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.grid(True, alpha=0.2, color='#00ff88', axis='y')
            
            # Add statistics
            mean_size = np.mean(sizes)
            median_size = np.median(sizes)
            ax.axvline(mean_size, color='#ff6b6b', linestyle='--', linewidth=2, label=f'Mean: {mean_size:.0f}')
            ax.axvline(median_size, color='#4ecdc4', linestyle='--', linewidth=2, label=f'Median: {median_size:.0f}')
            ax.legend(facecolor='#1a2550', edgecolor='#00ff88', labelcolor='#00ff88')
        
        fig.tight_layout()
        layout.addWidget(canvas)
        widget.setLayout(layout)
        
        return widget
        
    def create_geographic_visualization(self):
        """Create geographic distribution visualization"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        fig = Figure(figsize=(12, 6), facecolor='#0a0e27')
        canvas = FigureCanvasQTAgg(fig)
        
        ax = fig.add_subplot(111)
        ax.set_facecolor('#0f1535')
        
        # This would integrate with IP geolocation service
        # For now, show placeholder
        ax.text(0.5, 0.5, 'Geographic Visualization\n(Requires IP Geolocation Service)',
               ha='center', va='center', color='#00ff88', fontsize=16,
               transform=ax.transAxes)
        ax.axis('off')
        
        fig.tight_layout()
        layout.addWidget(canvas)
        widget.setLayout(layout)
        
        return widget
        
    def refresh_visualizations(self):
        """Refresh all visualizations"""
        if hasattr(self, 'packets'):
            self.create_visualizations()
            
    def export_charts(self):
        """Export all charts as images"""
        try:
            from PyQt6.QtWidgets import QFileDialog
            directory = QFileDialog.getExistingDirectory(self, "Select Export Directory")
            
            if directory:
                for i in range(self.tabs.count()):
                    tab_name = self.tabs.tabText(i).replace(' ', '_').replace('📊', '').replace('📈', '').replace('💬', '').replace('🔌', '').replace('📦', '').replace('🗺️', '').strip()
                    # Export logic here
                    
        except Exception as e:
            print(f"Export error: {e}")