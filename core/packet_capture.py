"""
Packet Capture Engine
Real-time packet capture across all network protocols
"""

from scapy.all import sniff, get_if_list, AsyncSniffer
from PyQt6.QtCore import QObject, pyqtSignal, QThread
import time

class PacketCaptureEngine(QObject):
    """Enterprise packet capture engine with real-time capabilities"""
    
    packet_captured = pyqtSignal(object)
    
    def __init__(self):
        super().__init__()
        self.sniffer = None
        self.is_running = False
        self.interface = None
        self.packet_count = 0
        self.start_time = None
        
    def get_interfaces(self):
        """Get list of available network interfaces"""
        try:
            interfaces = get_if_list()
            return interfaces if interfaces else ["No interfaces found"]
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return ["Error loading interfaces"]
            
    def start_capture(self, interface, packet_filter=None):
        """Start capturing packets on specified interface"""
        self.interface = interface
        self.is_running = True
        self.packet_count = 0
        self.start_time = time.time()
        
        try:
            # Start async sniffer for non-blocking capture
            # On Windows, use None for default interface if interface name doesn't work
            iface_to_use = None if interface == "No interfaces found" else interface
            
            self.sniffer = AsyncSniffer(
                iface=iface_to_use,
                prn=self._packet_handler,
                store=False,
                filter=packet_filter,
                count=0  # Capture indefinitely
            )
            self.sniffer.start()
            print(f"Started capture on interface: {interface}")
            
        except Exception as e:
            print(f"Error starting capture: {e}")
            import traceback
            traceback.print_exc()
            self.is_running = False
            
    def stop_capture(self):
        """Stop packet capture"""
        self.is_running = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                print(f"Error stopping capture: {e}")
            finally:
                self.sniffer = None
                
    def _packet_handler(self, packet):
        """Handle captured packet"""
        if not self.is_running:
            return
            
        self.packet_count += 1
        self.packet_captured.emit(packet)
        
    def get_capture_stats(self):
        """Get capture statistics"""
        if not self.start_time:
            return {
                'packet_count': 0,
                'duration': 0,
                'packets_per_second': 0
            }
            
        duration = time.time() - self.start_time
        pps = self.packet_count / duration if duration > 0 else 0
        
        return {
            'packet_count': self.packet_count,
            'duration': duration,
            'packets_per_second': pps
        }


class CaptureThread(QThread):
    """Dedicated thread for packet capture to prevent UI blocking"""
    
    packet_captured = pyqtSignal(object)
    
    def __init__(self, interface, packet_filter=None):
        super().__init__()
        self.interface = interface
        self.packet_filter = packet_filter
        self.is_running = False
        
    def run(self):
        """Run capture thread"""
        self.is_running = True
        try:
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                filter=self.packet_filter,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            print(f"Capture thread error: {e}")
            
    def _handle_packet(self, packet):
        """Handle captured packet in thread"""
        if self.is_running:
            self.packet_captured.emit(packet)
            
    def stop(self):
        """Stop capture thread"""
        self.is_running = False
        self.quit()
        self.wait()