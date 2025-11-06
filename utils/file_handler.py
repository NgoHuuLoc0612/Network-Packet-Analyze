"""
File Handler
Support for all capture file formats (pcap, pcapng, cap, etc.)
"""

from scapy.all import rdpcap, wrpcap, PcapReader, PcapWriter
import os

class FileHandler:
    """Enterprise file handler supporting multiple capture formats"""
    
    def __init__(self):
        self.supported_formats = ['.pcap', '.pcapng', '.cap', '.dmp']
        
    def load_file(self, file_path, progress_callback=None):
        """Load capture file and return parsed packets"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")
            
        try:
            # Load packets using scapy
            if progress_callback:
                progress_callback.setRange(0, 100)
                progress_callback.setValue(10)
                
            packets = rdpcap(file_path)
            
            if progress_callback:
                progress_callback.setValue(50)
                
            # Parse packets
            from core.packet_parser import PacketParser
            parser = PacketParser()
            parsed_packets = []
            
            total = len(packets)
            for i, packet in enumerate(packets):
                parsed_packet = parser.parse(packet)
                parsed_packets.append(parsed_packet)
                
                if progress_callback and i % 100 == 0:
                    progress = 50 + int((i / total) * 50)
                    progress_callback.setValue(progress)
                    
            if progress_callback:
                progress_callback.setValue(100)
                
            return parsed_packets
            
        except Exception as e:
            raise Exception(f"Error loading file: {str(e)}")
            
    def save_file(self, file_path, packets):
        """Save packets to capture file"""
        try:
            # Extract raw packets
            raw_packets = [p.get('raw_packet') for p in packets if 'raw_packet' in p]
            
            if not raw_packets:
                raise ValueError("No valid packets to save")
                
            # Determine format from file extension
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext == '.pcapng':
                # Save as pcapng format
                wrpcap(file_path, raw_packets, append=False, nano=True)
            else:
                # Save as pcap format (default)
                wrpcap(file_path, raw_packets, append=False)
                
            return True
            
        except Exception as e:
            raise Exception(f"Error saving file: {str(e)}")
            
    def merge_files(self, input_files, output_file):
        """Merge multiple capture files into one"""
        try:
            all_packets = []
            
            for file_path in input_files:
                packets = rdpcap(file_path)
                all_packets.extend(packets)
                
            # Sort by timestamp if available
            all_packets.sort(key=lambda x: x.time if hasattr(x, 'time') else 0)
            
            # Save merged file
            wrpcap(output_file, all_packets)
            
            return len(all_packets)
            
        except Exception as e:
            raise Exception(f"Error merging files: {str(e)}")
            
    def split_file(self, input_file, output_dir, max_packets_per_file=1000):
        """Split large capture file into smaller files"""
        try:
            packets = rdpcap(input_file)
            total_packets = len(packets)
            file_count = 0
            
            base_name = os.path.splitext(os.path.basename(input_file))[0]
            
            for i in range(0, total_packets, max_packets_per_file):
                chunk = packets[i:i + max_packets_per_file]
                file_count += 1
                output_file = os.path.join(output_dir, f"{base_name}_part{file_count}.pcap")
                wrpcap(output_file, chunk)
                
            return file_count
            
        except Exception as e:
            raise Exception(f"Error splitting file: {str(e)}")
            
    def filter_and_save(self, input_file, output_file, filter_func):
        """Filter packets and save to new file"""
        try:
            packets = rdpcap(input_file)
            filtered_packets = [p for p in packets if filter_func(p)]
            
            if filtered_packets:
                wrpcap(output_file, filtered_packets)
                return len(filtered_packets)
            else:
                return 0
                
        except Exception as e:
            raise Exception(f"Error filtering file: {str(e)}")
            
    def get_file_info(self, file_path):
        """Get information about capture file"""
        try:
            packets = rdpcap(file_path)
            
            info = {
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'packet_count': len(packets),
                'format': os.path.splitext(file_path)[1],
                'first_packet_time': str(packets[0].time) if packets else None,
                'last_packet_time': str(packets[-1].time) if packets else None
            }
            
            return info
            
        except Exception as e:
            raise Exception(f"Error reading file info: {str(e)}")
            
    def validate_file(self, file_path):
        """Validate capture file integrity"""
        try:
            packets = rdpcap(file_path)
            return len(packets) > 0
        except Exception:
            return False