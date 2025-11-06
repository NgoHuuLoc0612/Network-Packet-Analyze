"""
Test script to verify packet capture is working
Run this first to test if Scapy can capture packets
"""

from scapy.all import sniff, get_if_list, conf
import sys

def packet_callback(packet):
    """Called for each packet"""
    print(f"✓ Packet captured: {packet.summary()}")

def main():
    print("=" * 80)
    print("NETWORK PACKET CAPTURE TEST")
    print("=" * 80)
    print()
    
    # Show available interfaces
    print("Available Network Interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    print()
    
    # Show default interface
    print(f"Default Interface: {conf.iface}")
    print()
    
    # Try to capture packets
    print("Starting packet capture test (capturing 10 packets)...")
    print("Generate some network traffic (open a website, ping something)...")
    print()
    
    try:
        # Capture 10 packets on default interface
        packets = sniff(count=10, prn=packet_callback, timeout=30)
        
        print()
        print(f"Successfully captured {len(packets)} packets!")
        print()
        
        if len(packets) > 0:
            print("Sample packet details:")
            print(packets[0].show())
        else:
            print("⚠ No packets captured. This might indicate:")
            print("  1. No network activity")
            print("  2. Need to run as Administrator/root")
            print("  3. Firewall blocking packet capture")
            print("  4. Npcap not installed properly (Windows)")
            
    except PermissionError:
        print("❌ ERROR: Permission denied!")
        print()
        print("Solutions:")
        print("  Windows: Run Command Prompt as Administrator")
        print("  Linux/Mac: Run with sudo (sudo python test_capture.py)")
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        print()
        print("Possible issues:")
        print("  1. Npcap not installed (Windows): https://npcap.com/#download")
        print("  2. libpcap not installed (Linux): sudo apt-get install libpcap-dev")
        print("  3. No active network interface")
        
if __name__ == '__main__':
    main()