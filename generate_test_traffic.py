#!/usr/bin/env python3
"""
Script pour générer des paquets de test pour l'analyseur réseau
Crée différents types de paquets : IPv4, IPv6, TCP, UDP, ARP, DHCP
"""

import socket
import struct
import time
import os

def create_ethernet_header(dst_mac, src_mac, eth_type):
    """Crée un header Ethernet"""
    return struct.pack('!6s6sH', 
                       dst_mac, src_mac, eth_type)

def create_arp_packet():
    """Crée un paquet ARP de test"""
    # Ethernet header
    dst_mac = b'\xff\xff\xff\xff\xff\xff'  # broadcast
    src_mac = b'\x00\x11\x22\x33\x44\x55'  # MAC source
    eth_header = create_ethernet_header(dst_mac, src_mac, 0x0806)  # ARP
    
    # ARP packet
    arp_data = struct.pack('!HHBBH6s4s6s4s',
                           0x0001,  # Hardware type (Ethernet)
                           0x0800,  # Protocol type (IPv4)
                           6,       # Hardware address length
                           4,       # Protocol address length
                           0x0001,  # Operation (ARP request)
                           b'\x00\x11\x22\x33\x44\x55',  # Sender MAC
                           socket.inet_aton('192.168.1.1'),  # Sender IP
                           b'\x00\x00\x00\x00\x00\x00',  # Target MAC
                           socket.inet_aton('192.168.1.100'))  # Target IP
    
    return eth_header + arp_data

def create_udp_packet():
    """Crée un paquet IPv4/UDP de test"""
    # Ethernet header
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    src_mac = b'\x00\x11\x22\x33\x44\x55'
    eth_header = create_ethernet_header(dst_mac, src_mac, 0x0800)  # IPv4
    
    # IP header
    version_ihl = 0x45  # Version 4, IHL 5
    tos = 0
    total_len = 60  # 20 IP + 8 UDP + 32 data
    packet_id = 12345
    flags_frag = 0
    ttl = 64
    protocol = 17  # UDP
    checksum = 0
    src_ip = socket.inet_aton('192.168.1.10')
    dst_ip = socket.inet_aton('192.168.1.20')
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            version_ihl, tos, total_len, packet_id,
                            flags_frag, ttl, protocol, checksum,
                            src_ip, dst_ip)
    
    # UDP header
    src_port = 54321
    dst_port = 53  # DNS
    udp_len = 40  # 8 header + 32 data
    udp_checksum = 0
    
    udp_header = struct.pack('!HHHH',
                             src_port, dst_port, udp_len, udp_checksum)
    
    # UDP data
    udp_data = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
    
    return eth_header + ip_header + udp_header + udp_data

def create_tcp_packet():
    """Crée un paquet IPv4/TCP de test"""
    # Ethernet header
    dst_mac = b'\xff\xff\xff\xff\xff\xff'
    src_mac = b'\x00\x11\x22\x33\x44\x55'
    eth_header = create_ethernet_header(dst_mac, src_mac, 0x0800)  # IPv4
    
    # IP header
    version_ihl = 0x45
    tos = 0
    total_len = 60  # 20 IP + 40 TCP
    packet_id = 12346
    flags_frag = 0
    ttl = 64
    protocol = 6  # TCP
    checksum = 0
    src_ip = socket.inet_aton('192.168.1.10')
    dst_ip = socket.inet_aton('192.168.1.20')
    
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            version_ihl, tos, total_len, packet_id,
                            flags_frag, ttl, protocol, checksum,
                            src_ip, dst_ip)
    
    # TCP header
    src_port = 49152
    dst_port = 80  # HTTP
    seq_num = 0
    ack_num = 0
    data_offset = 5 << 4  # 5 * 4 bytes = 20 bytes
    flags = 0x02  # SYN
    window = 65535
    checksum = 0
    urg_ptr = 0
    
    tcp_header = struct.pack('!HHIIBBHHH',
                              src_port, dst_port, seq_num, ack_num,
                              data_offset, flags, window, checksum, urg_ptr)
    
    return eth_header + ip_header + tcp_header

def main():
    """Génère des paquets de test"""
    print("Génération de paquets de test...")
    
    # Note: Ceci génère des données brutes, pas un fichier pcap valide
    # Pour créer un vrai fichier pcap, on devrait utiliser scapy
    
    packets = []
    packets.append(create_arp_packet())
    packets.append(create_udp_packet())
    packets.append(create_tcp_packet())
    
    print(f"Généré {len(packets)} paquets de test")
    print("\nTypes de paquets générés:")
    print("  - 1 paquet ARP")
    print("  - 1 paquet IPv4/UDP")
    print("  - 1 paquet IPv4/TCP")
    print("\nNote: Pour créer un fichier pcap valide, utilisez scapy")
    print("ou capturez du trafic réel avec tcpdump")

if __name__ == '__main__':
    main()
