import pyshark

def load_pcap(file_path):
    """ Load the PCAP file using pyshark """
    cap = pyshark.FileCapture(file_path, use_json=True, include_raw=True)
    packets = []
    for packet in cap:
        packets.append(packet)
    cap.close()
    return packets

def process_pcap(file_path):
    """ Process the pcap file and extract packet information """
    packets = load_pcap(file_path)
    packet_data = []
    
    for packet in packets:
        ip_len = int(packet.length)
        
        if 'IP' in packet:
            ip_flags = int(packet.ip.flags, 16)
            ip_ttl = int(packet.ip.ttl)
            ip_proto = int(packet.ip.proto)
        else:
            ip_flags = 0
            ip_ttl = 0
            ip_proto = 0
        
        protocol = 'Other'
        sport = 0
        dport = 0
        tcp_flags = 0
        tcp_window_size = 0
        tcp_urg_ptr = 0
        tcp_options_length = 0
        
        if 'TCP' in packet:
            tcp_flags = int(packet.tcp.flags, 16) if hasattr(packet.tcp, 'flags') else 0
            tcp_window_size = int(packet.tcp.window_size_value) if hasattr(packet.tcp, 'window_size_value') else 0
            tcp_urg_ptr = int(packet.tcp.urgent_pointer) if hasattr(packet.tcp, 'urgent_pointer') else 0
            tcp_options_length = len(packet.tcp.options) if hasattr(packet.tcp, 'options') else 0
            sport = int(packet.tcp.srcport) if hasattr(packet.tcp, 'srcport') else 0
            dport = int(packet.tcp.dstport) if hasattr(packet.tcp, 'dstport') else 0
            protocol = 'TCP'
        elif 'UDP' in packet:
            sport = int(packet.udp.srcport) if hasattr(packet.udp, 'srcport') else 0
            dport = int(packet.udp.dstport) if hasattr(packet.udp, 'dstport') else 0
            protocol = 'UDP'
        elif 'ICMP' in packet:
            protocol = 'ICMP'
        
        packet_info = {
            'ip_len': ip_len,
            'ip_ttl': ip_ttl,
            'ip_flags': ip_flags,
            'ip_proto': ip_proto,
            'protocol': protocol,
            'sport': sport,
            'dport': dport,
            'tcp_flags': tcp_flags,
            'tcp_window_size': tcp_window_size,
            'tcp_urg_ptr': tcp_urg_ptr,
            'tcp_options_length': tcp_options_length,
            'udp_length': int(packet.udp.length) if 'UDP' in packet else 0,
            'icmp_type': int(packet.icmp.type) if 'ICMP' in packet else 0,
            'icmp_code': int(packet.icmp.code) if 'ICMP' in packet else 0,
            'payload': packet.highest_layer.encode() if hasattr(packet, 'highest_layer') else b''
        }
        packet_data.append(packet_info)
    
    return packet_data

    

