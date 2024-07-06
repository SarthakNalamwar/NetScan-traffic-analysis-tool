# feature_extraction.py
from typing import List, Dict, Any
import numpy as np

def extract_features(packet_info: Dict[str, Any]) -> List[float]:
    features = []

    # IP features
    features.extend([
        packet_info.get('ip_len', 0),
        packet_info.get('ip_ttl', 0),
        int(packet_info.get('ip_flags', 0)),
        packet_info.get('ip_proto', 0)
    ])

    # Port features
    features.extend([
        packet_info.get('sport', 0),
        packet_info.get('dport', 0)
    ])

    # Protocol one-hot encoding
    protocols = ['TCP', 'UDP', 'ICMP', 'Other']
    features.extend([1 if packet_info.get('protocol') == proto else 0 for proto in protocols])

    # TCP-specific features
    if packet_info.get('protocol') == 'TCP':
        features.extend([
            int(packet_info.get('tcp_flags', 0)),
            packet_info.get('tcp_window_size', 0),
            packet_info.get('tcp_urg_ptr', 0),
            packet_info.get('tcp_options_length', 0)
        ])
    else:
        features.extend([0, 0, 0, 0])  # Padding for non-TCP packets

    # UDP-specific features
    if packet_info.get('protocol') == 'UDP':
        features.append(packet_info.get('udp_length', 0))
    else:
        features.append(0)  # Padding for non-UDP packets

    # ICMP-specific features
    if packet_info.get('protocol') == 'ICMP':
        features.extend([
            packet_info.get('icmp_type', 0),
            packet_info.get('icmp_code', 0)
        ])
    else:
        features.extend([0, 0])  # Padding for non-ICMP packets

    # Payload features
    features.extend([
        packet_info.get('payload_size', 0),
        packet_info.get('payload_entropy', 0)
    ])

    return features

def calculate_entropy(payload: bytes) -> float:
    byte_counts = np.bincount(np.frombuffer(payload, dtype=np.uint8), minlength=256)
    probabilities = byte_counts / len(payload)
    entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
    return entropy

def process_packet_data(packet_data: List[Dict[str, Any]]) -> np.ndarray:
    for packet in packet_data:
        payload = packet.get('payload', b'')
        packet['payload_size'] = len(payload)
        packet['payload_entropy'] = calculate_entropy(payload)

    return np.array([extract_features(packet) for packet in packet_data])

if __name__ == "__main__":
    sample_packet = {
        'ip_len': 100,
        'ip_ttl': 64,
        'ip_flags': 2,
        'ip_proto': 6,
        'protocol': 'TCP',
        'sport': 12345,
        'dport': 80,
        'tcp_flags': 2,
        'tcp_window_size': 65535,
        'tcp_urg_ptr': 0,
        'tcp_options_length': 12,
        'payload': b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
    }
    features = extract_features(sample_packet)
    print("Extracted features:", features)
    print("Number of features:", len(features))
