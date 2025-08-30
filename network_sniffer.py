from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        proto_name = get_protocol_name(proto_num)
        print(f"Source: {src_ip} --> Destination: {dst_ip} | Protocol: {proto_name}")
        if packet.haslayer(TCP):
            print(f"Source Port: {packet[TCP].sport} --> Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"Source Port: {packet[UDP].sport} --> Destination Port: {packet[UDP].dport}")
        if packet.haslayer("Raw"):
            print(f"Payload: {packet['Raw'].load}\n")

def get_protocol_name(proto_num):
    proto_dict = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return proto_dict.get(proto_num, str(proto_num))

print("Starting packet capture...")
sniff(prn=packet_callback, count=10)
