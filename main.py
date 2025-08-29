from scapy.all import sniff
import socket


name = socket.gethostbyaddr("18.244.87.25")
def show_packet(packet):
    print(packet.summary())  # Краткая инфа о пакете

sniff(count=5, prn=show_packet)
print(name)