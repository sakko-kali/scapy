from scapy.all import *
import socket


# name = socket.gethostbyaddr("18.244.87.25")
# def show_packet(packet):
#     print(packet.summary())  # Краткая инфа о пакете
#
# sniff(count=5, prn=show_packet)
# print(name)

# packet = IP(dst="8.8.8.8")/ICMP()
#
# reply = sr1(packet, timeout=5)
#
# if reply:
#     reply.show()
# else:
#     print("-")