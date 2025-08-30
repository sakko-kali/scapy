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

# ips=["8.8.8.8","45.33.32.156","0.0.0.0"]
# for ip in ips:
#     ip = IP(dst=ip)
#     tcp = TCP(dport=80, flags="S")
#     packet = ip/tcp
#     reply = sr1(packet, timeout=10)
#     if reply:
#         reply.show()