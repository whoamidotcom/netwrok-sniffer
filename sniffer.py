import socket
import struct
import sys


def ethernet_frame(data):
    dst_mac, src_mac, ethernet_type = struct.unpack("! 6s 6s H", data[:14])
    return traduzir_mac(dst_mac), traduzir_mac(src_mac), ethernet_type, data[14:]


def ip_header(data):
    ipheader = struct.unpack("!BBHHHBBH4s4s", data[:20])
    ip_v = ipheader[0]
    ttl = ipheader[5]
    protocolo = ipheader[6]
    ip_dst = socket.inet_ntoa(ipheader[9])
    ip_src = socket.inet_ntoa(ipheader[8])
    return ip_v, ttl, protocolo, ip_dst, ip_src, data[20:].decode("latin-1")


def traduzir_mac(byts):
    return ":".join(map("{:02x}".format, byts)).upper()


if __name__ == "__main__":
    sckt = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while 1:
        try:
            data, source = sckt.recvfrom(65535)
            dst_mac, src_mac, tp, ip_pkt = ethernet_frame(data)
            ip_v, ttl, protocolo, ip_src, ip_dst, pkt_data = ip_header(ip_pkt)
            print("\n #########################################")
            print(f"{ip_src} ---> {ip_dst}")
            print(f"TTL: {ttl}")
            print(f"Protocolo: {protocolo}")
            print(pkt_data.encode("utf-8"))
        except KeyboardInterrupt:
            sys.exit(0)
