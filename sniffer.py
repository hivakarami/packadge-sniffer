import socket
import struct
import textwrap

TAB = '\t'

# properly foramt mac address (human read : AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#unpacking 
def enthernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


#properly format ipv4 addr like 127.0.0.1
def ipv4(addr):
    return '.'.join(map(str, addr))


#unpacking IPv4 packet
def ipv4_packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:]


#unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4]) 
    return  icmp_type, code, checksum, data[4:]

#unpack TCP part
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#unpack udp
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# make more readable
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    connect = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) # making sure it is compatible with all machines 
    # infinite loop for listenign to data
    while True:
        raw_data, addr = connect.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = enthernet_frame(raw_data)
        print("enthernet frame: ")
        print("dest_mac: " + str(dest_mac))
        print("src_mac: " + str(src_mac))
        print("eth_proto: " + str(eth_proto))
        #print("data: " + str(data))

        # 8 is for IPv4
        if eth_proto == 8:
            (version, header_len, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB + "IPv4 Packet:")
            print(TAB + TAB + "version:" + str(version) + " header_len:" + str(header_len) + " ttl:" + str(ttl))
            print(TAB + TAB + "protocol:" + str(proto) + " source:" + src + " target:" + target)

            if proto == 1:
                (icmp_type, code, checksum, data) = icmp_packet(data)
                print(TAB + "ICMP Packet:")
                print(TAB + TAB + "ICMP Type:" + str(icmp_type) + " Code:" + str(code) + " Checksum:" + str(checksum))
            elif proto == 17:
                (src_port, dest_port, size, data) = udp_segment(data)
                print(TAB + "UDP Segment:")
                print(TAB + TAB + "Source Port: " + str(src_port) + " Destination Port: " + str(dest_port) + " Length: " + str(size))
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB + "TCP Segment:")
                print(TAB + TAB + "Source Port: " + str(src_port) + " Destination Port: " + str(dest_port))
                print(TAB + TAB + "Sequence Number: " + str(sequence) + " Acknowledgment Number: " + str(acknowledgment))
                print(TAB + TAB + "Flags: URG=" + str(flag_urg) + " ACK=" + str(flag_ack) + " PSH=" + str(flag_psh) + " RST=" + str(flag_rst) + " SYN=" + str(flag_syn) + " FIN=" + str(flag_fin))
                
            
            print(TAB + 'Data:')
            print(format_multi_line('\t\t', data))

        print('\n')



            

        
main()


