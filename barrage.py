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

def construct_IP_packet():
	''' Construct an IPv4 packet '''
	# FIXME fill in IP packet address fields dynamically and compute checksum
	version = b'\x04'
	ihl = b''
	service = b''
	length = b''
	ident = b''
	flags = b''
	ttl = b''
	protocol = b'\x01'
	header_chksm = b''
	source_ip = b''
	dest_ip = b''

def construct_packet(target, relays):
	icmp_payload = construct_ICMP_payload(b"")
	for dest in relays:
		# FIXME: craft an IP packet with the victim's source IP and relay's dest IP
		ip_packet = construct_IP_packet()
		print(ip_packet)
	#socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	#return struct.pack('!BBHHHBBH4s4s', ip_data)

def icmp_barrage(target, relays):
	''' Send ping packets to the relays with source IP spoofed '''
	pass

if __name__ == "__main__":
	data = unhexlify("4500003c1c46400040060000ac100a63ac100a0c")
	packet = construct_ICMP_payload(data)
	print(packet.hex())
