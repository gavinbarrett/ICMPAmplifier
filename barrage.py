import socket
import struct

def construct_ICMP_payload():
	''' Construct the core ICMP payload '''
	...

def construct_IP_packet():
	''' Construct an IPv4 packet '''
	...

def contruct_ETH_packet():
	''' Construct an ethernet packet '''
	...

def construct_packet():
	#socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	#return struct.pack('!BBHHHBBH4s4s', ip_data)

if __name__ == "__main__":
	packet = construct_packet()
	print(packet)
