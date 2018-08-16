#! /usr/bin/env python
import sys, time, os, struct
from scapy.all import *

# Disable Kernel's RST in iptable (for the use of scapy)
os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

# Network configuration
srcip = "localhost"	# source ip or dns
dstip = "localhost"	# destination ip or dns
dport = 445			# smb server - raw connection
sport = 3000		# port of source (client) by default
uid = 0
pid = os.getpid()
iface = "lo"		# depends on system env

# Timeout of receiving messages from counterpart
timeout = 0.1

# Initiate TCP connection - 3 handshaking
def three_handshake(skt):
	global sport, dport, dstip
	SYN = IP(dst=dstip)/TCP(sport = sport, dport = dport, flags = "S") # SYN
	SYN_ACK = skt.sr1(SYN, verbose=False, retry=-1) # Listen SYN - ACK
	ACK = generate_ack(SYN_ACK, "A")
	# (A) After sending ACK, listen server response
	#resp = skt.sr1(ACK, verbose=False, retry=-1) # Listen server response
	#return resp
	# (B) After sending ACK, no response from server: SYN_ACK is last response
	send(ACK, verbose=False) # Send ACK
	SYN_ACK.getlayer(IP).len += 1
	return SYN_ACK

def generate_ack(rp, type):
	global sport, dstip, dport
	if type == "A": # Generates ack message to TCP pkt
		p = IP(dst=dstip)/TCP(sport = sport, dport = dport, 
			seq=rp.ack, ack=rp.seq+1, flags = "A")
	elif type == "FA": # Generates FIN-ACK message
		tcp_seg_len = get_tcp_seg_len(rp)
		p = IP(dst=dstip)/TCP(sport = sport, dport = dport, 
			seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = 0x11)
	elif type == "R": # Generates ack message to Raw pkt
		tcp_seg_len = get_tcp_seg_len(rp)
		p = IP(dst=dstip)/TCP(sport = sport, dport = dport, 
			seq=rp.ack, ack=rp.seq+tcp_seg_len, flags = "A")
	return p

# Filter out except TCP packets
# Or wait for long time until one Raw message is received
def filter_tcp_ans(skt, ans, findraw=False):
	global sport
	tcp_resp_list = []
	for sr in ans:
		if sr[1].haslayer("TCP") and sr[1].getlayer("TCP").dport == sport:
			tcp_resp_list.append(sr[1])
	if findraw is True:
		for t in range(150): # max waiting seconds
			sniff_list = skt.sniff(timeout=1)
			if len(sniff_list) < 1:
				continue
			for r in sniff_list:
				if r.haslayer("Raw") and r.haslayer("TCP"): # filter out UDP(DNS)
					if r.getlayer("TCP").dport == sport:	# filter out remaining SMB
						tcp_resp_list.append(r)
						return tcp_resp_list
	return tcp_resp_list

def get_tcp_seg_len(rp):
	ip_total_len = rp.getlayer(IP).len
	ip_header_len = rp.getlayer(IP).ihl * 32 / 8
	tcp_header_len = rp.getlayer(TCP).dataofs * 32/8
	tcp_seg_len = ip_total_len - ip_header_len - tcp_header_len
	return tcp_seg_len

"""
def pseudo_header(ip_src, ip_dst, ip_proto, length):
	print type(ip_src)
	print type(ip_dst)
	print type(ip_proto)
	print type(length)
	return struct.pack("!4s4sHH", inet_aton(str(ip_src)), inet_aton(str(ip_dst)), ip_proto, length)
"""

def disconnect_session(skt, rp):
	# Send FIN-ACK -> get FIN-ACK -> Send ACK
	global timeout

	# Send FIN-ACK and Listen FIN-ACK
	FIN_ACK = generate_ack(rp, "FA")
	ans, unans = skt.sr(FIN_ACK, multi=1, timeout=timeout, verbose=False) # SEND -> GET RESPONSE (normal case) -> GET FINACK
	resps = filter_tcp_ans(skt, ans)

	FIN_ACK = None

	# FIN-ACK picker
	for resp in resps:
		if resp.getlayer("TCP").flags == 0x11:
			FIN_ACK = resp

	if FIN_ACK == None:
		print "[-] disconnect_session(), no FIN-ACK from server"
		sys.exit()
	
	# Send ack to fin-ack
	ACK = generate_ack(FIN_ACK, "A")
	send(ACK, verbose=False)

# Manipulating trace to send from the local system
def localize_msg(rp, reqmsg):
	global srcip, sport, dstip, dport, uid, pid
	
	reqmsg[IP].src = srcip
	reqmsg[IP].dst = dstip
	reqmsg[IP].sport = sport
	reqmsg[IP].dport = dport
	reqmsg[IP].seq = rp.ack
	tcp_seg_len = get_tcp_seg_len(rp)
	reqmsg[IP].ack = rp.seq+tcp_seg_len

	if reqmsg.haslayer(Raw): # processing depending on SMB requests
		# Strip [NetBIOS session service]
		nb_layer = reqmsg.getlayer(Raw).load[0:4]
		# Strip [SMB]
		smb_layer = reqmsg.getlayer(Raw).load[4:]
		# SMB: Session setup request
		if smb_layer[4] == b'\x73':
			smb_layer = SMBSession_Setup_AndX_Request(smb_layer)
			# Update PID
			smb_layer.PID = pid
			# Update UID (provided from server) from session setup request
			if uid > 0:
				smb_layer.UID = uid
		# SMB: Tree connect request
		elif smb_layer[4] == b'\x75':
			smb_layer = bytearray(smb_layer)
			# Update PID
			smb_layer[26] = struct.pack('H', pid)[0]
			smb_layer[27] = struct.pack('H', pid)[1]
			# Update UID
			smb_layer[28] = struct.pack('H', uid)[0]
			smb_layer[29] = struct.pack('H', uid)[1]

		reqmsg[TCP].remove_payload()
		reqmsg /= Raw(nb_layer)
		reqmsg /= Raw(smb_layer)
		#reqmsg.show()

	# For the checksum recalculation when sending
	del reqmsg[IP].chksum
	del reqmsg[IP][TCP].chksum

	return reqmsg[IP]

# Some response messages need corresponding ack. Set 2 cases
def send_receive(skt, rp, reqmsg, send_ack=False):
	global timeout, uid
	_reqmsg = localize_msg(rp, reqmsg)

	ans, unans = skt.sr(_reqmsg, verbose=False, multi=1, timeout=timeout)
	resps = filter_tcp_ans(skt, ans, findraw=True)
	_rp = None

	# ans structure : [(sent, received), (sent, received), ...] @ depricated
	for resp in resps:
		if resp.haslayer(Raw): # processing depending on SMB responses
			# Strip [NetBIOS session service]
			nb_layer = resp.getlayer(Raw).load[0:4]
			# Strip [SMB]
			smb_layer = resp.getlayer(Raw).load[4:]
			if smb_layer[4] == b'\x73': # SMB: Session setup response
				smb_layer_ssr = SMBSession_Setup_AndX_Response(smb_layer)
				if uid == 0: # First seen session setup reseponse
					uid = smb_layer_ssr.UID
		_rp = resp

	if _rp == None:
		print "[-] send_receive(), no response from server"
		sys.exit()

	if send_ack == True:
		ACK = generate_ack(_rp, "R")
		send(ACK, verbose=False)

	return _rp

if __name__ == "__main__":

	# User can specify sport manually
	if len(sys.argv) == 2:
		sport = int(sys.argv[1])

	# Read pcap
	#smbtrace = rdpcap("smbtraces/basicSMBtraces.pcapng")
	smbtrace = rdpcap("smbtraces/basicSMBtraces_nopass.pcapng")

	conf.L3socket = L3RawSocket # comment out this unless loopback communication
	skt = conf.L3socket(iface = iface)

	# TCP THS
	rp = three_handshake(skt)

	# time.sleep(1)
	
	# Negotiate protocol request
	print "=====================send Negotiate protocol request======================="
	npr_pkt = smbtrace[23]
	rp = send_receive(skt, rp, npr_pkt, send_ack=True)

	# time.sleep(1)

	# Session setup request
	print "=====================send session setup request======================="
	ssr_pkt = smbtrace[27]
	rp = send_receive(skt, rp, ssr_pkt)

	# # # time.sleep(1)

	# Tree connect request
	print "=====================send Tree connect request======================="
	tcar_pkt = smbtrace[29]
	rp = send_receive(skt, rp, tcar_pkt, send_ack=True)

	# time.sleep(1)

	# Disconnect session
	disconnect_session(skt, rp)
