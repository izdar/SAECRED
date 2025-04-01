from settings import *
import os
import json
from dragonfly.dragonfly import *
from hashlib import *
from ast import literal_eval
import sys
import signal
from datetime import datetime
import time
import timeout_decorator
import logging
import base64
import multiprocessing
import traceback
import hashlib
import chardet
from ResetHandler import *

class Driver:
	def __init__(self):
		self.APProcess = None
		self.SuppProcess = None
		self.auth=None
		self.src = ""
		self.dst = ""
		self.src_index = 0
		self.pmkids =[]
		self.pmk = []
		self.kck = [b'\xa6m=A\x009S\xf9\xae0\xf8\xdf\x1a\xbf\x80\xc3M\x0e\x0f\x989\x00+\x0f\x84\x97e\xcer\x06\xb3p']
		self.commitResponse = None
		self.confirmResponse = None
		self.send_confirm = 0
		self.password_identifier_element = b''
		self.seqNum = 0
		self.peer_scalar = 0
		self.peer_element = ECC.EccPoint(0,0,"secp256r1")
		self.anticlogging_token = b""
		self.collected_tokens = []
		self.state = 0
		self.validConfirmHashes_256 = ["e090e47c04922f9798e88ed0b74fbb84cfb83b65557fdc511db840ec135167867257d49c2db8a13c076e4861bd12e3531dda6fdebd496c32bc84bc69db646792"]
		self.validConfirmHashes_224 = ["e090e47c04922f9798e88ed0b74fbb84cfb83b65557fdc511db840ec135167867257d49c2db8a13c076e4861bd12e3531dda6fdebd496c32"]
		self.validScalar = 0
		self.group_id = 0
		self.validElement = ECC.EccPoint(0,0,"secp256r1")
		self.validpwe = ECC.EccPoint(0,0,"secp256r1")
		self.validrand = None
		self.validmask = None
		self.reuseValues = False
		self.pwe = ECC.EccPoint(0,0,"secp256r1")
		self.status_codes = { 
			0: "success",
			
		}

		self.PT = None

		self.RejectedGroups = \
		[]
		# [(20).to_bytes(2,"little")]
		self.ANonce = None
		self.SNonce = None
		self.ReplayCounter = 0
		self.ptk = 0
		self.peer_send_confirm = 1
		self.peer_confirm = None
		self.RSNinfo = None

		self.L2sock = L2Socket(type=ETH_P_ALL, iface=iface)
		self.beacon = {}
		self.outputSentence = []
		self._triggerAC = False
		self.triggerState = False
		self.ongoingConnection = False
		self.useDummyMAC = False
		self.ACUsed = False

		self.reset_handler = None
		self.set_reset_handler()

		self.capture = []

		self.M1 = None
		self.M2 = None
		self.M3 = None
		self.M4 = None

		self.fourWayParams = {
			'KeyDescVersion': {"ARC4": 1, 'HMAC-SHA-1-128': 2, "AES-CMAC-128": 3, 'default': 0},
			'KeyType': {'Pairwise': 1 << 3, 'Group': 0},
			'KeyIndex': 0x00,
			'Install': {'Set': 1 << 6, 'notSet': 0},
			'KeyAck': {'Set': 1 << 7, 'notSet': 0},
			'KeyMIC': {'Set': 1 << 8, 'notSet': 0},
			'Secure': {'Set': 1 << 9, 'notSet': 0},
			'Error': {'Set': 1 << 10, 'notSet': 0},
			'Request': {'Set': 1 << 11, 'notSet': 0},
			'EncrypedKeyData': {'Set': 1 << 12, 'notSet': 0},
			'SMKMessage': {'Set': 1 << 13, 'notSet': 0}
			}

		self.sniffTimeout = False

		self.beaconProcess = None

		self.packetQueue = multiprocessing.Queue()
		self.packetQueued = multiprocessing.Event()

		# src = get_macaddress(iface)

	def getFourWayKeyInfo(self, keyDesc='default', keyType='Pairwise',
	 					install='notSet', keyAck='notSet',secure='notSet', error='notSet',
						request='notSet', encrypted='notSet', smk='notSet'):
		return hex(self.fourWayParams['KeyDescVersion'][keyDesc] |\
				self.fourWayParams['KeyType'][keyType] |\
				self.fourWayParams['KeyIndex'] |\
				self.fourWayParams['Install'][install] |\
				self.fourWayParams['KeyAck'][keyAck] |\
				self.fourWayParams['Secure'][secure] |\
				self.fourWayParams['Error'][error] |\
				self.fourWayParams['Request'][request] |\
				self.fourWayParams['EncrypedKeyData'][encrypted] |\
				self.fourWayParams['SMKMessage'][smk])[2:]

	def create_beacon_frame(self, ssid, mac, channel):
		dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
		beacon = Dot11Beacon(cap="ESS+privacy")
		
		ssid_elt = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
		rates_elt = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x24\x30\x48\x6c")
		dsset_elt = Dot11Elt(ID="DSset", info=chr(channel).encode())
		# h2e = Dot11Elt(ID=61, info=b"\x00\x19\x00\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x02\x00\x00\x0f\xac\x04\x03\x00\x00\x0f\xac\x04\x04") 
		
		rsn_elt = Dot11Elt(ID=48, info=(
			b'\x01\x00'                  # RSN Version 1
			b'\x00\x0f\xac\x02'          # Group Cipher Suite: 00-0f-ac (AES)
			b'\x02\x00'                  # 2 Pairwise Cipher Suites (next two lines)
			b'\x00\x0f\xac\x04'          # Pairwise Cipher Suite: 00-0f-ac (CCMP)
			b'\x00\x0f\xac\x02'          # Pairwise Cipher Suite: 00-0f-ac (TKIP)
			b'\x01\x00'                  # 1 Authentication Key Management Suite (line below)
			b'\x00\x0f\xac\x08'          # Authentication Key Management Suite: 00-0f-ac (SAE)
			b'\xc0\x00'                  # RSN Capabilities (no extra capabilities)
		))

		rsn_x_ie = Dot11Elt(ID=244, len=1, info=bytes.fromhex("20"))


		frame = RadioTap() / dot11 / beacon / ssid_elt / rates_elt / dsset_elt / rsn_elt / rsn_x_ie
		return frame

	# Function to send beacon frames
	def send_beacon(self, ssid, mac, channel, iface):
		frame = self.create_beacon_frame(ssid, mac, channel)
		sendp(frame, iface=iface, inter=0.1, loop=1)

	def getBeacon(self):
		p = self.L2sock.recv()
		while p is None:
			p = self.L2sock.recv()
		while Dot11Beacon not in p or p.subtype != 8 or p.info.decode("utf-8") != SULConfig["ssid"]:
			p = self.L2sock.recv()
		return p

	def parseBeacon(self, pkt):
		self.beacon = pkt[Dot11Beacon].network_stats()
		self.beacon['rates'] = [int(x) for x in self.beacon["rates"]]
		return pkt[Dot11].addr2

	def getSymbols(self):
		data = {}
		with open(os.path.join(alphabetPath, alphabetSymbols), 'r') as f:
			data = json.load(f)
		return data

	def createPacket(self, messageType, messageFields={}, group_id=19, ap_commit_pkt=[], password="correctPassword",_src=src):
		if not len(messageFields):
			messageFields = {
					"src": _src,
					"dst": dst,
					"rand": 0,
					"mask": 0,
					"group_id": group_id,
					"password" : password,
					"pwe": 0,
					"scalar": 0,
					"element": ECC.EccPoint(0,0,"secp256r1"),
					"send_confirm": 0,
					"confirm": 0,
					"h2e": True
			}
		if messageFields["group_id"] == 26:
			messageFields["pwe"] = ECC.EccPoint(0,0,"secp224r1")
			messageFields["element"] = ECC.EccPoint(0,0,"secp224r1")
		if messageType == COMMIT:
			self.calculateCommit(messageFields)
		elif messageType == CONFIRM:
			self.calculateConfirm(ap_commit_pkt, messageFields)
		elif messageType == ASSOCIATION_REQUEST:
			return ASSOCIATION_REQUEST
		return messageFields


	def calculateCommit(self, messageFields, group_id=19):
		random.seed(datetime.now().timestamp())
		if messageFields["h2e"]:
			self.PT = hash_to_element(SULConfig["ssid"], messageFields["password"], None, "secp256r1" if messageFields["group_id"] == 19 else "secp224r1")
		messageFields["pwe"] = \
			derive_pwe_ecc(messageFields["password"], src, dst, "secp256r1" if messageFields["group_id"] == 19 else "secp224r1") \
			if not messageFields["h2e"] else \
			generate_pwe(dst, src, self.PT, secp256r1_r if messageFields["group_id"] == 19 else secp224r1_r)
		rand = random.randint(0, secp256r1_r - 1) if messageFields["group_id"] == 19 else random.randint(0, secp224r1_r - 1)
		messageFields["rand"] = rand
		messageFields["mask"] = random.randint(0, secp256r1_r - 1) if messageFields["group_id"] == 19 else random.randint(0, secp224r1_r - 1)
		messageFields["scalar"] = (messageFields["rand"] + messageFields["mask"]) % secp256r1_r if messageFields["group_id"] == 19 else (messageFields["rand"] + messageFields["mask"]) % secp224r1_r
		temp = messageFields["pwe"] * messageFields["mask"]
		messageFields["element"] = ECC.EccPoint(temp.x, Integer(secp256r1_p if messageFields["group_id"] == 19 else secp224r1_p) - temp.y, "secp256r1" if messageFields["group_id"] == 19 else "secp224r1") 
		return messageFields

	def calculatePMK(self, ap_commit_pkt, messageFields):
		if ap_commit_pkt is None:
			self.kck.append(b'\x00' * 32)
			self.pmk.append(b'\x00' * 32)
			return 0, ECC.EccPoint(0, 0, "secp256r1")
		group_id, peer_scalar, peer_element_x, peer_element_y, peer_element, pos = self.parseCommitResponse(ap_commit_pkt)
		if type(pos) == str:
			self.kck.append(b'\x00' * 32)
			self.pmk.append(b'\x00' * 32)
			return 0, ECC.EccPoint(0, 0, "secp256r1")
		# print(messageFields["pwe"].x, messageFields["pwe"].y)
		k = ((messageFields["pwe"] * peer_scalar + peer_element) * messageFields["rand"]).x
		# print(hex(k))
		keyseed = HMAC256(b"\x00"*32, int_to_data(k)) \
		if not len(self.RejectedGroups) else \
			HMAC256(b"".join(x for x in self.RejectedGroups), int_to_data(k))
		kck_and_pmk = KDF_Length(keyseed, "SAE KCK and PMK", int_to_data((messageFields["scalar"] + peer_scalar) % secp256r1_r), 512, 256.0) if messageFields["group_id"] == 19 else KDF_Length(keyseed, "SAE KCK and PMK", int_to_data((messageFields["scalar"] + peer_scalar) % secp224r1_r), 512, 256.0)
		self.kck.append(kck_and_pmk[0:32])
		self.pmk.append(kck_and_pmk[32:])
		self.pmkids.append(int_to_data((messageFields["scalar"] + peer_scalar) % secp256r1_r)[:16])
		return peer_scalar, peer_element
		# print(self.pmk[-1].hex(), self.kck[-1].hex(), int_to_data(k).hex())

	def calculateConfirm(self, ap_commit_pkt, messageFields):
		peer_scalar, peer_element = self.calculatePMK(ap_commit_pkt, messageFields)
		# print(binascii.hexlify(self.kck[-1]).decode('utf-8'))
		# print(binascii.hexlify(self.pmk[-1]).decode('utf-8'))
		if "scalar" in messageFields and "element" in messageFields:
			messageFields["confirm"] = calculate_confirm_hash(self.kck[-1], messageFields["send_confirm"], messageFields["scalar"], messageFields["element"], peer_scalar, peer_element)
		else:
			messageFields["confirm"] = calculate_confirm_hash(self.kck[-1], messageFields["send_confirm"], 0, ECC.EccPoint(0,0,"secp256r1"), peer_scalar, peer_element)
		# print(messageFields["confirm"])
		return messageFields["confirm"]

	def testCommit(self, _src=src):
		fields = self.createPacket(COMMIT,group_id=19, _src=dummy_src)
		fields["h2e"] = True
		recv_pkt = self.sendCommitMessage(fields)
		# recv_pkt.show()
		if type(recv_pkt) == list:
			return fields, recv_pkt[0]
		return fields, recv_pkt
	
	def testConfirm(self):
		fields, ap_commit_pkt = self.testCommit()
		messageFields = self.createPacket(CONFIRM, messageFields=fields, ap_commit_pkt=ap_commit_pkt)
		confirm_recv = self.sendConfirmMessage(messageFields)
		p = self.process_confirm(confirm_recv, messageFields)
		return p

	def sniffPackets(self, func):
		try:
			self.capture = sniff(iface=iface, prn=func, stop_filter=lambda x: self.packetQueued.is_set(), timeout=TIMEOUT)
		except Scapy_Exception as e:
			self.sniffTimeout = True

	def sniffAcks(self):
		try:
			sniff(iface=iface, prn=self.ackHandler, stop_filter=lambda x: self.packetQueued.is_set(), timeout=TIMEOUT)
		except Scapy_Exception as e:
			self.sniffTimeout = True

	def packetHandler(self, p):
		if (Dot11AssoResp in p or Dot11Auth in p or Dot11Deauth in p) and (p.addr1 == src or p.addr1 == dummy_src):
			self.packetQueue.put(p)
			# self.packetQueued.set()

	def dot11AssoRespHandler(self, p):
		if (Dot11Deauth in p or (Dot11 in p and p[Dot11].FCfield == 'from-DS') and Dot11AssoResp not in p) and p.addr1 == src:
			self.packetQueue.put(p)
			self.packetQueued.set()


	def ackHandler(self,p):
		if Dot11Ack in p:
			self.packetQueue.put(p)
			self.packetQueued.set()

	def sendCommitMessage(self, messageFields, dummy_src=dummy_src, h2e=False):
		h2e = messageFields["h2e"]
		if self.useDummyMAC:
			auth = build_sae_commit(dummy_src, dst, messageFields["scalar"], messageFields["element"], messageFields["group_id"], token=self.anticlogging_token, status=126 if h2e else 0)
			self.useDummyMAC = False
			self.L2sock.send(RadioTap()/auth)
			return
		p = []
		for i in range(TRANSMISSIONS):
			sniffThread = multiprocessing.Process(target=self.sniffPackets, args=(self.packetHandler,))
			sniffThread.start()
			time.sleep(0.5)
			auth = None
			try:
				auth = build_sae_commit(messageFields["src"], messageFields["dst"], messageFields["scalar"], messageFields["element"], messageFields["group_id"], token=self.anticlogging_token, password_identifier=(b'\xff' + ((len(self.password_identifier_element))).to_bytes(1, "big") + b'\x21' + self.password_identifier_element) if len(self.password_identifier_element) else b'', rejected_groups=(b'\xff' + ((2*len(self.RejectedGroups))).to_bytes(1,"big") + b'\x5c' + b''.join(x for x in self.RejectedGroups)) if h2e and len(self.RejectedGroups) else b'',status=126 if h2e else 0)
			except OverflowError:
				auth = build_sae_commit(messageFields["src"], messageFields["dst"], messageFields["scalar"], messageFields["element"], messageFields["group_id"], token=self.anticlogging_token, password_identifier=(b'\xff' + ((len(self.password_identifier_element))).to_bytes(1, "big") + b'\x21' + self.password_identifier_element) if len(self.password_identifier_element) else b'', rejected_groups=(b'\xff\xff' + b'\x5c' + b''.join(x for x in self.RejectedGroups)) if h2e and len(self.RejectedGroups) else b'',status=126 if h2e else 0)	
			self.useDummyMAC = False
			self.L2sock.send(RadioTap()/auth)
			time.sleep(1)
			sniffThread.join()
			if self.packetQueue.empty():
				time.sleep(0.7)
			else:
				# pkt = self.packetQueue.get(timeout=1)
				# p.append(pkt)
				while not self.packetQueue.empty():
					pkt = self.packetQueue.get(timeout=5)
					p.append(pkt)
			if not len(p) and i == TRANSMISSIONS - 1:
				return "timeout"
			elif not len(p):
				continue
			else:
				pass
			self.packetQueued.set()
			self.packetQueued.clear()
			return p

	def handle_dot11auth(self, pkt):
		if pkt.addr1 == src and Dot11Auth in pkt:
			# self.L2sock.send(RadioTap() / Dot11(type=1, subtype=13, addr1=pkt.addr2))
			self.L2sock.send(self.auth)
		elif pkt.haslayer(Dot11ProbeReq):
			probe_resp = Dot11(type=0, subtype=5, addr1=supp, addr2=src, addr3=dst)
			ssid_elt = Dot11Elt(ID="SSID", info=SULConfig["ssid"], len=len(SULConfig["ssid"]))
			rates_elt = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x24\x30\x48\x6c")
			dsset_elt = Dot11Elt(ID="DSset", info=chr(6).encode())
			# h2e = Dot11Elt(ID=61, info=b"\x00\x19\x0600\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x02\x00\x00\x0f\xac\x04\x03\x00\x00\x0f\xac\x04\x04") 
			
			rsn_elt = Dot11Elt(ID=48, info=(
				b'\x01\x00'                  # RSN Version 1
				b'\x00\x0f\xac\x02'          # Group Cipher Suite: 00-0f-ac (AES)
				b'\x02\x00'                  # 2 Pairwise Cipher Suites (next two lines)
				b'\x00\x0f\xac\x04'          # Pairwise Cipher Suite: 00-0f-ac (CCMP)
				b'\x00\x0f\xac\x02'          # Pairwise Cipher Suite: 00-0f-ac (TKIP)
				b'\x01\x00'                  # 1 Authentication Key Management Suite (line below)
				b'\x00\x0f\xac\x08'          # Authentication Key Management Suite: 00-0f-ac (SAE)
				b'\xc0\x00'                  # RSN Capabilities (no extra capabilities)
			))

			rsn_x_ie = Dot11Elt(ID=244, len=1, info=bytes.fromhex("20"))
			frame = RadioTap() / probe_resp / Dot11ProbeResp(timestamp=int(time.time()), cap=0x1104) / ssid_elt / rates_elt / dsset_elt / rsn_elt / rsn_x_ie
			self.L2sock.send(frame)
	
	def sniff_dot11auth(self):
		sniff(prn=self.handle_dot11auth, iface=iface,store=0, timeout=30)
	

	def sendConfirmMessage(self, messageFields):
		for i in range(TRANSMISSIONS):
			sniffThread = multiprocessing.Process(target=self.sniffPackets, args=(self.packetHandler,))
			sniffThread.start()
			time.sleep(0.1)
			auth = build_sae_confirm(src, dst, messageFields["send_confirm"], messageFields["confirm"])
			self.L2sock.send(RadioTap()/auth)
			sniffThread.join()
			p = None
			try:
				p = self.packetQueue.get(timeout=5)
			except:
				p = None
			self.packetQueued.set()
			self.packetQueued.clear()
			if p is None and i == TRANSMISSIONS - 1:
				return "timeout"
			elif p is None:
				continue
			else:
				pass
				# self.L2sock.send(RadioTap()/Dot11(addr1=dst)/Dot11Ack())	
			return p

	def process_confirm(self, p, messageFields):
		try:	
			payload = bytes(p[Dot11Auth].payload)
		except:
			return "malformed_packet"

		send_confirm = int.from_bytes(payload[:2], "little")
		pos = 2
		
		received_confirm = payload[pos:pos+32]
		pos += 32

		self.peer_confirm = received_confirm
		self.peer_send_confirm = send_confirm

		if type(self.peer_element) != bytes and type(messageFields['element']) != bytes:
			expected_confirm = calculate_confirm_hash(self.kck[-1], send_confirm, self.peer_scalar, self.peer_element, messageFields["scalar"], messageFields["element"])
			return expected_confirm, received_confirm
		else:
			return 'success', 'fail' 

	def parseCommitResponse(self, p):
		if type(p) == str:
			return '','','','','',"TIMEOUT"
		if (int(p[Dot11Auth].status) == 0x0001 or int(p[Dot11Auth].status) == 0x007b):
			# payload = bytes(p[Dot11Auth].payload)
			# group_id = int.from_bytes(payload[:2], "little")
			return '','','','','',"COMMIT_ERROR"
		elif (int(p[Dot11Auth].status) == 77):
			payload = bytes(p[Dot11Auth].payload)
			group_id = int.from_bytes(payload[:2], "little")
			return group_id,'','','','',"COMMIT_UNSUPPORTED_GROUP"
		elif (int(p[Dot11Auth].status) == 0x004c):
			payload = bytes(p[Dot11Auth].payload)
			group_id = int.from_bytes(payload[:2], "little")
			pos = 2
			anti_clogging_token = payload[pos:]
			self.anticlogging_token = anti_clogging_token
			return '','','','', anti_clogging_token,"ANTICLOGGING_TOKEN_REQUIRED"
		elif (p[Dot11Auth].status in [0, 126]):
			payload = bytes(p[Dot11Auth].payload)
			group_id = int.from_bytes(payload[:2], "little")
			pos = 2
			peer_scalar = int(payload[pos:pos+32].hex(), 16)
			pos += 32
			peer_element_x = int(payload[pos:pos+32].hex(), 16)
			peer_element_y = int(payload[pos+32:pos+64].hex(), 16)
			try:
				peer_element = ECC.EccPoint(peer_element_x, peer_element_y, "secp256r1")
			except:
				return group_id, peer_scalar, peer_element_x, peer_element_y, peer_element, "COMMIT_AP_ELEMENT_NOT_ON_CURVE"
			pos += 64
			return group_id, peer_scalar, peer_element_x, peer_element_y, peer_element, pos
		else:
			return '','','','','',"COMMIT_ERROR"


	def createAssociationRequest(self, h2e=False):
		dot11_assoc_req = Dot11(addr1=dst, addr2=src, addr3=dst) / Dot11AssoReq(cap=0x3114, listen_interval=0x000a)

		# SSID parameter set
		ssid_elt = Dot11Elt(ID=0, info=SULConfig["ssid"])

		# Supported Rates
		supported_rates_elt = Dot11Elt(ID=1, len=len(b'\x02\x04\x0b\x96\x0c\x12\x18\x24'),info=b'\x02\x04\x0b\x16\x0c\x12\x18\x24')

		# Extended Supported Rates
		extended_rates_elt = Dot11Elt(ID=50, len=4, info=bytes.fromhex("3048606c"))

		power_capabilities = Dot11Elt(ID=33, len=2, info=bytes.fromhex("0016"))

		# pmkids_elt = PMKIDListPacket(nb_pmkids=1, pmkid_list=["\x00"*16])
		# RSN Information Element
		rsn_info_elt = Dot11EltRSN(
			ID=48,
			version=1,
			# len=26,
			pmkids=PMKIDListPacket(),
			group_cipher_suite=RSNCipherSuite(cipher=0x04),
			nb_pairwise_cipher_suites=1,
			pairwise_cipher_suites=[RSNCipherSuite(cipher=0x04)],
			nb_akm_suites=1,
			akm_suites=[AKMSuite(suite=0x08)],
			mfp_capable=1,
		)
		
		ht_capabilties = Dot11Elt(ID=45, len=26, info=bytes.fromhex("e71917ffff00000000000000002c010100000000000000000000"))

		he_capabilities = Raw(load=bytes.fromhex("ff1a230178309ac0ab023f4e09fd098c160ffc01fafffaff611cc771"))

		he_6ghz_band_capabilities = Raw(load=bytes.fromhex("ff033bbd02"))

		rm_enabled_capabilities = Dot11Elt(ID=70, len=5, info=bytes.fromhex("7100000000"))

		extended_capabilities = Dot11Elt(ID=127, len=11,info=bytes.fromhex("0400400001004040000020"))

		vendor_specific = Dot11Elt(ID=221, len=7, info=bytes.fromhex("0050f202000100"))

		operating_classes = Dot11Elt(ID=59,  info=bytes.fromhex("51517376797c7d8384"))

		rsn_info_elt.len = len(rsn_info_elt)

		self.RSNinfo = rsn_info_elt

		rsn_x_ie = Dot11Elt(ID=244, len=1, info=bytes.fromhex("20"))

		association_request_packet = RadioTap(ChannelFlags=0xc0, ChannelFrequency=0x8509) / dot11_assoc_req / ssid_elt / supported_rates_elt / extended_rates_elt / power_capabilities / rsn_info_elt / ht_capabilties / extended_capabilities / he_capabilities / he_6ghz_band_capabilities / rm_enabled_capabilities / operating_classes / vendor_specific
		# association_request_packet.show()
		return association_request_packet / rsn_x_ie if h2e else association_request_packet
		# return RadioTap()/Dot11(addr1=dst, addr2=src, addr3=dst)/Dot11AssoReq(cap=0x1100, listen_interval=0x00a) / ssid_elt / Dot11Elt(ID=0, info=self.beacon['ssid'])/Dot11EltRates(len=len(self.beacon['rates']), rates=self.beacon['rates'])/ rsn_info_elt 

	def sendDeauth(self, messageFields={}):
		for i in range(2):
			self.L2sock.send(RadioTap()/Dot11(addr1=dst, addr2=src, addr3=dst)/Dot11Deauth(reason=1))
			# time.sleep(0.3)

	def sendDisassoc(self):
		self.L2sock.send(RadioTap()/Dot11(addr1=dst, addr2=src, addr3=dst)/Dot11Disas(reason=1))
		

	def sendDummyDeauth(self):
		for dummy in dummy_list[:AC_TRIGGER_COUNT]:
			for i in range(2):
				self.L2sock.send(RadioTap()/Dot11(addr1=dst, addr2=dummy, addr3=dst)/Dot11Deauth(reason=1))

	def sendAssociationRequest(self,messageFields={}):
		p = None
		for i in range(TRANSMISSIONS):
			self.L2sock.send(self.createAssociationRequest(h2e=messageFields["h2e"]))
			time.sleep(0.1)
			sniffThread = multiprocessing.Process(target=self.sniffPackets, args=(self.dot11AssoRespHandler,))
			sniffThread.start()
			sniffThread.join()
			try:
				p = self.packetQueue.get(timeout=1)
			except:
				pass
			if p is None and i == TRANSMISSIONS - 1:
				return "timeout"
			elif p is None:
				continue
			else:
				pass
			self.packetQueued.clear()
			return p

	def openSystemAuth(self):
		auth = RadioTap() / Dot11(type=0, subtype=11, addr1=dst, addr2=src, addr3=dst) / Dot11Auth(algo=0, status=0)
		return auth

	def sendOpenSystemAuth(self, messageFields):
		for i in range(TRANSMISSIONS):
			sniffThread = multiprocessing.Process(target=self.sniffPackets, args=(self.dot11AssoRespHandler,))
			sniffThread.start()
			time.sleep(0.1)
			self.L2sock.send(self.openSystemAuth())
			sniffThread.join()
			p = None
			try:
				p = self.packetQueue.get(timeout=1)
			except:
				p = None
			self.packetQueued.clear()
			if p is None and i == TRANSMISSIONS - 1:
				return "timeout"
			elif p is None:
				continue
			else:
				pass
			return p


	def parseACToken(self, p):
		if (int(p[Dot11Auth].status) == 0x004c):
			payload = bytes(p[Dot11Auth].payload)
			group_id = int.from_bytes(payload[:2], "big")
			pos = 2
			anti_clogging_token = payload[pos:]
			return anti_clogging_token

	def mapOutputSymbols(self, p, messageFields):
		if p == "timeout":
			return "TIMEOUT"
		if p is None:
			return "null_action"
		if is_sae_commit(p):
			group_id, self.peer_scalar, peer_element_x, peer_element_y, self.peer_element, pos = self.parseCommitResponse(p)
			if type(self.peer_scalar) == str:
				self.peer_scalar = 0
			if type(self.peer_element) == str:
				self.peer_element = ECC.EccPoint(0, 0, "secp256r1")
			if pos == "COMMIT_AP_ELEMENT_NOT_ON_CURVE":
				return "COMMIT_ERROR_INVALID_POINT"
			elif pos == "COMMIT_ERROR":
				return "COMMIT_ERROR"
			elif pos == "COMMIT_UNSUPPORTED_GROUP":
				self.RejectedGroups.append(group_id.to_bytes(2, 'little'))
				return "GROUP_NOT_SUPPORTED"
			elif pos == "ANTICLOGGING_TOKEN_REQUIRED":
				return "ANTICLOGGING_TOKEN_REQUIRED"
			else:
				self.ongoingConnection = True
				self.commitResponse = p
				try:
					self.calculatePMK(p, messageFields)
				except:
					return "SUCCESSFUL_TRANSITION_TO_CONFIRMED"
				return "COMMIT_VALID"
		elif is_sae_confirm(p):
			if str(p) == "malformed_packet":
				return "CONFIRM_ERROR_HASH_MISMATCH"
			elif str(p) == "timeout":
				return "CONFIRM_TIMEOUT"
			else:
				if p[Dot11Auth].status == 0:
					expected, received = self.process_confirm(p, messageFields)
					if expected == received:
						return "RECEIVED_CONFIRM_VALID"
					elif received == 'fail':
						return "COMMIT_ELEMENT_NOT_ON_CURVE"
					else:
						return "RECEIVED_CONFIRM_INVALID"
				elif p[Dot11Auth].status == 1:
					return "CONFIRM_ERROR"

		else:
			if Dot11Deauth in p:
				self.ongoingConnection = False
				return "DEAUTHENTICATION"
			elif int.from_bytes(bytes(p[Dot11].payload)[13:15], "big") == 0x88:
				return "M1_RECEIVED"
			elif int.from_bytes(bytes(p[Dot11].payload)[13:15], "big") == 0x108:
				return "M2_RECEIVED"
			elif int.from_bytes(bytes(p[Dot11].payload)[13:15], "big") == 0x13c8:
				return "M3_RECEIVED"
			elif int.from_bytes(bytes(p[Dot11].payload)[13:15], "big") == 0x308:
				return "M4_RECEIVED"
			elif p[Dot11].FCfield == 'from-DS' and Dot11AssoResp not in p and Dot11Ack not in p:
				return "ASSOCIATION_RESPONSE"
	
	def startAP(self):
		self.APProcess = subprocess.Popen(["nohup", "sudo","%s%s"%(AP_PATH, "./hostapd"), "-dd", "-K", "%s%s"%(AP_PATH, "hostapd_wpa3.conf")], stdout=open("hostapd_dump.log","a"), stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
		time.sleep(0.1)

	def stopAP(self):
		os.killpg(os.getpgid(self.APProcess.pid), signal.SIGINT)
		time.sleep(0.1)

	def restartAP(self):
		self.stopAP()
		self.startAP()

	def homingSequence(self):
		self.sendDeauth()
		self.sendDummyDeauth()
		while True:
			try:
				mf = self.createPacket("COMMIT", password=SULConfig["password"])
				pkt = self.sendCommitMessage(mf)[0]
				mf["send_confirm"] = self.send_confirm
				mf["confirm"] = self.calculateConfirm(pkt, mf)
				pkt = self.sendConfirmMessage(mf)
				break
			except:
				self.sendDeauth()
				self.sendDummyDeauth()			
		for i in range(2):
			self.sendAssociationRequest()


	def resetState(self):
		global src
		self.sendDeauth()
		self.RejectedGroups = []
		self.commitResponse = None
		self.confirmResponse = None
		self.send_confirm = 1
		self.src_index = self.src_index + 1
		src = src_list[self.src_index]
		self.send_confirm = 0
		self.anticlogging_token = b''
		self.password_identifier_element = b''
		self.RejectedGroups = []
		self._triggerAC = False
		self.triggerState = False
		self.ongoingConnection = False
		self.useDummyMAC = False
		self.outputSentence = []
		self.commitResponse = None
		self.peer_scalar = 0
		self.peer_element = ECC.EccPoint(0,0,"secp256r1")
	
	def read_from_file(self, filename):
		try:
			with open(filename, 'rb') as file:
				line = file.readline()
				return line if line else None
		except FileNotFoundError:
			return None

	def write_to_file(self, filename, msg):
		with open(filename, 'w') as file:
			file.write(msg)

	@timeout_decorator.timeout(10)
	def testCrash(self, _src=src):
		self.useDummyMAC = True
		fields, recv_pkt = self.testCommit(_src=dummy_src)
		self.useDummyMAC = False
		symbol = self.mapOutputSymbols(recv_pkt, fields)
		return symbol == "TIMEOUT"

	def parse_fuzzer_packet(self, message):
		algo = int.from_bytes(message[0:2], 'little')
		seq = int.from_bytes(message[2:4], 'little')
		status_code = int.from_bytes(message[4:6], 'little')
		message_type = int.from_bytes(message[6:8], 'little')
		group_id = int.from_bytes(message[8:10], 'little')
		payload = message[10:]
		return algo, seq, status_code, message_type, group_id, payload

	def packetToState(self, packet_list, response_list):
		currentState = "nothing"
		for packet in packet_list:
			try:
				algo, seq, status_code, message_type, group_id, payload = self.parse_fuzzer_packet(message)
				if seq == 1:
					pos = 0
					scalar = int(payload[pos:pos+32].hex(), 16)
					element = int(payload[pos+32:pos+96].hex(), 16)
					element = ECC.EccPoint(element.x, element.y, "secp256r1")
					self.fuzzer_scalar = scalar
					self.fuzzer_element = element
					pos += 32
					currentState = "confirmed"
			except:
				currentState = "nothing"
			try:
				algo, seq, status_code, message_type, group_id, payload = self.parse_fuzzer_packet(message)
				if seq == 2:
					payload = bytes(p[Dot11Auth].payload)
					send_confirm = int.from_bytes(payload[:2], "little")
					pos = 2
					received_confirm = payload[pos:pos+32]
					pos += 32
					self.confirm = received_confirm
					self.send_confirm = send_confirm
			except:
				pass

	def check_sae_params(self, sae_params, messageFields):
		valid_scalar, valid_element = False, False
		scalar, element, confirm, send_confirm, ac_token, status, passwdId, rgList, acList = None, None, None, None, None, None, None, None, None
		if "failed" in sae_params:
			return "IGNORE"
		if "scalar" in sae_params:
			scalar = messageFields['scalar']
			element = messageFields['element']
			status = int(sae_params["status"])
			if "ac_token" in sae_params:
				ac_token = bytes.fromhex(sae_params["ac_token"])
				if ac_token != self.anticlogging_token:
					return "IGNORE"
			if "pi_list" in sae_params:
				try:
					passwdId = int(sae_params["pi_list"], 16).to_bytes(2, "big")
					self.password_identifier_element = passwdId
				except:
					pass
			if "rg_list" in sae_params:
				rgList = bytes.fromhex(sae_params["rg_list"])
			if "ac_list" in sae_params:
				acList = bytes.fromhex(sae_params["ac_list"])
			if scalar > 1 and scalar < secp256r1_r:
				try:
					ECC.EccPoint(element.x, element.y, "secp256r1")
					if "pi_list" in sae_params:
						return "COMMIT_ERROR"
					if "ac_list" in sae_params:
						return "COMMIT_ERROR" 
					if rgList is not None:
						if (19).to_bytes(2, 'little') not in rgList and (20).to_bytes(2, 'little') not in rgList and (21).to_bytes(2, 'little') not in rgList:
							return "COMMIT_VALID"
					return "COMMIT_VALID"
				except:
					return "COMMIT_ERROR"
			else:
				return "COMMIT_ERROR"
		elif "send_confirm" in sae_params:
			send_confirm = int(sae_params["send_confirm"])
			confirm_hash = bytes.fromhex(sae_params["confirm_hash"])
			if self.commitResponse is not None:
				try:
					expected_confirm_hash = self.calculateConfirm(self.commitResponse, messageFields)
					if confirm_hash == expected_confirm_hash:
						return "RECEIVED_CONFIRM_VALID"
					else:
						return "CONFIRM_ERROR"
				except:
					return "IGNORE"

	def oracle_approximation(self, messageFields):
		_data = ""
		while not len(_data):
			with open(BYTES_PARSED, 'r') as f:
				_data = f.read()
		data = json.loads(_data)
		ans = self.check_sae_params(data, messageFields)
		oracle_response = ""
		if ans == "COMMIT_VALID":
			oracle_response = "CONFIRMED"
		elif ans == "RECEIVED_CONFIRM_VALID":
			oracle_response = "ACCEPTED"
		elif ans == "COMMIT_ERROR":
			oracle_response = "NOTHING"
		elif ans == "CONFIRM_ERROR":
			oracle_response = "IGNORE"
		else:
			oracle_response = "IGNORE"
		with open("../WiFiPacketGen/sync/oracle-response.txt",'w') as f:
			f.write(oracle_response)
		return ans
		
	def start_physical_interface(self):
		start_virtual_interface(phy, iface)
		set_ap_mode(phy)
		start_ap(phy, 6)

	def set_reset_handler(self):
		if SUT == "eero":
			self.reset_handler = reset_eero
		elif SUT == "Verizon":
			self.reset_handler = reset_Verizon
		elif SUT == "hostap":
			pass
		elif SUT == "ASUS-1800S":
			self.reset_handler = reset_ASUS1800S
		elif SUT == "ASUS-TUF":
			self.reset_handler = reset_ASUSTUF
		elif SUT == "Tp-Link_CD7A":
			self.reset_handler = reset_TPLinkCD7A
		elif SUT == "Tp-Link_0C78":
			self.reset_handler = reset_TPLink0C78

	def hard_reset(self):
		if not HOSTAP_TEST:
			subprocess.check_output(["sudo", "airmon-ng","stop", iface])
			time.sleep(2)
			while not self.reset_handler():
				pass
			self.src_index = 0
			self.start_physical_interface()
			time.sleep(2)
			self.L2sock = L2Socket(type=ETH_P_ALL, iface=iface)
			time.sleep(2)
			self.resetState()
		else:
			self.stopAP()
			time.sleep(2)
			self.startAP()
			time.sleep(2)
		return time.time()
		

	def read_trace_length(self):
		traceLength = 0
		while True:
			try:
				with open("../WiFiPacketGen/sync/trace-length.txt") as f:
					traceLength = int(f.read())
				break
			except:
				pass
		return traceLength

	def delete_trace_files(self, traceLength):
		for i in range(traceLength):
			try:
				os.remove("../WiFiPacketGen/sync/message_%d.txt"%i)
			except FileNotFoundError:
				pass
		try:
			os.remove("../WiFiPacketGen/sync/trace-length.txt")
		except FileNotFoundError:
			pass


	def check_lock(self):
		if os.path.exists(PAUSE_FILE):
			try:
				subprocess.check_output(["sudo", "airmon-ng","stop", iface])
			except:
				pass
			with open(WORKER_PAUSE_FILE, 'w') as f:
				f.write("paused")
			print("Worker %s is pausing..."%SUT)

			while os.path.exists(PAUSE_FILE):
				time.sleep(CHECK_INTERVAL)
			
			os.remove(WORKER_PAUSE_FILE)
			self.start_physical_interface()
			time.sleep(2)
			self.L2sock = L2Socket(type=ETH_P_ALL, iface=iface)
			time.sleep(2)
			self.resetState()


	def read_messages(self, message_file):
		data = ""
		while not len(data):
			with open(message_file, 'r') as f:
				data = f.read()
		data = data.split(', ')[1:]
		print(data)
		with open(message_file,'w') as f:
			f.write("")
		return [bytes.fromhex(x) if x not in ["ASSOCIATION_REQUEST", "COMMIT", "CONFIRM"] else x for x in data]


	def communicate_with_ocaml(self, message_file, response_file):
		messageFields = {'password' : 'correctPassword', 'group_id' : 19}
		start_time = time.time()
		while True:
			if not HOSTAP_TEST:
				self.check_lock()
			elif time.time() - start_time >= 3600:
				start_time = self.hard_reset()
			messages = self.read_messages(message_file)
			print(messages)
			for index, message in enumerate(messages):
				print(message)
				valid_packet_request = ""
				try:
					valid_packet_request = message
				except:
					pass
				if valid_packet_request == 'COMMIT':
					messageFields = self.createPacket(COMMIT, group_id=19,_src=src)
					APResponse = self.sendCommitMessage(messageFields)
					if APResponse is not None:
						if type(APResponse) == str:
							self.confirmResponse = APResponse
							confirm_ans = APResponse
						elif is_sae_confirm(APResponse):
							self.confirmResponse = APResponse
							confirm_ans = APResponse
						elif is_sae_commit(APResponse):
							if self.mapOutputSymbols(APResponse, messageFields) == "ANTICLOGGING_TOKEN_REQUIRED":
								APResponse = self.sendCommitMessage(messageFields)
							self.commitResponse = APResponse
					if type(APResponse) == list:
						for p in APResponse:
							if is_sae_commit(p):
								commit_ans = p
								self.commitResponse = p
								self.mapOutputSymbols(p, messageFields)
							if is_sae_confirm(p):
								confirm_ans = p
								self.confirmResponse = p
					if index == len(messages) - 1:
						self.write_to_file(response_file, "SUCCESSFUL_TRANSITION_SUCCESS")
				elif valid_packet_request == 'CONFIRM':
					if "send_confirm" not in messageFields:
						messageFields["send_confirm"] = self.send_confirm
					else:
						messageFields["send_confirm"] += 1
					if "scalar" not in messageFields and "element" not in messageFields:
						messageFields["scalar"] = 0
						messageFields["element"] = ECC.EccPoint(0,0,"secp256r1")
					self.calculateConfirm(self.commitResponse, messageFields)
					self.confirmResponse = self.sendConfirmMessage(messageFields)
					confirm_response = self.mapOutputSymbols(self.confirmResponse, messageFields)
					if index == len(messages) - 1:
						self.write_to_file(response_file, "SUCCESSFUL_TRANSITION_SUCCESS")
				elif valid_packet_request == 'ASSOCIATION_REQUEST':
					messageFields["h2e"] = True
					self.sendAssociationRequest(messageFields)
					if index == len(messages) - 1:
						self.write_to_file(response_file, "SUCCESSFUL_TRANSITION_SUCCESS")
				elif message:
					status_code = int.from_bytes(message[4:6], 'little')
					algo = int.from_bytes(message[0:2], 'little')
					seq = int.from_bytes(message[2:4], 'little')
					messageFields['h2e'] = True if status_code == 126 else False
					messageFields = self.calculateCommit(messageFields)
					if b'<SCALAR>' in message:
						message = message.replace(b'<SCALAR>', int_to_data(messageFields['scalar']))
					if b'<ELEMENT>' in message:
						message = message.replace(b'<ELEMENT>', point_to_data(messageFields['element']))
					if b'<AC_TOKEN>' in message:
						message = message.replace(b'<AC_TOKEN>', self.anticlogging_token)
						messageFields['ac_token'] = self.anticlogging_token
					if b'<SEND_CONFIRM_COUNTER>' in message:
						self.send_confirm += 1
						messageFields['send_confirm'] = self.send_confirm
						message = message.replace(b'<SEND_CONFIRM_COUNTER>', struct.pack("<H", messageFields['send_confirm']))
					if b'<CONFIRM_HASH>' in message:
						if 'send_confirm' not in messageFields:
							messageFields['send_confirm'] = self.send_confirm
						confirm_hash = self.calculateConfirm(self.commitResponse, messageFields)
						message = message.replace(b'<CONFIRM_HASH>', confirm_hash)
					if index == len(messages) - 1:
						with open("../WiFiPacketGen/sync/placeholders-replace.pkt","wb") as f:
							f.write(message)
					while not os.path.exists(BYTES_PARSED):
						pass
					if index == len(messages) - 1:
						expected_state = self.oracle_approximation(messageFields)
					responses = self.sendFuzzerMessage(message)
					outputSymbol = ""
					outputSymbols = []
					if index == len(messages) - 1:
						if type(responses) == str:
							outputSymbol = "TIMEOUT"
						else:
							for response in responses:
								if "scalar" not in messageFields and "element" not in messageFields:
									messageFields["scalar"] = 0
									messageFields["element"] = ECC.EccPoint(0,0,"secp256r1")
								outputSymbols.append(self.mapOutputSymbols(response, messageFields))
							outputSymbol = outputSymbols[0]
						if outputSymbol == "TIMEOUT":
							crashed = False
							try:
								crashed = self.testCrash(_src=dummy_src)
							except:
								crashed = True
							if crashed:
								self.write_to_file(response_file, "CRASH")
							else:
								self.write_to_file(response_file, "TIMEOUT")
						elif expected_state == outputSymbol or expected_state in outputSymbols or (expected_state == "IGNORE" and outputSymbol in ["TIMEOUT", "COMMIT_ERROR", "CONFIRM_ERROR", "COMMIT_UNSUPPORTED_GROUP"]):
							self.write_to_file(response_file, "EXPECTED_OUTPUT")
						elif outputSymbol == "SUCCESSFUL_TRANSITION_TO_CONFIRMED":
							self.write_to_file(response_file, "SUCCESSFUL_TRANSITION_SUCCESS")
						else:
							self.write_to_file(response_file, "UNEXPECTED_OUTPUT")
			self.resetState()	
			time.sleep(1)

	def sendFuzzerMessage(self, message):
		for i in range(TRANSMISSIONS):
			sniffThread = multiprocessing.Process(target=self.sniffPackets, args=(self.packetHandler,))
			sniffThread.start()
			time.sleep(0.3)
			self.L2sock.send(RadioTap() / Dot11(type=0, subtype=11, addr1=dst, addr2=src, addr3=dst) / Raw(load=message))
			time.sleep(0.2)
			sniffThread.join()
			p = []
			if self.packetQueue.empty():
				time.sleep(0.7)
			else:
				while not self.packetQueue.empty():
					pkt = self.packetQueue.get(timeout=5)
					p.append(pkt)
			if not len(p) and i == TRANSMISSIONS - 1:
				return "timeout"
			elif not len(p):
				continue
			else:
				pass
			self.packetQueued.set()
			self.packetQueued.clear()
			return p

def main():
	driver = None
	try:
		subprocess.check_output(["sudo", "airmon-ng","check","kill"])
		time.sleep(2)
		if HOSTAP_TEST:
			subprocess.call(["bash", "run_ap.sh"])

		driver = Driver()
		if HOSTAP_TEST:
			driver.startAP()
		driver.communicate_with_ocaml("../WiFiPacketGen/sync/message.txt","../WiFiPacketGen/sync/response.txt")
	except Exception as err:
		tracebackStr = traceback.format_exc()
		with open("crash.log","w") as f:
			f.write(tracebackStr)
	finally:
		if HOSTAP_TEST:
			driver.stopAP()
		else:
			subprocess.check_output(["sudo", "airmon-ng","stop", iface])
		subprocess.check_output(["sudo", "service","NetworkManager","start"])

if __name__ == "__main__":
	main()
