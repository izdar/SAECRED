# TODO: For now only include the code we actually used for EAP-pwd
# TODO: Program unit tests so we can easily keep our EAP-pwd code correct
#!/usr/bin/env python3

#CODE COPIED FROM https://github.com/vanhoefm/libwifi/blob/master/dragonfly.py

from scapy.all import *
from .wifi import *
import sys, struct, math, random, select, time, binascii

from Crypto.Hash import HMAC, SHA256, SHA224, CMAC
from Crypto.PublicKey import ECC
from Crypto.Util import number
from Crypto.Math.Numbers import Integer
from Crypto.Cipher import AES

# Alternative is https://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python
from sympy.ntheory.residue_ntheory import sqrt_mod_iter

# ----------------------- Utility ---------------------------------

def int_to_data(num):
	return binascii.unhexlify("%064x" % num)

def data_to_int(num):
	return binascii.hexlify(bytes(num,'utf8'))

def zeropoint_to_data():
	return int_to_data(0) + int_to_data(0)

#TODO: Not sure if this actually works under python2...
def str2bytes(password):
	if not isinstance(password, str): return password
	if sys.version_info < (3, 0):
		return bytes(password)
	else:
		return bytes(password, 'utf8')

def getord(value):
	if isinstance(value, int):
		return value
	else:
		return ord(value)

def HMAC256(pw, data):
	h = HMAC.new(pw, digestmod=SHA256)
	h.update(data)
	return h.digest()

def HMAC224(pw, data):
	h = HMAC.new(pw, digestmod=SHA224)
	h.update(data)
	return h.digest()

# ----------------------- Elliptic Curve Operations ---------------------------------

# This is group 19. Support of it is required by WPA3.
secp256r1_p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
secp256r1_r = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

secp256r1_a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
secp256r1_b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

secp224r1_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
secp224r1_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
secp224r1_a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
secp224r1_b = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4

brainpoolP224r1_p = 0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF
brainpoolP224r1_r = 0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F


def legendre_symbol(a, p):
	"""Compute the Legendre symbol."""
	if a % p == 0: return 0

	ls = pow(a, (p - 1)//2, p)
	return -1 if ls == p - 1 else ls

def point_on_curve(x, y, curve):
	try:
		point = ECC.EccPoint(x, y)
	except ValueError:
		return False
	return True

def point_to_data(p):
	if p is None:
		return zeropoint_to_data()
	return int_to_data(p.x) + int_to_data(p.y)


# ----------------------- WPA3 ---------------------------------

def is_sae(p):
	if not Dot11Auth in p:
		return False
	return p[Dot11Auth].algo == 3

def is_sae_commit(p):
	return is_sae(p) and p[Dot11Auth].seqnum == 1

def is_sae_confirm(p):
	return is_sae(p) and p[Dot11Auth].seqnum == 2

def KDF_Length(data, label, context, length, divisor):
	iterations = int(math.ceil(length / 256.0))
	result, hashFunction = b"", None
	if length == 224 or length==28:
		hashFunction = HMAC224
	else:
		hashFunction = HMAC256
	for i in range(1, iterations + 1):
		hash_data = struct.pack("<H", i) + bytes(label, 'ascii') + context + struct.pack("<H", length)
		result += hashFunction(data, hash_data)
	return result

curve_z = {
	'secp256r1': -10,
	'secp224r1': 31
}

def int_to_bytes(i, length):
	return i.to_bytes(length, byteorder='big')

def bytes_to_int(b):
	return int.from_bytes(b, byteorder='big')


def is_quadratic_residue(a, p):
	return legendre_symbol(a, p) == 1

def modular_sqrt(a, p):
	if legendre_symbol(a, p) != 1:
		return None
	if a == 0:
		return 0
	if p % 4 == 3:
		return pow(a, (p + 1) // 4, p)
	s, e = p - 1, 0
	while s % 2 == 0:
		s //= 2
		e += 1
	n = 2
	while legendre_symbol(n, p) != -1:
		n += 1
	x = pow(a, (s + 1) // 2, p)
	b = pow(a, s, p)
	g = pow(n, s, p)
	r = e
	while True:
		t = b
		m = 0
		for m in range(r):
			if t == 1:
				break
			t = pow(t, 2, p)
		if m == 0:
			return x
		gs = pow(g, 2 ** (r - m - 1), p)
		g = gs * gs % p
		x = x * gs % p
		b = b * g % p
		r = m

def hkdf_extract(salt, ikm, hash_algo=hashlib.sha256):
	return hmac.new(salt, ikm, hash_algo).digest()

def hkdf_expand(prk, info, length, hash_algo=hashlib.sha256):
	hash_len = hash_algo().digest_size
	n = math.ceil(length / hash_len)
	okm = b""
	output_block = b""
	for i in range(1, n + 1):
		output_block = hmac.new(prk, output_block + info + struct.pack('B', i), hash_algo).digest()
		okm += output_block
	return okm[:length]

def ceq(x, y):
	return x == y

def csel(cond, x, y):
	return x if cond else y

def lsb(x):
	return x & 1

def simplified_swu(u, p, a, b, z):
	m = (pow(z, 2, p) * pow(u, 4, p) + z * pow(u, 2, p)) % p
	l = ceq(m, 0)
	t = pow(m, p - 2, p)
	x1 = csel(l, (b * pow(z * a, p - 2, p)) % p, ((-b * (1 + t) * pow(a, p - 2, p)) % p))
	gx1 = (pow(x1, 3, p) + a * x1 + b) % p
	x2 = (z * pow(u, 2, p) * x1) % p
	gx2 = (pow(x2, 3, p) + a * x2 + b) % p
	l = is_quadratic_residue(gx1, p)
	v = csel(l, gx1, gx2)
	x = csel(l, x1, x2)
	y = modular_sqrt(v, p)
	l = ceq(lsb(u), lsb(y))
	return (x, y) if l else (x, p - y)

def hash_to_element(ssid, password, identifier, curve_name):
	curve_params = {
		'secp256r1': (secp256r1_p, secp256r1_a, secp256r1_b),
		'secp224r1': (secp224r1_p, secp224r1_a, secp224r1_b)
	}
	p, a, b = curve_params[curve_name]
	z = curve_z[curve_name]
	ssid_bytes = ssid.encode()
	password_bytes = password.encode()
	if identifier:
		password_bytes += identifier
	pwd_seed = hkdf_extract(ssid_bytes, password_bytes)
	len_ = len(int_to_bytes(p, (p.bit_length() + 7) // 8)) * 3 // 2
	pwd_value1 = hkdf_expand(pwd_seed, b"SAE Hash to Element u1 P1", len_)
	u1 = bytes_to_int(pwd_value1) % p
	P1 = simplified_swu(u1, p, a, b, z)
	pwd_value2 = hkdf_expand(pwd_seed, b"SAE Hash to Element u2 P2", len_)
	u2 = bytes_to_int(pwd_value2) % p
	P2 = simplified_swu(u2, p, a, b, z)
	return ECC.EccPoint(P1[0], P1[1], curve_name) + ECC.EccPoint(P2[0], P2[1], curve_name)

def hash_mac_addresses(mac1, mac2, hash_algo=hashlib.sha256):
	mac1 = binascii.unhexlify(mac1.replace(':', ''))
	mac2 = binascii.unhexlify(mac2.replace(':', ''))
	max_mac = max(mac1, mac2)
	min_mac = min(mac1, mac2)
	hash_input = max_mac + min_mac
	salt = b'\x00' * hash_algo().digest_size
	val = HMAC256(salt, hash_input)
	return int.from_bytes(val, byteorder='big')

def generate_pwe(mac1, mac2, PT, order, hash_algo=hashlib.sha256):
	val = hash_mac_addresses(mac1, mac2)
	val = val % (order - 1) + 1
	PWE = PT * val
	return PWE

# TODO: Also modify to support curve 521
def derive_pwe_ecc(password, addr1, addr2, curve_name):
	curve = ECC._curves[curve_name]
	bits = curve.modulus_bits
	assert bits % 8 == 0

	addr1 = binascii.unhexlify(addr1.replace(':', ''))
	addr2 = binascii.unhexlify(addr2.replace(':', ''))
	hash_pw = addr1 + addr2 if addr1 > addr2 else addr2 + addr1
	for counter in range(1, 100):
		hash_data = str2bytes(password) + struct.pack("<B", counter)
		pwd_seed = HMAC256(hash_pw, hash_data)
		log(DEBUG, "PWD-seed: %s" % pwd_seed)
		if '224' in curve_name:
			pwd_value = KDF_Length(pwd_seed, "SAE Hunting and Pecking", curve.p.to_bytes(bits // 8), bits, 224.0)
		elif '256' in curve_name:
			pwd_value = KDF_Length(pwd_seed, "SAE Hunting and Pecking", curve.p.to_bytes(bits // 8), bits, 256.0)
		log(DEBUG, "PWD-value: %s" % pwd_value)
		pwd_value = int(binascii.hexlify(pwd_value), 16)

		# print(len(str(pwd_value)), "\n", len(str(curve.p)))

		if pwd_value >= curve.p:
			continue
		x = Integer(pwd_value)

		y_sqr = (x**3 - x * 3 + curve.b) % curve.p
		if legendre_symbol(y_sqr, curve.p) != 1:
			continue

		y = y_sqr.sqrt(curve.p)
		y_bit = getord(pwd_seed[-1]) & 1
		if y & 1 == y_bit:
			return ECC.EccPoint(x, y, curve_name)
		else:
			return ECC.EccPoint(x, curve.p - y, curve_name)

# TODO: Use this somewhere???
def calc_k_kck_pmk(pwe, peer_element, peer_scalar, my_rand, my_scalar, curve_name):
	k = ((pwe * peer_scalar + peer_element) * my_rand).x

	keyseed = HMAC256(b"\x00" * 32, int_to_data(k))
	if '256' in curve_name:
		kck_and_pmk = KDF_Length(keyseed, "SAE KCK and PMK",
							 int_to_data((my_scalar + peer_scalar) % secp256r1_r), 512)
	elif '224' in curve_name:
		kck_and_pmk = KDF_Length(keyseed, "SAE KCK and PMK",
							 int_to_data((my_scalar + peer_scalar) % secp224r1_r), 512)
	kck = kck_and_pmk[0:32]
	pmk = kck_and_pmk[32:]

	return k, kck, pmk


def calculate_confirm_hash(kck, send_confirm, scalar, element, peer_scalar, peer_element):
	return HMAC256(kck, struct.pack("<H", send_confirm) + int_to_data(scalar) + point_to_data(element)
						+ int_to_data(peer_scalar) + point_to_data(peer_element))

def build_sae_commit(srcaddr, dstaddr, scalar, element, group_id, token=b'', password_identifier=b'', rejected_groups=b'', status=0):
	p = Dot11(addr1=dstaddr, addr2=srcaddr, addr3=dstaddr)
	p = p/Dot11Auth(algo=3, seqnum=1, status=status)

#	group_id = 19
#	Check if groupid = 27
	scalar_blob = int_to_data(scalar)
	# ("%064x" % scalar).decode("hex")
	try:
		element_blob = int_to_data(element.x) + int_to_data(element.y)
	# ("%064x" % element.x).decode("hex") + ("%064x" % element.y).decode("hex")
		return p/Raw(struct.pack("<H", group_id) + token + scalar_blob + element_blob + password_identifier + rejected_groups)
	except:
		return p/Raw(struct.pack("<H", group_id) + token + scalar_blob + (element).to_bytes(64,"big") + password_identifier + rejected_groups)
	
def fuzzer_build_sae_commit(srcaddr, dstaddr, scalar, element, group_id, token=b'', rejected_groups=b'',status=0):
	p = Dot11Auth(algo=3, seqnum=1, status=status)

#	group_id = 19
#	Check if groupid = 27
	scalar_blob = int_to_data(scalar)
	# ("%064x" % scalar).decode("hex")
	try:
		element_blob = int_to_data(element.x) + int_to_data(element.y)
	# ("%064x" % element.x).decode("hex") + ("%064x" % element.y).decode("hex")
		return p/Raw(struct.pack("<H", group_id) + token + scalar_blob + element_blob + rejected_groups)
	except:
		return p/Raw(struct.pack("<H", group_id) + token + scalar_blob + (element).to_bytes(64,"big") + rejected_groups)
	
def build_sae_confirm(srcaddr, dstaddr, send_confirm, confirm):
	p = Dot11(addr1=dstaddr, addr2=srcaddr, addr3=dstaddr)
	p = p/Dot11Auth(algo=3, seqnum=2, status=0)
	return p/Raw(struct.pack("<H", send_confirm) + confirm)	


class SAEHandshake():
	def __init__(self, password, srcaddr, dstaddr):
		self.password = password
		self.srcaddr = srcaddr
		self.dstaddr = dstaddr

		self.pwe = None
		self.rand = None
		self.scalar = None
		self.element = None
		self.kck = None
		self.pmk = None

	def send_commit(self, curve):
		self.pwe = derive_pwe_ecc(self.password, self.dstaddr, self.srcaddr, curve)

		# After generation of the PWE, each STA shall generate a secret value, rand, and a temporary secret value,
		# mask, each of which shall be chosen randomly such that 1 < rand < r and 1 < mask < r and (rand + mask)
		# mod r is greater than 1, where r is the (prime) order of the group.
		group_id, group_prime, prime_order = 19, secp256r1_p, secp256r1_r
		self.rand = random.randint(0, prime_order - 1)
		mask = random.randint(0, prime_order - 1)

		# commit-scalar = (rand + mask) mod r
		self.scalar = (self.rand + mask) % prime_order
		assert self.scalar > 1

		# COMMIT-ELEMENT = inverse(mask * PWE)
		temp = self.pwe * mask
		self.element = ECC.EccPoint(temp.x, Integer(group_prime) - temp.y)

		auth = build_sae_commit(self.srcaddr, self.dstaddr, self.scalar, self.element, group_id)
		L2Socket(type=ETH_P_ALL, iface='hwsim0').send(RadioTap()/auth)

	def process_commit(self, p):
		payload = str(p[Dot11Auth].payload)

		group_id = struct.unpack("<H", payload[:2])[0]
		pos = 2

		self.peer_scalar = int(payload[pos:pos+32].encode("hex"), 16)
		pos += 32

		peer_element_x = int(payload[pos:pos+32].encode("hex"), 16)
		peer_element_y = int(payload[pos+32:pos+64].encode("hex"), 16)
		self.peer_element = ECC.EccPoint(peer_element_x, peer_element_y)
		pos += 64

		k = ((self.pwe * self.peer_scalar + self.peer_element) * self.rand).x

		keyseed = HMAC256("\x00"*32, int_to_data(k))
		kck_and_pmk = KDF_Length(keyseed, "SAE KCK and PMK",
								 int_to_data((self.scalar + self.peer_scalar) % secp256r1_r), 512)\
									if group_id == 19 else\
										KDF_Length(keyseed, "SAE KCK and PMK",
								 int_to_data((self.scalar + self.peer_scalar) % secp224r1_r), 512)
		self.kck = kck_and_pmk[0:32]
		self.pmk = kck_and_pmk[32:]

		self.send_confirm()

	def send_confirm(self):
		send_confirm = 0
		confirm = calculate_confirm_hash(self.kck, send_confirm, self.scalar, self.element, self.peer_scalar, self.peer_element)

		auth = build_sae_confirm(self.srcaddr, self.dstaddr, send_confirm, confirm)
		sendp(RadioTap()/auth)

	def process_confirm(self, p):
		payload = str(p[Dot11Auth].payload)

		send_confirm = struct.unpack("<H", payload[:2])[0]
		pos = 2

		received_confirm = payload[pos:pos+32]
		pos += 32

		expected_confirm = calculate_confirm_hash(self.kck, send_confirm, self.peer_scalar, self.peer_element, self.scalar, self.element)
		return expected_confirm

# ----------------------- EAP-pwd (TODO Test with Python3) ---------------------------------

def KDF_Length_eappwd(data, label, length):
	num_bytes = (length + 7) // 8
	iterations = (num_bytes + 31) // 32

	# TODO: EAP-pwd uses a different byte ordering for the counter and length?!? WTF!
	result = b""
	for i in range(1, iterations + 1):
		hash_data  = digest if i > 1 else b""
		hash_data += struct.pack(">H", i) + str2bytes(label) + struct.pack(">H", length)
		digest = HMAC256(data, hash_data)
		result += digest

	result = result[:num_bytes]
	if length % 8 != 0:
		num_clear = 8 - (length % 8)
		trailbyte = result[-1] >> num_clear << num_clear
		result = result[:-1] + struct.pack(">B", trailbyte)
	return result


def derive_pwe_ecc_eappwd(password, peer_id, server_id, token, curve_name, info=None):
	curve = ECC._curves[curve_name]
	bits = curve.modulus_bits

	hash_pw = struct.pack(">I", token) + str2bytes(peer_id + server_id + password)
	for counter in range(1, 100):
		hash_data = hash_pw + struct.pack("<B", counter)
		pwd_seed = HMAC256(b"\x00", hash_data)
		log(DEBUG, "PWD-Seed: %s" % pwd_seed)
		pwd_value = KDF_Length_eappwd(pwd_seed, "EAP-pwd Hunting And Pecking", bits)
		log(DEBUG, "PWD-Value: %s" % pwd_value)
		pwd_value = int(binascii.hexlify(pwd_value), 16)

		if bits % 8 != 0:
			pwd_value = pwd_value >> (8 - (521 % 8))

		if pwd_value >= curve.p:
			continue
		x = Integer(pwd_value)

		log(DEBUG, "X-candidate: %x" % x)
		y_sqr = (x**3 - x * 3 + curve.b) % curve.p
		if legendre_symbol(y_sqr, curve.p) != 1:
			continue

		y = y_sqr.sqrt(curve.p)
		y_bit = getord(pwd_seed[-1]) & 1
		if y & 1 == y_bit:
			if not info is None: info["counter"] = counter
			return ECC.EccPoint(x, y, curve_name)
		else:
			if not info is None: info["counter"] = counter
			return ECC.EccPoint(x, curve.p - y, curve_name)


def calculate_confirm_eappwd(k, element1, scalar1, element2, scalar2, group_num=19, rand_func=1, prf=1):
	hash_data  = int_to_data(k)
	hash_data += point_to_data(element1)
	hash_data += int_to_data(scalar1)
	hash_data += point_to_data(element2)
	hash_data += int_to_data(scalar2)
	hash_data += struct.pack(">HBB", group_num, rand_func, prf)
	confirm = HMAC256(b"\x00" * 32, hash_data)
	return confirm

# ----------------------- Fuzzing/Testing ---------------------------------

def inject_sae_auth(srcaddr, bssid):
	p = Dot11(addr1=bssid, addr2=srcaddr, addr3=bssid)
	p = p/Dot11Auth(algo=3, seqnum=1, status=0)

	group_id = 19
	scalar = 0
	element_x = 0
	element_y = 0
	p = p/Raw(struct.pack("<H", group_id))

	if False:
		# Convert to octets
		commit_scalar = ("%064x" % scalar).decode("hex")
		commit_element = ("%064x" % element_x).decode("hex") + ("%064x" % element_y).decode("hex")
		p = p / Raw(commit_scalar + commit_element)
	else:
		p = p / Raw(open("/dev/urandom").read(32*3))
	sendp(RadioTap()/p)

def forge_sae_confirm(bssid, stamac):
	kck = "\x00" * 32
	send_confirm = "\x00\x00"
	confirm = HMAC256(kck, send_confirm + int_to_data(0) + zeropoint_to_data()
						   + int_to_data(0) + zeropoint_to_data())

	auth = Dot11(addr1=bssid, addr2=stamac, addr3=bssid)
	auth = auth/Dot11Auth(algo=3, seqnum=2, status=0)
	auth = auth/Raw(struct.pack("<H", 0) + confirm)

	sendp(RadioTap()/auth)

