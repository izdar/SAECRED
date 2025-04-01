import json

def mac_to_int(mac):
    """
    Convert MAC address to an integer.
    
    :param mac: str, MAC address in format '00:00:00:00:00:00'
    :return: int, Integer representation of the MAC address
    """
    return int(mac.replace(':', ''), 16)

def int_to_mac(integer):
    """
    Convert an integer to a MAC address.
    
    :param integer: int, Integer representation of the MAC address
    :return: str, MAC address in format '00:00:00:00:00:00'
    """
    return ':'.join(format((integer >> i) & 0xff, '02x') for i in (40, 32, 24, 16, 8, 0))

src = "00:1c:50:0e:46:30"

all_dst = ["e8:9c:25:b8:1e:18","5c:62:8b:0d:0c:77","98:25:4a:fa:cd:7a","c8:7f:54:24:a0:7c","ac:91:9b:f3:19:6d","c8:e3:06:90:3a:e6"]

dummy_src = "9c:00:ff:ff:ff:00"
dummy_list = [dummy_src[:-1] + str(i) for i in range(10)]

src_list_init = [int_to_mac(mac_to_int(src) + i) for i in range(10000000)]
src_list = list(filter(lambda x: x not in all_dst and x not in dummy_list, src_list_init))

with open("precomputed-macs.json", "w") as f:
    json.dump(src_list, f)