SUT="hostapd"
BYTES_PARSED = '../WiFiPacketGen/sync/driver_oracle.json'
FUZZING = True
HOSTAP_TEST = True

PAUSE_FILE = "../../reset-lock/pause_signal" 
WORKER_PAUSE_FILE = "../../reset-lock/worker_%s_paused" % SUT

CHECK_INTERVAL = 5 

IFACE_RESTART_TIMER = 0


COMMIT = "COMMIT"
CONFIRM = "CONFIRM"
COMMIT_TOKEN_REQUIRED = "COMMIT_TOKEN_REQUIRED"
ASSOCIATION_REQUEST = "ASSOCIATION_REQUEST"
DEAUTHENTICATION = "DEAUTHENTICATION"

iface="wlan0"


src = ""
phy = ""
dst = ""
ssid = ""

if not HOSTAP_TEST:
    src = "00:1c:50:0e:46:30"
    phy = "wlx001c500e4630"
else:
# hostapd
    src = "02:00:00:00:01:00"

if SUT == "eero":
    # eero 6
    dst = "c8:e3:06:90:3a:e6"
    ssid = "pirwani"

if SUT == "Verizon":
    # Verizon MAC
    dst = "ac:91:9b:f3:19:6d"
    ssid = "pirwani-verizon"

if SUT == "ASUS-TUF":
    # ASUS-TUF MAC
    dst = "c8:7f:54:24:a0:7c"
    ssid = "pirwani-ASUS-TUF"

if SUT == "Tp-Link_CD7A":
    # TP-link CD7A
    dst = "98:25:4a:fa:cd:7a"
    ssid = "pirwani-TP-Link_CD7A"

if SUT == "Tp-Link_0C78":
    # TP-Link 0C78
    dst = "5c:62:8b:0d:0c:77"
    ssid = "Pirwani-TP-Link_0C78"

if SUT == "ASUS-1800S":
    # ASUS-1800S
    dst = "e8:9c:25:b8:1e:18"
    ssid = "Pirwani-ASUS-1800S"

if SUT == 'hostapd':
    dst = "02:00:00:00:02:00"
    ssid = "pirwani"


dummy_src = "9c:00:ff:ff:ff:00"
dummy_list = [dummy_src[:-1] + str(i) for i in range(10)]
src_iterator = 1
src_list_init = [int_to_mac(mac_to_int(src) + i) for i in range(10000000)]
src_list = list(filter(lambda x: x != dst and x not in dummy_list, src_list_init))
import json
src_list = json.load(open("precomputed-macs.json", "r"))
del src_list_init

AC_TRIGGER_COUNT = 10

TRANSMISSIONS = 2
TIMEOUT = 1
ACK_TIMEOUT = 1

SULConfig = {
    "ssid": ssid,
    "password": "correctPassword"
}
