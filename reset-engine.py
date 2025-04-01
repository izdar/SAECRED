import os
import time
from ResetHandler import *

PAUSE_FILE = "./reset-lock/pause_signal"  # File used for signaling pause/resume
NUM_WORKERS = 1  # Adjust this number to the number of worker scripts
# DEVICES = ["Tp-Link_0C78", "Verizon", "ASUS-TUF", "Tp-Link_CD7A", "ASUS-1800S"]
DEVICES = ["macbook"]
# MACS = ["ac:91:9b:f3:19:6d", "c8:7f:54:24:a0:7c", "98:25:4a:fa:cd:7a", "5c:62:8b:0d:0c:77", "e8:9c:25:b8:1e:18"]
MACS = ["ea:6a:0e:c6:e8:86"]
MAC_FILTER = "not (wlan dst ff:ff:ff:ff:ff:ff or wlan dst 00:00:00:00:00:00) and (" + " or ".join(f"wlan src {mac} or wlan dst {mac}" for mac in MACS) + ")"
def get_worker_pause_files():
    """Returns a list of worker pause files based on their PIDs."""
    return ["./reset-lock/worker_%s_paused" % device for device in DEVICES]

def all_workers_paused():
    """Check if all worker pause files exist."""
    pause_files = get_worker_pause_files()
    return all(os.path.exists(f) for f in pause_files)

def pause_workers():
    """Creates the pause signal to stop all AP testing."""
    print("Pausing workers...")
    with open(PAUSE_FILE, 'w') as f:
        f.write("pause")
    
    # Wait until all workers have paused
    print("Waiting for all workers to pause...")
    while not all_workers_paused():
        time.sleep(1)  # Check every second

    print("All workers are paused.")

def reset_aps():
    """Resets the APs through your custom reset functions."""
    print("Resetting APs...")
    # Call your AP reset functions here
    try:
        subprocess.run("sudo rm /etc/NetworkManager/system-connections/*", shell=True)
    except:
        pass
    subprocess.check_output(["sudo", "service","NetworkManager","start"])
    time.sleep(5)
    while not reset_ASUS1800S():
        pass
    while not reset_ASUSTUF():
        pass
    while not reset_TPLink0C78():
        pass
    while not reset_TPLinkCD7A():
        pass
    while not reset_Verizon():
        pass
    # while not reset_eero():
    #     pass
    subprocess.check_output(["sudo", "airmon-ng", "check", "kill"])
    time.sleep(100)  # Simulate the AP reset time
    
    print("APs reset successfully.")

def resume_workers():
    """Removes the pause signal to allow workers to continue."""
    print("Resuming workers...")
    os.remove(PAUSE_FILE)

def start_virtual_interface(iface, viface):
	cmd = ["sudo", "iw", iface, "interface", "add", viface, "type", "monitor"]
	subprocess.check_output(cmd)
	subprocess.check_output(["sudo", "ifconfig", viface, "up"])

if __name__ == "__main__":
    try:
        # start_virtual_interface("wlx00873f3f3e7b", "wlan1")
        # count = 64
        while True:
            # tshark_command = [
            #     'tshark', '-i', 'wlan1', 
            #     '-f', MAC_FILTER,  # Use -f for capture filter instead of -Y
            #     '-w', 'analysis-traces/capture_%d.pcap' % count, 
            #     '-a', 'duration:3600'  # Automatically stop after 3600 seconds
            # ]
            pause_workers()
            # reset_aps()      
            resume_workers()
            time.sleep(5)
            # while True:
            #     try:
            #         subprocess.check_output(tshark_command)
            #         break
            #     except:
            #         time.sleep(1)
            # count += 1
            time.sleep(3600)
    except KeyboardInterrupt:
        pass