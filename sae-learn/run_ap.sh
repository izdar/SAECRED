sudo modprobe mac80211_hwsim radios=4;
sudo ifconfig wlan0 down;
sudo iw wlan0 set type monitor;
sudo ifconfig wlan0 up;
sudo iw wlan0 set channel 6;
sudo ifconfig wlan1 down;
sudo iw wlan1 set type monitor;
sudo iw wlan1 set monitor active;
sudo ifconfig wlan1 up;
sudo iw wlan1 set channel 6;
sudo ifconfig wlan2 down;
sudo iw wlan2 set type monitor;
sudo ifconfig wlan2 up;
sudo iw wlan2 set channel 6;
sudo ifconfig hwsim0 up;
sudo ifconfig wlan3 down;
sudo iw wlan3 set type monitor;
sudo iw wlan3 set monitor active;
sudo ifconfig wlan3 up;
sudo iw wlan3 set channel 6;

