sudo modprobe mac80211_hwsim radios=10;
sudo ifconfig wlan0 down;
sudo iw wlan0 set type monitor;
sudo ifconfig wlan0 up;
sudo iw wlan0 set channel 1;
sudo ifconfig wlan1 down;
sudo iw wlan1 set type monitor;
sudo ifconfig wlan1 up;
sudo iw wlan1 set channel 1;
sudo ifconfig wlan2 down;
sudo iw wlan2 set type monitor;
sudo ifconfig wlan2 up;
sudo iw wlan2 set channel 2;
sudo ifconfig wlan3 down;
sudo iw wlan3 set type monitor;
sudo ifconfig wlan3 up;
sudo iw wlan3 set channel 2;
sudo ifconfig wlan4 down;
sudo iw wlan4 set type monitor;
sudo ifconfig wlan4 up;
sudo iw wlan4 set channel 3;
sudo ifconfig wlan5 down;
sudo iw wlan5 set type monitor;
sudo ifconfig wlan5 up;
sudo iw wlan5 set channel 3;
sudo ifconfig wlan6 down;
sudo iw wlan6 set type monitor;
sudo ifconfig wlan6 up;
sudo iw wlan6 set channel 4;
sudo ifconfig wlan7 down;
sudo iw wlan7 set type monitor;
sudo ifconfig wlan7 up;
sudo iw wlan7 set channel 4;
sudo ifconfig wlan8 down;
sudo iw wlan8 set type monitor;
sudo ifconfig wlan8 up;
sudo iw wlan8 set channel 5;
sudo ifconfig wlan9 down;
sudo iw wlan9 set type monitor;
sudo ifconfig wlan9 up;
sudo iw wlan9 set channel 5;
sudo ifconfig hwsim0 up;

