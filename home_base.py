# home-base watches for a pre-defined home network to be in range, then pauses pwning to
# allow for internet connectivity tasks to be carried out. Once out of range, pwning is resumed
# Inspiration and some methodologies taken from @nagy_craig's "Educational-purposes-only" plugin
# Install dependencies: apt update; apt install nmap macchanger
import pwnagotchi.plugins as plugins
import pwnagotchi
import logging
import subprocess
import time
import requests

class HomeBase(plugins.Plugin):
    __author__ = '@troystauffer'
    __version__ = '1.0.3'
    __license__ = 'GPL3'
    __description__ = 'Connects to home network for internet when available'

    def __init__(self):
        self.ready = 0
        self.status = ''
        self.network = ''
        self.original_interface = 'wlan0mon'

    def on_loaded(self):
        for opt in ['ssid', 'password', 'minimum_signal_strength']:
            if opt not in self.options or (opt in self.options and self.options[opt] is None):
                logging.error(f"[home_base] Option {opt} is not set.")
                return
        _log("plugin loaded")
        self.ready = 1

    def on_unfiltered_ap_list(self, agent, access_points):
        if self.ready != 1:
            return
            
        home_network = self.options['ssid']
        result = _run('iwconfig wlan0')
        if "Not-Associated" in result:
            for network in access_points:
                if network['hostname'] == home_network:
                    signal_strength = network['rssi']
                    channel = network['channel']
                    _log(f"FOUND home network on channel {channel} (rssi: {signal_strength})")
                    
                    if signal_strength >= self.options['minimum_signal_strength']:
                        _log("Starting association...")
                        self.ready = 0
                        _connect_to_target_network(self, agent, network['hostname'], channel)
                    else:
                        _log(f"Signal strength too low: {signal_strength}dB")
                        self.status = 'rssi_low'

    def on_ui_update(self, ui):
        pass

    def on_epoch(self, agent, epoch, epoch_data):
        if "Not-Associated" in _run('iwconfig wlan0') and "Monitor" not in _run('iwconfig wlan0mon'):
            _restart_monitor_mode(self, agent)

def _run(cmd):
    result = subprocess.run(cmd, shell=True, stdin=None, stderr=None, stdout=subprocess.PIPE, executable="/bin/bash")
    return result.stdout.decode('utf-8').strip()

def _notify_bettercap(command):
    try:
        response = requests.post(
            "http://127.0.0.1:8081/api/session",
            json={"cmd": command},
            auth=("pwnagotchi", "pwnagotchi"),
            timeout=10
        )
        if response.status_code == 200:
            _log(f"Bettercap command succeeded: {command}")
            return True
        else:
            _log(f"Bettercap error ({response.status_code}): {response.text}")
            return False
    except Exception as e:
        _log(f"Bettercap communication failed: {str(e)}")
        return False

def _connect_to_target_network(self, agent, network_name, channel):
    self.network = network_name
    self.status = 'switching_mon_off'
    
    _notify_bettercap("wifi.recon off")
    _notify_bettercap("set wifi.interface null")
    _notify_bettercap("module off wifi")
    time.sleep(5)
    
    subprocess.run('systemctl stop bettercap', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('killall wpa_supplicant dhclient', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('iw dev wlan0mon del', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('modprobe -r brcmfmac', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    subprocess.run('modprobe brcmfmac', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)
    
    for _ in range(3):
        subprocess.run('macchanger -A wlan0', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        if "00:00:00" not in _run('ifconfig wlan0 | grep HWaddr'):
            break
            
    with open('/tmp/wpa_supplicant.conf', 'w') as f:
        f.write(f'ctrl_interface=DIR=/var/run/wpa_supplicant\nupdate_config=1\ncountry=DE\n\nnetwork={{\n\tssid="{network_name}"\n\tpsk="{self.options["password"]}"\n}}\n')
    
    subprocess.run('wpa_supplicant -B -c /tmp/wpa_supplicant.conf -i wlan0', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)
    subprocess.run('dhclient -v wlan0', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    self.status = 'associated'
    self.ready = 1
    _log("Successfully connected to home network")

def _restart_monitor_mode(self, agent):
    _log("Restoring monitoring capabilities")
    
    subprocess.run('systemctl stop bettercap', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('killall wpa_supplicant dhclient', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('iw dev wlan0mon del', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('modprobe -r brcmfmac', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    subprocess.run('modprobe brcmfmac', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)
    
    subprocess.run('iw phy $(iw phy | head -1 | cut -d" " -f2) interface add wlan0mon type monitor', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('ifconfig wlan0mon up', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    
    subprocess.run('systemctl start bettercap', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(10)
    
    for _ in range(3):
        if _notify_bettercap("set wifi.interface wlan0mon") and \
           _notify_bettercap("wifi.recon on") and \
           _notify_bettercap("module restart wifi"):
            break
        time.sleep(5)
    
    agent.next_epoch(self)
    _log("Monitoring mode fully restored")

def _log(message):
    logging.info(f'[home_base] {message}')
