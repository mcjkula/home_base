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
    __version__ = '1.0.4'
    __license__ = 'GPL3'
    __description__ = 'Connects to home network for internet when available'

    def __init__(self):
        self.ready = 0
        self.status = ''
        self.network = ''

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
        while self.status == 'rssi_low':
            ui.set('face', '(ﺏ__ﺏ)')
            ui.set('status', 'Signal strength of %s is currently too low to connect ...' % self.network)
        while self.status == 'home_detected':
            ui.set('face', '(◕‿‿◕)')
            ui.set('face', '(ᵔ◡◡ᵔ)')
            ui.set('status', 'Found home network at %s ...' % self.network)
        while self.status == 'switching_mon_off':
            ui.set('face', '(◕‿‿◕)')
            ui.set('face', '(ᵔ◡◡ᵔ)')
            ui.set('status', 'We\'re home! Pausing monitor mode ...')
        while self.status == 'scrambling_mac':
            ui.set('face', '(⌐■_■)')
            ui.set('status', 'Scrambling MAC address before connecting to %s ...' % self.network)
        while self.status == 'associating':
            ui.set('status', 'Greeting the AP and asking for an IP via DHCP ...')
            ui.set('face', '(◕‿◕ )')
            ui.set('face', '( ◕‿◕)')
        if self.status == 'associated':
            ui.set('face', '(ᵔ◡◡ᵔ)')
            ui.set('status', 'Home at last!')

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
    
    # Disable WiFi recon but keep bettercap running
    _log("Disabling WiFi monitoring")
    agent.run('wifi.recon off')
    time.sleep(2)
    
    # Use empty string instead of null/none
    agent.run('set wifi.interface ""')
    time.sleep(2)
    
    # Kill wpa_supplicant and dhclient but leave bettercap running
    _log('Stopping network services...')
    subprocess.run('killall wpa_supplicant dhclient', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    
    # Manually remove monitor interface
    _log('Removing monitor interface...')
    subprocess.run('iw dev wlan0mon del 2>/dev/null', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    
    # Bring up wlan0 in managed mode
    _log('Setting up managed interface...')
    self.status = 'scrambling_mac'
    
    # Make sure wlan0 is up
    subprocess.run('ifconfig wlan0 up', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    
    # MAC randomization
    subprocess.run('macchanger -A wlan0', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    
    # Connection setup
    self.status = 'associating'
    _log(f'Connecting to {network_name} on channel {channel}...')
    
    with open('/tmp/wpa_supplicant.conf', 'w') as f:
        f.write(f'ctrl_interface=DIR=/var/run/wpa_supplicant\nupdate_config=1\ncountry=GB\n\nnetwork={{\n\tssid="{network_name}"\n\tpsk="{self.options["password"]}"\n}}\n')
    
    subprocess.run('wpa_supplicant -B -c /tmp/wpa_supplicant.conf -i wlan0', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    
    # Get IP address
    subprocess.run('dhclient wlan0', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    
    # Verify connection
    if "Not-Associated" not in _run('iwconfig wlan0'):
        _log("Successfully connected to home network")
        self.status = 'associated'
        self.ready = 1
    else:
        _log("Failed to connect - will retry later")
        self.ready = 1

def _restart_monitor_mode(self, agent):
    _log("Restoring monitoring capabilities")
    
    # Release network connection
    subprocess.run('killall wpa_supplicant dhclient', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('dhclient -r wlan0', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    
    # Create monitor interface
    _log('Creating monitor interface...')
    subprocess.run('iw dev wlan0mon del 2>/dev/null', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    subprocess.run('iw phy $(iw phy | head -1 | cut -d" " -f2) interface add wlan0mon type monitor', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('ifconfig wlan0mon up', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    
    # Tell bettercap to use wlan0mon without restarting service
    _log('Reconfiguring bettercap...')
    agent.run('set wifi.interface wlan0mon')
    time.sleep(2)
    agent.run('wifi.recon on')
    time.sleep(1)
    
    agent.next_epoch(self)
    _log("Monitoring mode restored")

def _log(message):
    logging.info(f'[home_base] {message}')
