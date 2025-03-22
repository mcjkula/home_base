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
    __version__ = '1.0.2'
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
        home_network = self.options['ssid']
        result = _run('iwconfig wlan0')
        if self.ready == 1 and "Not-Associated" in result:
            for network in access_points:
                if network['hostname'] == home_network:
                    signal_strength = network['rssi']
                    channel = network['channel']
                    _log("FOUND home network nearby on channel %d (rssi: %d)" % (channel, signal_strength))
                    if signal_strength >= self.options['minimum_signal_strength']:
                        _log("Starting association...")
                        self.ready = 0
                        _connect_to_target_network(self, agent, network['hostname'], channel)
                    else:
                        _log("The signal strength is too low (%d) to connect." % (signal_strength))
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
        # Check if we need to restart monitor mode
        if "Not-Associated" in _run('iwconfig wlan0') and "Monitor" not in _run('iwconfig wlan0mon'):
            _restart_monitor_mode(self, agent)

def _run(cmd):
    result = subprocess.run(cmd, shell=True, stdin=None, stderr=None, stdout=subprocess.PIPE, executable="/bin/bash")
    return result.stdout.decode('utf-8').strip()

def _notify_bettercap(command):
    try:
        requests.post(
            "http://127.0.0.1:8081/api/session",
            data=f'{{"cmd":"{command}"}}',
            auth=("pwnagotchi", "pwnagotchi"),
            timeout=5
        )
        _log(f"Sent to bettercap: {command}")
        return True
    except Exception as e:
        _log(f"Error communicating with bettercap: {e}")
        return False

def _connect_to_target_network(self, agent, network_name, channel):
    self.network = network_name
    _log('sending command to Bettercap to stop wifi recon...')
    self.status = 'switching_mon_off'
    
    # First properly disable WiFi in bettercap
    _notify_bettercap("wifi.recon off")
    time.sleep(2)
    _notify_bettercap("set wifi.interface none")
    time.sleep(2)
    
    _log('ensuring all wpa_supplicant processes are terminated...')
    subprocess.run('systemctl stop wpa_supplicant; killall wpa_supplicant', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(5)
    
    # Added interface cleanup
    _log('removing monitor interface...')
    subprocess.run('iw dev wlan0mon del 2>/dev/null', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(2)
    
    _log('disabling monitor mode...')
    subprocess.run('modprobe --remove brcmfmac; modprobe brcmfmac', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(5)
    
    # Verify interface exists before MAC change
    if "wlan0" in _run('iwconfig'):
        _log('randomizing wlan0 MAC address prior to connecting...')
        self.status = 'scrambling_mac'
        subprocess.run('macchanger -A wlan0', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
        time.sleep(5)
        
        # Check interface status
        for _ in range(3):
            if "wlan0" in _run('ifconfig -a'):
                break
            subprocess.run('ifconfig wlan0 up', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
            time.sleep(2)
    
    _log('setting wlan0 channel to match the target...')
    self.status = 'associating'
    subprocess.run('iwconfig wlan0 channel %d' % channel, shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(2)
    
    # Reduced redundant ifconfig calls
    with open('/tmp/wpa_supplicant.conf', 'w') as wpa_supplicant_conf:
        wpa_supplicant_conf.write("ctrl_interface=DIR=/var/run/wpa_supplicant\nupdate_config=1\ncountry=GB\n\nnetwork={\n\tssid=\"%s\"\n\tpsk=\"%s\"\n}\n" % (network_name, self.options['password']))
    
    _log('starting wpa_supplicant...')
    subprocess.run('wpa_supplicant -B -c /tmp/wpa_supplicant.conf -i wlan0', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(5)
    
    _log('requesting IP address...')
    subprocess.run('dhclient -v wlan0', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(5)
    
    self.status = 'associated'
    self.ready = 1
    _log('finished connecting to home wifi')

def _restart_monitor_mode(self, agent):
    _log('resuming wifi recon...')
    _log('stopping wpa_supplicant...')
    subprocess.run('systemctl stop wpa_supplicant; killall wpa_supplicant', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(5)
    
    # Release DHCP lease
    _log('releasing DHCP lease...')
    subprocess.run('dhclient -r wlan0', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(2)
    
    # Remove existing wlan0mon interface if it exists
    _log('cleaning up any existing monitor interfaces...')
    subprocess.run('iw dev wlan0mon del 2>/dev/null', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(2)
    
    # Reload wifi driver
    _log('reloading brcmfmac driver...')
    subprocess.run('modprobe --remove brcmfmac && modprobe brcmfmac', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(5)
    
    _log('randomizing MAC address of wlan0...')
    subprocess.run('macchanger -A wlan0', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(5)
    
    subprocess.run('ifconfig wlan0 up', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(2)
    
    # Create wlan0mon interface
    _log('creating wlan0mon interface...')
    subprocess.run('iw phy "$(iw phy | head -1 | cut -d" " -f2)" interface add wlan0mon type monitor && ifconfig wlan0mon up', 
                  shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(5)
    
    # Tell bettercap to use wlan0mon
    _log('telling Bettercap to use wlan0mon interface...')
    _notify_bettercap("set wifi.interface wlan0mon")
    time.sleep(2)
    
    # Restart wifi recon
    _log('telling Bettercap to resume wifi recon...')
    _notify_bettercap("wifi.recon on")
    time.sleep(2)
    
    agent.next_epoch(self)

def _log(message):
    logging.info('[home_base] %s' % message)
