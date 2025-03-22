# home-base watches for a pre-defined home network to be in range, then pauses pwning to
# allow for internet connectivity tasks to be carried out. Once out of range, pwning is resumed
# Inspiration and some methodologies taken from @nagy_craig's "Educational-purposes-only" plugin
# Install dependencies: apt update; apt install nmap macchanger
import pwnagotchi.plugins as plugins
import pwnagotchi
import logging
import subprocess
import time

class HomeBase(plugins.Plugin):
    __author__ = '@troystauffer'
    __version__ = '1.0.2'
    __license__ = 'GPL3'
    __description__ = 'Connects to home network for internet when available'

    def __init__(self):
        self.ready = 0
        self.status = ''
        self.network = ''
        self.connected = False

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
        
        if agent.mode == 'auto' and self.ready == 1 and "Not-Associated" in result:
            for network in access_points:
                if network['hostname'] == home_network:
                    signal_strength = network['rssi']
                    channel = network['channel']
                    _log("FOUND home network nearby on channel %d (rssi: %d)" % (channel, signal_strength))
                    if signal_strength >= self.options['minimum_signal_strength']:
                        _log("Starting transition to MANUAL mode...")
                        display = agent.view()
                        display.set('status', f"Home network found! Switching to MANUAL...")
                        display.set('face', '(◕‿‿◕)')
                        display.update(force=True)
                        time.sleep(1)
                        pwnagotchi.reboot(mode="MANU")
                        return
                    else:
                        _log("The signal strength is too low (%d) to connect." % (signal_strength))
                        self.status = 'rssi_low'
                        self.network = home_network
        
        elif agent.mode == 'manual':
            home_found = False
            for network in access_points:
                if network['hostname'] == home_network:
                    home_found = True
                    signal_strength = network['rssi']
                    channel = network['channel']
                    
                    if signal_strength >= self.options['minimum_signal_strength'] and not self.connected:
                        _log("Home network in range with good signal, connecting...")
                        self.ready = 0
                        _connect_to_target_network(self, agent, network['hostname'], channel)
                    break
            
            if not home_found and "Not-Associated" in result:
                _log("Home network no longer in range, switching back to AUTO mode")
                display = agent.view()
                display.set('status', "Going back to hunting mode...")
                display.set('face', '(¬‿¬)')
                display.update(force=True)
                time.sleep(1)
                pwnagotchi.reboot(mode="AUTO")

    def on_manual_mode(self, agent):
        _log("Device in MANUAL mode - will look for home network")
        self.connected = False

    def on_ui_update(self, ui):
        if self.status == 'rssi_low':
            ui.set('face', '(ﺏ__ﺏ)')
            ui.set('status', 'Signal strength of %s is currently too low to connect ...' % self.network)
        elif self.status == 'home_detected':
            ui.set('face', '(◕‿‿◕)')
            ui.set('status', 'Found home network at %s ...' % self.network)
        elif self.status == 'switching_mon_off':
            ui.set('face', '(◕‿‿◕)')
            ui.set('status', 'We\'re home! Pausing monitor mode ...')
        elif self.status == 'scrambling_mac':
            ui.set('face', '(⌐■_■)')
            ui.set('status', 'Scrambling MAC address before connecting to %s ...' % self.network)
        elif self.status == 'associating':
            ui.set('status', 'Greeting the AP and asking for an IP via DHCP ...')
            ui.set('face', '(◕‿◕ )')
        elif self.status == 'associated':
            ui.set('face', '(ᵔ◡◡ᵔ)')
            ui.set('status', 'Home at last!')

    def on_epoch(self, agent, epoch, epoch_data):
        if agent.mode == 'manual' and self.connected and "Not-Associated" in _run('iwconfig wlan0'):
            _log("Lost connection to home network, will check if still in range next scan")
            self.connected = False

def _run(cmd):
    result = subprocess.run(cmd, shell=True, stdin=None, stderr=None, stdout=subprocess.PIPE, executable="/bin/bash")
    return result.stdout.decode('utf-8').strip()

def _connect_to_target_network(self, agent, network_name, channel):
    self.network = network_name
    _log('sending command to Bettercap to stop using wlan0mon...')
    self.status = 'switching_mon_off'
    try:
        agent.run('wifi.recon off')
    except Exception as e:
        _log(f"Error stopping recon: {str(e)}")
    
    _log('ensuring all wpa_supplicant processes are terminated...')
    subprocess.run('systemctl stop wpa_supplicant; killall wpa_supplicant', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(5)
    
    _log('removing monitor interface...')
    subprocess.run('iw dev wlan0mon del 2>/dev/null', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    
    _log('disabling monitor mode...')
    subprocess.run('modprobe --remove brcmfmac; modprobe brcmfmac', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(3)
    
    if "wlan0" in _run('iwconfig'):
        _log('randomizing wlan0 MAC address prior to connecting...')
        self.status = 'scrambling_mac'
        subprocess.run('macchanger -A wlan0', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
        time.sleep(2)
        
        for _ in range(3):
            if "wlan0" in _run('ifconfig -a'):
                break
            subprocess.run('ifconfig wlan0 up', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
            time.sleep(2)
    
    _log('setting wlan0 channel to match the target...')
    self.status = 'associating'
    subprocess.run('iwconfig wlan0 channel %d' % channel, shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(2)
    
    with open('/tmp/wpa_supplicant.conf', 'w') as wpa_supplicant_conf:
        wpa_supplicant_conf.write("ctrl_interface=DIR=/var/run/wpa_supplicant\nupdate_config=1\ncountry=DE\n\nnetwork={\n\tssid=\"%s\"\n\tpsk=\"%s\"\n}\n" % (network_name, self.options['password']))
    
    _log('starting wpa_supplicant...')
    subprocess.run('wpa_supplicant -B -c /tmp/wpa_supplicant.conf -i wlan0', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(5)
    
    _log('requesting IP address...')
    subprocess.run('dhclient -v wlan0', shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None, executable="/bin/bash")
    time.sleep(3)
    
    if "inet" in _run('ifconfig wlan0'):
        self.status = 'associated'
        self.connected = True
        _log('successfully connected to home wifi')
    else:
        _log('failed to get IP address')
    
    self.status = 'associated'
    self.ready = 1

def _log(message):
    logging.info('[home_base] %s' % message)
