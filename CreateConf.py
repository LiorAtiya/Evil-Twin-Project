import os 

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