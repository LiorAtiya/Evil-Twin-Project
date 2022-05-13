import os

def Change_to_MonitorMode_airmon(iface):
    #Checks which components are working on the wireless network - and kills their processes
    os.system("sudo airmon-ng check kill")
    os.system("sudo airmon-ng start "+ iface)
    os.system("clear")
    os.system("iwconfig")
   
    return iface

def Change_back_airmon(iface):
    os.system("sudo airmon-ng stop "+ iface)
    os.system("sudo systemctl start NetworkManager")
    os.system("clear")
    

def Change_to_MonitorMode(iface):
    os.system('sudo ifconfig %s down' % iface)
    os.system('sudo iwconfig %s mode monitor' % iface)
    os.system('sudo ifconfig %s up' % iface)
    return iface
    

def Change_back(iface):
    os.system("sudo ip link set "+ iface+ " down")
    os.system("sudo iw "+ iface+  " set type managed")
    os.system("sudo ip link set "+ iface+ " up")



