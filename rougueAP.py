import sys, os, multiprocessing
import netifaces
import time
import logging
logging.getLogger("kamene.runtime").setLevel(logging.ERROR)
import argparse
from kamene.all import (Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, 
hexdump, RandMAC)
from threading import Thread
import re


def main():
    iface = Iface()
    MultiBeacons = SendMultiBeacons(iface.ifaceName)
    
    
    
    
    #AP = CreateBeacon(iface.tgt_SSID, iface.ifaceName)

def prompt(prompt, default=None):
    if default is not None:
        return input(f'{prompt} (default: {default}): ') or default
    else:
        return input(f'{prompt}: ') 
    
def printNL():
    print('\n') 


class Iface:
    def __init__(self):
        self.ifaces = {}
        self.ifaceName = None
        self.ifaceName = None
        self.tgt_SSID = None
        self.ifaceSelection()
        self.SetIfaceName()
        self.checkMode()
        self.checkScanWnetworks()
        
    def ifaceSelection(self):
        cut = r"tr -d ' '"
        ifaces = {}
        count = 1
        selection_options = ''
        for x, y in zip(
                os.popen(
                    f'sudo iw dev | grep \'Interface\' |'
                    f'cut -d \' \' -f 2 | {cut}'
                    ).read().split(' '),
        
                os.popen(
                    f'sudo iw dev | grep \'type\' |'
                    f'cut -d \' \' -f 2 | {cut}'
                    ).read().split(' '),
            ):  
                if x and y:
                    name = x.strip('\n')
                    mode = y.strip('\n')
                    self.ifaces[str(count)] = {'name': name, 'mode': mode}
                    selection_options += (f' {count}. {name}   mode: {mode}\n' )
                    count +=1
                else:
                    print('No available interfaces. Exiting')
                    sys.exit(0)
        
        print("[i] Available wireless interfaces: ")
        print(selection_options)
        
    def SetIfaceName(self):
        while True:
            try:
                entry = prompt("[-] Enter selection: " ) or '1'
                if entry in self.ifaces.keys():
                    self.iface = self.ifaces[entry]
                    self.ifaceName = self.iface['name']
                    break
                else:
                    print(f'[!] Invalid entry \'{entry}\'. Try again')
                    continue
            except OSError as err:
                print(err)
                sys.exit(0)
            except KeyboardInterrupt:
                print("Exiting...")
    def checkMode(self):
        if self.iface['mode'] == 'monitor':
            pass
        
        else:
            print(f'[!] Interface not in monitor mode')
            entry = prompt('[?] Run airmon-ng? (y=yes, n=no )', 'n')
            while True:
                try:
                    if entry in ['y', 'n', 'Y', 'N']:
                        if entry in ['y', 'Y']:
                            os.system(f'sudo airmon-ng start {self.ifaceName}')
                            os.system('clear')
                            self.ifaceSelection()       
                            self.SetIfaceName()
                            break
                            
                        else:
                            print('Interface not in monitor mode needed to continue.\n Exiting...')
                            sys.exit(0)
                        
                    else:
                        print(f'[!] Invalid entry \'{entry}\'. Try again')
                        continue

                except OSError as err:
                    print(err)
                    sys.exit(0)
                    
                except KeyboardInterrupt:
                    sys.exit(0)
        print(f'[*] Selected interface: {self.ifaceName}')

    def checkScanWnetworks(self):
        entry = prompt('[?] Scan for wireless networks? (y=yes, n=no )', 'n')
        while True:
            try:
                if entry in ['y', 'n', 'Y', 'N']:
                    self.scanWnetworks() if entry in ['y', 'Y'] else ('' if entry in ['n', 'N'] else '')
                    break
                
                else:
                    print(f'[!] Invalid entry \'{entry}\'. Try again')
                    continue
            except OSError as err:
                print(err)
                sys.exit(0)
        os.system('clear')
    def scanWnetworks(self):
        os.system(
                'x-terminal-emulator --new-tab --unhide --no-dbus --command \' '
                f'airodump-ng {self.ifaceName} --band abg \' 2> /dev/null '
                '& sleep 3 2> /dev/null '
                '&& kill \"$!\"1> /dev/null 2> /dev/null'
                )
        printNL()
               
class CreateBeacon:
    def __init__(self, ifaceName, tgt_SSID):
        self.infinite = True
        self.ifaceName=ifaceName
        self.sender_mac = str(RandMAC())
        self.tgt_SSID=tgt_SSID
        self.num_APs = None

        self.dot11 = Dot11(
                    type=0, 
                    subtype=8,
                    addr1="ff:ff:ff:ff:ff:ff", 
                    addr2=self.sender_mac, 
                    addr3=self.sender_mac
                    )
        self.beacon = Dot11Beacon(cap="ESS")
        
        self.eSSIDs = Dot11Elt(
                    ID="SSID", 
                    info=self.tgt_SSID, 
                    len=len(self.tgt_SSID))
        self.rsn = Dot11Elt(
                    ID='RSNinfo', info=(
                    '\x01\x00'
                    '\x00\x0f\xac\x02'
                    '\x02\x00'
                    '\x00\x0f\xac\x04'
                    '\x00\x0f\xac\x02'
                    '\x01\x00'
                    '\x00\x0f\xac\x02'
                    '\x00\x00'
                    ))
        self.frame = RadioTap(present=0)/self.dot11/self.beacon/self.eSSIDs/self.rsn
    
    
        
    def sendBeacon(self):
        sendp(self.frame, inter=0.050, iface=self.ifaceName, loop=1, verbose=0)
                 
class SendMultiBeacons:
    def __init__(self, ifaceName):
        self.SSIDs = []
        self.ifaceName = ifaceName
        self.getSSID_list()
        self.send()
        
    def getSSID_list(self):
        while True:
            num_APs = prompt('[*] Enter number of APs to create: (1-10) (1) ', '1')
            if num_APs.isdigit():
                if int(num_APs) > 0 <= 10:
                    break
                else:
                    continue
            else:
                continue
            
        os.system('clear')
        default = 1
        created_SSIDs = ''
        SSIDs = []
        for i in range(int(num_APs)):
            i+=1
            default_SSID = f'FreeWifi{default}'
            SSID = input(f'[i] Enter SSID 4-28 characters long for AP {i}: (default: {default_SSID}):\n ')
            if SSID == '':
                SSID = default_SSID
                default += 1
                
            if len(SSID) > 28:
                print(f"SSIDs Must be 4-28 characters. Defaulted to {SSIDs[:28]} ")
                SSID = SSIDs[:28]   
                
            SSIDs.append(SSID)     
            print(f'[i] Ap SSID \'{SSID}\' created')
            created_SSIDs += f'{i}.{SSID}   '
            os.system('clear')
            print(f'Created SSIDs: {created_SSIDs}  ')
            
        self.SSIDs = tuple(SSIDs)
        time.sleep(2)
        
    def send(self):
        for idx, element in enumerate(self.SSIDs):
            Beacon = CreateBeacon(self.ifaceName, element)
            print(f'\n[i] Creating beacons for {element}...\n')
            time.sleep(2)

            for i in range(3):  
                try:
                    print(f'[i] Sending beacon {i+1}...\n')
                    i = multiprocessing.Process(target=Beacon.sendBeacon)
                    i.start()
                except KeyboardInterrupt:
                    time.sleep(1)
                    printNL()
                    print('processes stopped')
                    sys.exit(0)
                    
        printNL()
        print('Sending Packects...')
        while True:
            try:
                sys.stdout.write(".")
                sys.stdout.flush()
                time.sleep(1)
            except KeyboardInterrupt:
                printNL()
                print('processes stopped')
                sys.exit(0)
            

        
        
if __name__ == "__main__":
    main()