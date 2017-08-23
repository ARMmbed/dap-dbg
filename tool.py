"""
Debugging tool for using USBPcap when developing CMSIS-DAP devices.
"""
from __future__ import print_function

import sys
import time
import struct
import subprocess

from packet_usbpcap import USB
import cmsis_dap

from pipe import FIFOServer

def decode_extcap(output):
    for line in output.split('\n'):
        split = line.find(' ')

        entry = line[:split]
        if_raw = line[split+1:]

        yield entry, dict([
            tuple(pair.strip('{}').split('=', 1)) for pair in if_raw.split('}{')
        ])

def get_interfaces():
    raw = run_usbpcap("--extcap-interfaces")

    return (_if for t, _if in decode_extcap(raw) if t == 'interface')

def choose_interface():
    """
    Prompt the user to choose a USBPcap interface to use.

    TODO: provide details of which devices exist on each interface.
    """
    # find out possible interfaces to listen on
    print('--- CHOOSE A CAPTURE INTERFACE (1) ---')
    choices = list(get_interfaces())

    for i, interface in enumerate(choices):
        print('[%d] %s' % (i + 1, interface['display']))

    choice_ix = int(input("> ")) - 1
    choice = choices[choice_ix]

    check_interface(choice['value'])

    return choice

def check_interface(interface):
    """
    Call `USBPcapCMD.exe --extcap-interface IFACE --extcap-dlts` to query its
    data format
    """
    raw = run_usbpcap("--extcap-interface", interface, "--extcap-dlts")
    result = decode_extcap(raw)

    rows = list(data for type, data in result if type == 'dlt')

    if len(rows) != 1:
        raise RuntimeError("Too many DLTs returned.")
    
    dlt = rows[0]

    if int(dlt['number']) != 249:
        raise RuntimeError("Data format must be USBPcap (249)")

class DeviceNode:
    def __init__(self, name, children=[]):
        self.name = name
        self.children = children

        # Having children isn't necessary to be a root node.
        self.root = False
    
    def __repr__(self):
        if len(self.children) > 0:
            return '%s, [%s]' % (self.name, ', '.join(repr(x) for x in self.children))
        else:
            return self.name

def get_device_tree(interface):
    """
    Build a USB device tree from USBPcap.
    """
    raw = run_usbpcap('--extcap-interface', interface, '--extcap-config', '--devices', '1')

    devices_raw =  decode_extcap(raw)
    devices = {}

    for type, data in devices_raw:
        if type == 'value' and data['arg'] == '99':
            # device
            device = DeviceNode(data['display'], [])
            if 'parent' in data:
                devices[data['parent']].children.append(device)
            else:
                # remove [n] from the name
                device.name = device.name[4:]
                device.root = True
    
            devices[data['value']] = device

    return devices

def choose_devices(interface):
    print("\r\n--- CHOOSE DEVICES (e.g. * or 1 or 1,2,3,4) ---\r\n")

    possible_devices = get_device_tree(interface['value'])
    
    i = 0
    for dev_id, device in sorted(possible_devices.items()):
        if device.root:
            print("[%s] %s" % (dev_id, device))
    
    choice_str = input('> ')

    if choice_str == '*':
        choices = list(possible_devices)
    else:
        choices = list(int(x) for x in choice_str.split(','))

    return choices

def run_usbpcap(*opts):
    cmd = ['USBPcapCMD.exe'] + list(opts)
    raw = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, encoding='ascii')

    return raw.stdout.strip()

def listen(interface, devices):
    """ 
    Start a USBPcapCMD.exe process, with a named pipe to use as a FIFO,
    listening to the specified device and interface.
    """
    pipe = FIFOServer('dapdebug')

    cmd = ('USBPcapCMD.exe', '--extcap-interface', interface['value'], '--capture', '--capture-from-all-devices', '--fifo', pipe.path)
    # cmd = ('python3', 'test_pipe.py', pipe.path)
    print('-- RUNNING ' + ' '.join(cmd))

    with subprocess.Popen(cmd, encoding='ascii') as process:
        pipe.connect()

        print("-- CONNECTED TO CHILD PROCESS")

        packet = pipe.read()
        magic = packet[:4]

        if magic == b'\xd4\xc3\xb2\xa1':
            endian = '<'
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian = '>'
        else:
            raise RuntimeError("Invalid magic bytes in Pcap data.")

        packet = packet[4:]
        vermaj,vermin,tz,sig,snaplen,linktype = struct.unpack(endian+"HHIIII",packet)

        previous = None

        while 1:
            packet = pipe.read()

            header = packet[:16]
            sec,usec,caplen,wirelen = struct.unpack(endian+"IIII", header)

            raw = packet[16:]

            usb = USB(raw)

            # Filter by devices and by interrupt transfers
            if usb.device not in devices or usb.transfer != 1:
                continue

            print(usb.detail())

if __name__ == '__main__':
    intf = choose_interface()

    # Get a list of devices to listen to
    devices = choose_devices(intf)

    print("\r\n")

    # Listen to the device
    listen(intf, devices)
    
