# CMSIS-DAP Dissector for Scapy

Debug devices using the CMSIS-DAP protocol over USB HID using USBPcap and ScaPy.

## Usage

> Please note that this is designed to work with USBPcap on Windows, and has only
> been tested with Windows 10.

```
PS > python3 .\tool.py
--- CHOOSE A CAPTURE INTERFACE (1) ---
[1] USBPcap1
[2] USBPcap2
> 2

--- CHOOSE DEVICES (e.g. * or 1 or 1,2,3,4) ---
[1] Synaptics FP Sensors (WBF) (PID=0017)
[2] USB Composite Device, [Integrated Camera]
[3] Intel(R) Wireless Bluetooth(R), [Microsoft Bluetooth LE Enumerator, Bluetooth Device (RFCOMM Protocol TDI), Microsof
t Bluetooth Enumerator, Bluetooth Device (Personal Area Network)]
[4] USB Composite Device, [USB Mass Storage Device [MBED VFS USB Device], USB Serial Device (COM15), USB Input Device [HID-compliant vendor-defined device]]
> 4

-- RUNNING USBPcapCMD.exe --extcap-interface \\.\USBPcap2 --capture --capture-from-all-devices --fifo \\.\pipe\dapdebug
-- CONNECTED TO CHILD PROCESS
...
```

