"""
Scapy definitions for USB packets captured by USBPcap on Windows.
"""
from scapy.packet import Packet
from scapy.fields import LEShortField, LELongField, LEIntField, BitEnumField, BitField, ByteEnumField, ByteField

class USB(Packet):
    """
    Represents a USB packet saved by USBPcap.
    
    Based on packet format specified at http://desowin.org/usbpcap/captureformat.html.
    """
    name = "USBPcap"
    fields_desc = [
        LEShortField("headerLen", None),
        LELongField("irpId", None),
        LEIntField("status", None),

        LEShortField("function", None),
        ByteField("info", None),

        LEShortField("bus", 0),
        LEShortField("device", 0),

        BitEnumField("direction", 0, 1, {
            0: "OUT",
            1: "IN"
        }),
        BitField("endpoint", 0, 7),

        ByteEnumField("transfer", 0, {
            0: "isochronous",
            1: "interrupt",
            2: "control",
            3: "bulk"
        }),
        LEIntField("bodyLength", 0)
    ]

    def pre_dissect(self, s):
        if isinstance(self.underlayer, USB):
            self.direction = self.underlayer.endpoint & 0x80
        return s

    def detail(self):
        if hasattr(self.payload, "detail"):
            return self.sprintf("USB ep=%USB.endpoint% %-3s,USB.direction%") + " | " + self.payload.detail()
        else:
            pass
