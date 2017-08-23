"""
Scapy definitions for CMSIS-DAP packets. Data structures specified in the
CMSIS-DAP documentation.

https://arm-software.github.io/CMSIS_5/DAP/html/group__DAP__Commands__gr.html
"""
from packet_usbpcap import USB

from scapy.config import conf
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, BitField, BitEnumField, PacketListField, ConditionalField, LEShortField, StrLenField

conf.debug_dissector = True

class CMSISDAPRequest(Packet):
    """
    CMSIS-DAP packet
    """
    name = "CMSIS-DAP"

    fields_desc = [
        ByteEnumField("cmd", 0, {
            0x0: "Info",
            0x1: "HostStatus",
            0x2: "Connect",
            0x3: "Disconnect",
            0x4: "TransferConfigure",
            0x5: "Transfer",
            0x6: "TransferBlock",
            0x7: "TransferAbort",
            0x8: "WriteAbort",
            0x9: "Delay",
            0xa: "ResetTarget",
            0x10: "SWJ_Pins",
            0x11: "SWJ_Clock",
            0x12: "SWJ_Sequence",
            0x13: "SWD_Configure",
            0x14: "JTAG_Sequence",
            0x15: "JTAG_Configure",
            0x16: "JTAG_IDCODE",
            0x80: "Vendor0"
        })
    ]

    def detail(self):
        if hasattr(self.payload, "detail"):
            return self.sprintf("{CMSISDAPRequest:CMSIS-DAP req %CMSISDAPRequest.cmd%}") + " | " + self.payload.detail()
        else:
            return self.sprintf("{CMSISDAPRequest:CMSIS-DAP req %CMSISDAPRequest.cmd%}")

# Bind to any USB interrupt transfer
bind_layers(USB, CMSISDAPRequest, transfer=1, direction=0)

class CMSISDAPResponse(Packet):
    """
    CMSIS-DAP packet
    """
    name = "CMSIS-DAP"
    previous = None

    fields_desc = [
        ByteEnumField("cmd", 0, {
            0x0: "Info",
            0x1: "HostStatus",
            0x2: "Connect",
            0x3: "Disconnect",
            0x4: "TransferConfigure",
            0x5: "Transfer",
            0x6: "TransferBlock",
            0x7: "TransferAbort",
            0x8: "WriteAbort",
            0x9: "Delay",
            0xa: "ResetTarget",
            0x10: "SWJ_Pins",
            0x11: "SWJ_Clock",
            0x12: "SWJ_Sequence",
            0x13: "SWD_Configure",
            0x14: "JTAG_Sequence",
            0x15: "JTAG_Configure",
            0x16: "JTAG_IDCODE",
            0x80: "Vendor0"
        })
    ]

    def detail(self):
        if hasattr(self.payload, "detail"):
            return self.sprintf("{CMSISDAPResponse:CMSIS-DAP res %CMSISDAPResponse.cmd%}") + " | " + self.payload.detail()
        else:
            return self.sprintf("{CMSISDAPResponse:CMSIS-DAP res %CMSISDAPResponse.cmd%}")
bind_layers(USB, CMSISDAPResponse, transfer=1, direction=1)

class CMSISDAPInfoRequest(Packet):
    """
    Dissector for CMSIS-DAP protocol packets
    """
    name = "DAP_Info"
    fields_desc = [
        ByteEnumField("id", 0, {
            0x01: "VendorID",
            0x02: "ProductID",
            0x03: "Serial Number",
            0x04: "CMSIS-DAP FW Version",
            0x05: "Target Vendor",
            0x06: "Target Device Name",
            0xf0: "Capabilities",
            0xf1: "Test Domain Timer",
            0xf2: "Trace Domain Management",
            0xfd: "SWO Trace Buffer Size",
            0xfe: "Packet Count",
            0xff: "Packet Size"
        })
    ]

    def detail(self):
        return self.sprintf("%CMSISDAPInfoRequest.id%")
bind_layers(CMSISDAPRequest, CMSISDAPInfoRequest, cmd=0)

class CMSISDAPInfoResponse(Packet):
    """
    Dissector for CMSIS-DAP protocol packets
    """
    name = "DAP_InfoResponse"
    fields_desc = [
        ByteField("len", 0),
        ConditionalField(
            StrLenField("dataSTR", "", length_from=lambda pkt: pkt.len),
            lambda pkt: pkt.len > 2
        ),
        ConditionalField(
            ByteField("dataB", 0),
            lambda pkt: pkt.len == 1
        ),
        ConditionalField(
            LEShortField("dataS", 0),
            lambda pkt: pkt.len == 2
        )
    ]

    def dataValue(self):
        dataName = "dataB" if self.len == 1 else "dataS" if self.len == 2 else "dataSTR"
        return str(self.fields[dataName])

    def detail(self):
        return self.dataValue()
bind_layers(CMSISDAPResponse, CMSISDAPInfoResponse, cmd=0)

class CMSISDAPTransferRequest(Packet):
    name = "Request"
    fields_desc = [
        BitField("timeStamp", 0, 1),
        BitField("pad", 0, 1),

        ConditionalField(
            BitField("matchMask", 0, 1),
            lambda pkt: pkt.RnW == 1
        ),
        ConditionalField(
            BitField("pad", 0, 1),
            lambda pkt: pkt.RnW == 0
        ),

        # Value Match field is only applicable if we're reading
        ConditionalField(
            BitEnumField("valueMatch", 0, 1, {
                0: "Normal Read",
                1: "Value Match"
            }),
            lambda pkt: pkt.RnW == 1
        ),
        ConditionalField(
            BitField("pad", 0, 1),
            lambda pkt: pkt.RnW == 0
        ),

        BitField("reg", 0, 2),

        BitEnumField("RnW", 0, 1, {
            0: "Write",
            1: "Read"
        }),

        BitEnumField("APnDP", 0, 1, {
            0: "DP",
            1: "AP"
        }),

        ConditionalField(
            LEShortField("value", 0),
            lambda pkt: pkt.RnW == 0
        ),

        ConditionalField(
            LEShortField("matchValue", 0),
            lambda pkt: pkt.RnW == 1 and pkt.valueMatch == 1
        ),

        ConditionalField(
            LEShortField("matchMask", 0),
            lambda pkt: pkt.RnW == 1 and pkt.matchMask == 1
        ),
    ]

    def extract_padding(self, p):
        return "", p


class CMSISDAPTransfer(Packet):
    name = "DAP_Transfer"
    fields_desc = [
        ByteField("dapIndex", 0),
        ByteField("count", 0),
        PacketListField("transfers", [], CMSISDAPTransferRequest,
                        count_from=lambda p: p.count)
    ]
bind_layers(CMSISDAPRequest, CMSISDAPTransfer, cmd=5)
