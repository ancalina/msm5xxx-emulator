"""Firmware evidence for display writer selection."""
from __future__ import annotations
import struct
from ...facts import facts_for


def has_row565_writer(image):
    if not isinstance(image, bytes):
        return False
    fixed = {0:0xb5f3,0x38:0x202b,0x3c:0x0649,0x3e:0x7008,
             0x64:0x28a0,0x72:0x2003,0x76:0x0649,0x78:0x7008,
             0x7c:0x7088,0x7e:0x2005,0x84:0x7088,0x86:0x200b,
             0x88:0x7008,0x90:0x2880,0xa8:0x20ff,0xac:0x0649,
             0xae:0x7088,0xb0:0x7088,0xf8:0x2f0e,0x124:0x2e06,
             0x148:0x20f0,0x14e:0x7088,0x150:0x2000,0x152:0x7088,
             0x156:0x20ff,0x15c:0x7088,0x15e:0x7088}
    marker = struct.pack('<H',0x28a0)
    limit=min(len(image),0x80000)
    pos=image.find(marker,0,limit)
    while pos>=0:
        writer=pos-0x64
        if (writer >= 0 and not writer & 1 and writer+0x160<=limit
                and all(struct.unpack_from('<H',image,writer+o)[0]==op for o,op in fixed.items())):
            for call in range(max(0,writer-0x1000)&~1,min(limit-4,writer+0x2000),2):
                if image[call+1]&0xf8==0xf0 and facts_for(image).thumb_call_target(call)==writer:
                    return True
        pos=image.find(marker,pos+1,limit)
    return False
