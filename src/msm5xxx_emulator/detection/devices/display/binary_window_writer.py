"""Firmware evidence for display writer selection."""
from __future__ import annotations
import struct
from ...facts import facts_for


def has_binary_window_writer(image):
    if not isinstance(image,bytes):return False
    fixed={0:0x2075,6:0x2000,0xc:0x208e,0x12:0x2015,0x18:0x2000,
           0x1e:0x2077,0x24:0x205c,0x2a:0x2700,0x2c:0x2400,0x2e:0x20ff,
           0x3a:0x2c78,0x44:0x2f8f,0x48:0x20af,0x292:0xb5f0,
           0x298:0x20ff,0x29e:0x2700,0x2a0:0x2500,0x2a2:0x21ff,
           0x338:0x2075,0x344:0x2700,0x346:0x2015,0x352:0x205c,
           0x358:0x7828,0x35e:0x3501,0x366:0x2f78,0x370:0x2c7f}
    marker=struct.pack('<H',0x2075);limit=min(len(image),0x10000);pos=image.find(marker,0,limit)
    while pos>=0:
        if not pos&1 and pos+0x372<=limit and all(struct.unpack_from('<H',image,pos+o)[0]==v for o,v in fixed.items()):
            cmd=facts_for(image).thumb_call_target(pos+2);data=facts_for(image).thumb_call_target(pos+8)
            if (cmd is not None and data is not None and 0<=cmd<data and data+8<=limit
                    and struct.unpack_from('<4H',image,cmd)==(0x2101,0x0649,0x7108,0x46f7)
                    and struct.unpack_from('<4H',image,data)==(0x2101,0x0649,0x7188,0x46f7)
                    and all(facts_for(image).thumb_call_target(pos+off)==target for off,target in
                            ((0xe,data),(0x14,cmd),(0x1a,data),(0x20,data),(0x26,cmd),
                             (0x30,data),(0x33a,cmd),(0x340,data),(0x348,cmd),
                             (0x34e,data),(0x354,cmd),(0x35a,data)))):
                init=pos-0x62;writer=pos+0x292
                for call in range(0,limit-0x80,2):
                    if image[call+1]&0xf8==0xf0 and facts_for(image).thumb_call_target(call)==init:
                        if any(image[later+1]&0xf8==0xf0 and facts_for(image).thumb_call_target(later)==writer
                               for later in range(call+4,call+0x80,2)):
                            return True
        pos=image.find(marker,pos+1,limit)
    return False
