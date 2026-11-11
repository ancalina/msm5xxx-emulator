"""Firmware evidence for display writer selection."""
from __future__ import annotations
import struct
from ...facts import facts_for


def find_source_packed12(image):
    if not isinstance(image, bytes):return None
    dest=0x03800000
    init_fixed={0:0xb4f0,6:0x2300,8:0x1e8a,0xa:0x2575,0xc:0x6207,
                0xe:0x7015,0x10:0x2400,0x12:0x700c,0x14:0x2781,
                0x16:0x700f,0x18:0x2715,0x1a:0x7017,0x1c:0x700c,
                0x1e:0x2640,0x20:0x700e,0x22:0x265c,0x24:0x7016,
                0x28:0x700c,0x2a:0x3301,0x32:0x429e,0x36:0x7015,
                0x38:0x700c,0x3a:0x207f,0x3c:0x7008,0x3e:0x7017,
                0x40:0x700c,0x42:0x203f,0x44:0x7008}
    packed_fixed={0:0xb4fe,4:0x2700,8:0x6862,0xa:0x215c,
                  0x70:0x7866,0x72:0x5ced,0x74:0x23f0,0x76:0x401d,
                  0x78:0x4033,0x7a:0x091b,0x82:0x702b,0x84:0x78a5,
                  0x86:0x23f0,0x88:0x401d,0x8c:0x5c9e,0x8e:0x23f0,
                  0x90:0x4033,0x92:0x091b,0x94:0x18eb,0xa2:0x785d,
                  0xa4:0x78b6,0xa6:0x23f0,0xa8:0x401d,0xaa:0x4033,
                  0xac:0x091b,0xae:0x18eb}
    marker=struct.pack('<3H',0x23f0,0x401d,0x4033)
    init_marker=struct.pack('<3H',0x2575,0x6207,0x7015)
    init_at=image.find(init_marker,0,min(len(image),0x200000));matches=[]
    while init_at>=0:
        init=init_at-0xa
        if (init>=0 and not init&1 and init+0x48<=len(image)
                and all(struct.unpack_from('<H',image,init+o)[0]==v for o,v in init_fixed.items())
                and facts_for(image).thumb_literal_value(init+2,1)==0x02000042
                and any(image[call+1]&0xf8==0xf0 and facts_for(image).thumb_call_target(call)==init
                        for call in range(max(0,init-0x800)&~1,init,2))):
            desc=image.find(struct.pack('<I',dest),0,min(len(image),0x20000))
            while desc>=0:
                if desc>=4 and not desc&3 and desc+8<=len(image):
                    source,size=struct.unpack_from('<I4xI',image,desc-4)
                    if 0<size<=0x40000 and source+size<=len(image):
                        p=image.find(marker,source,source+size)
                        while p>=0:
                            writer=p-0x74
                            if (source<=writer and writer+0xb0<=source+size and not writer&1
                                    and all(struct.unpack_from('<H',image,writer+o)[0]==v for o,v in packed_fixed.items())):
                                table=facts_for(image).thumb_literal_value(writer+2,4)
                                same=facts_for(image).thumb_literal_value(writer+0x96,5)
                                pair=struct.pack('<2I',0x02000042,0x02000040)
                                if (table is not None and table==same and 0x01000000<=table<0x02000000
                                        and image.find(pair,0,len(image))>=0):
                                    matches.append((desc,source,size,init,writer,table))
                            p=image.find(marker,p+1,source+size)
                desc=image.find(struct.pack('<I',dest),desc+1,min(len(image),0x20000))
        init_at=image.find(init_marker,init_at+1,min(len(image),0x200000))
    matches=set(matches)
    return next(iter(matches)) if len(matches)==1 else None
