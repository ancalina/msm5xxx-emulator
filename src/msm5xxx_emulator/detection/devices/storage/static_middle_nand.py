"""Direct-ROM x16 small-page NAND producer with a copied ready descriptor.

Unlike middle_nand's copied driver, this graph executes in primary NOR.  The
signature closes reset/status/erase call edges, 1024*32 pages, the halfword
payload bus, and the GPIO pointer copied from this same dump.
"""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import struct

_RESET = bytes.fromhex('ff200d21490508707047')

def find_static_middle_nand_profile(image: bytes) -> dict | None:
    hits = []
    at = 0
    while (at := image.find(_RESET, at)) >= 0:
        reset = at
        at += 2
        if reset & 1 or reset < 0x60 or reset + 0x640 > len(image):
            continue
        # Reset=ff and status=70 use command 01a00000; data is 01800000.
        # The erase sweep shifts block by 5 and stops at 1<<10 blocks.
        spans = ((-0x58, '0320c0050d21490570220a700478c02c05d0c12c03d0'), (0x14, '406a0188490801d2013ffad1'), (0x90, '0320c0050088'), (0xb8, '80b501277801'), (0xc2,
            '013701239b029f42f7db80bc08bc1847'), (0x15e, '60200d21490508701920000507700470d0200870'), (0x294,
            '0d204005ff2301339d4201d2002100e05021017080210170051c1921'), (0x2c8, 'c00f0322d205002807d103e04100615a11800130b042f9d3'),)
        if any(image[reset+o:reset+o+len(bytes.fromhex(h))] != bytes.fromhex(h) for o,h in spans):
            continue
        if any(facts_for(image).thumb_call_target(reset+site) != reset+target for site,target in ((0x6a,0), (0x8c,0xa), (0xbe,0xd2), (0x15a,0), (0x17a,0xa), (0x17e,-0x60),
            (0x290,0))):
            continue
        instruction=struct.unpack_from('<H',image,reset+0x12)[0]
        if instruction&0xff00 != 0x4800:
            continue
        pool=((reset+0x16)&~3)+(instruction&255)*4
        if not 0 <= pool <= len(image) - 4:
            continue
        descriptor=struct.unpack_from('<I',image,pool)[0]
        mappings= []
        for table in range(0,min(0x30000,len(image)-12),4):
            source,target,size=struct.unpack_from('<III',image,table)
            if (target == 0x01000000 and 0 < size <= 0x800000 and target <= descriptor and descriptor+0x28 <= target+size and 0 <= source < source+size <= len(image)):
                pointer=source+descriptor-target+0x24
                if struct.unpack_from('<I',image,pointer)[0] == 0x03000728:
                    mappings.append((table,pointer))
        if len(mappings)!=1:
            continue
        table,pointer=mappings[0]
        hits.append(dict(signature='direct-middle-x16-small-page-v1', data=0x01800000,address=0x01900000,command =0x01a00000, data_size=0x1000000,page_size=512,pages_per_block=32,bus_width=2,
            ready_address= 0x03000728,ready_mask=1,ready_width=2, source_interval=(reset-0x60,reset+0x640),reset=reset, code_intervals=((reset-0x60,reset+0x640),(pool,pool+4),
            (table,table+12),(pointer,pointer+4)), semantic_limit='erased external NAND; main-area native model, OOB absent'))
    return hits[0] if len(hits)==1 else None
