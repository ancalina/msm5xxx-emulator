"""Seven-row table-driven multikey scanner; physical matrix contacts only."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import hashlib
import struct

_PATTERN_SIZE = 162
_PATTERN_HASH = 'cda1e4ecb80639854a3828035a3363adc8111a9276e63ee68f241b75b912310d'
_CALLS = (0, 30, 68, 158)
_LITERALS = (34, 36, 42, 48, 54, 72, 106)
_FOLD_SIZE = 182
_FOLD_HASH = 'eff95a91fe8660ba4dcd169f747382df20d642b3c79d2575b5752dd431fb369e'
_FOLD_CALLS = (92, 104, 150, 154, 160)
_FOLD_LITERALS = (0, 16, 36, 42, 52, 96, 164, 172)

def _fold_input(image: bytes, loop: int, descriptor: int):
    entry = facts_for(image).thumb_call_target(loop - 0xbc)
    if entry is None or not 0 <= entry <= len(image) - _FOLD_SIZE:
        return None
    code = bytearray(image[entry:entry + _FOLD_SIZE])
    for o in _FOLD_CALLS:
        if facts_for(image).thumb_call_target(entry + o) is None:
            return None
        code[o:o + 4] = b"\0" * 4
    for o in _FOLD_LITERALS:
        if struct.unpack_from("<H", code, o)[0] & 0xf800 != 0x4800:
            return None
        code[o] = 0
    if hashlib.sha256(code).hexdigest() != _FOLD_HASH or facts_for(image).thumb_literal_value(entry + 0x10, 0) != descriptor:
        return None
    if (facts_for(image).thumb_call_target(entry + 0x68) != facts_for(image).thumb_call_target(entry + 0xa0) or facts_for(image).thumb_call_target(entry + 0x5c)
        != facts_for(image).thumb_call_target(entry + 0x96)):
        return None
    return dict(address=0x03000728, mask=2, default=2, reader=entry + 0x14, assumption=
        "Fold input high permits keypad; modeled open, bit1 independent of NAND R/B bit0", dependencies= [(entry, _FOLD_SIZE)])

def find_table7_matrix(image: bytes) -> dict | None:
    results= []; at=0
    anchor=bytes.fromhex('406b00880007000f0f281ed0')
    while (at:=image.find(anchor,at))>=0:
        loop=at-0x4a; at+=2
        if loop<0 or loop+_PATTERN_SIZE>len(image): continue
        code=bytearray(image[loop:loop+_PATTERN_SIZE])
        calls={o:facts_for(image).thumb_call_target(loop+o) for o in _CALLS}
        values={}
        for o in _LITERALS:
            word=struct.unpack_from('<H',code,o)[0]
            if word&0xf800!=0x4800: break
            values[o]=facts_for(image).thumb_literal_value(loop+o, (word>>8)&7)
            code[o]=0
        else:
            for o in _CALLS: code[o:o+4]=b'\0'*4
            if hashlib.sha256(code).hexdigest()!=_PATTERN_HASH or None in calls.values(): continue
            descriptor=values[0x22]; preserve=values[0x24]
            if values[0x36]!=descriptor or values[0x48]!=descriptor or values[0x30]!=preserve: continue
            if not isinstance(preserve,int) or preserve>>16!=0xffff: continue
            mask=preserve^0xffffffff
            bits= [b for b in range(16) if mask&(1<<b)]
            if len(bits)!=7 or calls[0]!=calls[0x9e]: continue
            helper=calls[0]
            if (image[helper:helper+2]!=bytes.fromhex('00b5') or facts_for(image).thumb_call_target(helper+2)!= calls[0x1e] or facts_for(image).thumb_call_target(helper+26)!=calls[0x44]
                or facts_for(image).thumb_literal_value(helper+6, 1)!=descriptor or facts_for(image).thumb_literal_value(helper+8, 3)!=preserve or image[helper+10:helper+26]!=bytes.fromhex('8a8b1a408a838a8b09690a80002801d1')): continue
            event_base=values[0x6a]-44
            events=list(image[event_base:event_base+28])
            if len(events)!=28 or any(events.count(x)!=1 for x in b'123456789*0#'): continue
            copies= [row for row in _layouts(image) if row[2]<=descriptor<=row[2]+row[3]-0x38 and row[2]<=values[0x2a]<=row[2]+row[3]-14]
            if len(copies)!=1: continue
            table,source,target,size,_=copies[0]
            descriptor_rom=source+descriptor-target
            if[struct.unpack_from('<I',image,descriptor_rom+o)[0] for o in (8,16,36,52)]!=[0x300072c,0x3000724,0x3000728,0x300072c]: continue
            rows_rom=source+values[0x2a]-target
            rows=struct.unpack_from('<7H',image,rows_rom)
            if[((v&mask)^mask) for v in rows]!=[1<<b for b in bits]: continue
            # The early bit4 guard is a separate active-low contact; released=1.
            contact=loop-0xa4
            if (image[contact-2:contact+2]!=bytes.fromhex('606b0088') or image[contact+4:contact+8]!=bytes.fromhex('10231840') or facts_for(image).thumb_literal_value(contact-4,
                4)!=descriptor): continue
            fold = _fold_input(image, loop, descriptor)
            if fold is None: continue
            results.append(dict(fold_input=fold, grammar='indirect-halfword-table7-v1',rows=7,columns=4,no_key= 15, single_key_column_sense= [14,13,11,7],descriptor=descriptor,
                presence_site=loop+8,sense_site= loop+0x4c,contact_site=contact, row_select_mask=mask,row_select_bits=bits,event_table=event_base,event_codes=events,
                token_cells= [dict(token=chr(x),event=x,row=events.index(x)%7,column=events.index(x)//7) for x in b'123456789*0#'], dependencies= [(loop,_PATTERN_SIZE),(helper,34),(table,12),(descriptor_rom,56),(rows_rom,14),(event_base,28)]
                + fold["dependencies"], semantic_limit= 'One physical contact at a time; scan guard released, clock uncalibrated'))
    return results[0] if len(results)==1 else None

# Required evidence providers are bound by registry discovery.
from msm5xxx_emulator.detection.startup_layouts import layouts as _layouts

def loaded_natural_columns(image, loaded):
    if not isinstance(image, bytes) or not image or not isinstance(loaded, bytes):
        return False
    profile = find_table7_matrix(image)
    spans = profile.get('dependencies', ()) if profile else ()
    return bool(spans and all(0 <= a < a + n <= min(len(image), len(loaded)) and image[a:a + n] == loaded[a:a + n] for a, n in spans))
