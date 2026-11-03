"""Six active-low GPIO rows and four sense columns in the legacy driver."""
import hashlib

from .arm import thumb_bl_target, thumb_literal_value
from .mono_page import _shape

_SCAN_SIZE = 112
_SCAN_HASH = '017111eddca4bed84319a65d5f5a0d710e00fe92c85bf33d69e3f3a937d6e4b7'
_BOARD_SIZE = 90
_BOARD_HASH = '12eb80cebf488591ab4d675c045c2ed7e7ce6e423e7717d06104ad1b309c1567'
_BOARD_ANCHOR = bytes.fromhex('297b012620231940301c202900d00020')
_BOARD_BASE = bytes.fromhex('c549c54d0a78920992010a7009782970002801d13df1e5f8')


def _hashed_shape(image, entry, size, digest, calls, literals):
    if entry < 0 or entry & 1 or entry + size > len(image):
        return None
    code = bytearray(image[entry:entry + size])
    targets = {offset: thumb_bl_target(image, entry + offset) for offset in calls}
    values = {offset: thumb_literal_value(image, entry + offset, register)
              for offset, register in literals}
    if (any(value is None or value & 1 or not 0 <= value <= len(image) - 2
            for value in targets.values()) or any(value is None for value in values.values())):
        return None
    for offset in calls:
        code[offset:offset + 4] = bytes(4)
    for offset, _ in literals:
        code[offset:offset + 2] = bytes(2)
    return (targets, values) if hashlib.sha256(code).hexdigest() == digest else None


def find_legacy_six_row_keypad(image):
    candidates=[]
    cursor=0
    while (at:=image.find(bytes.fromhex('0126a640f3439b069b0e194311701178'),cursor))>=0:
        cursor=at+2;entry=at-14
        found=_hashed_shape(image,entry,_SCAN_SIZE,_SCAN_HASH,(2,0x2a,0x54,0x6c),
                     ((6,2),(0x22,2),(0x2e,0),(0x3a,1),(0x58,2),(0x64,2)))
        if found is None:
            continue
        calls,values=found
        if (values[0x22]!=0x03000660 or values[0x64]!=0x03000660 or
                values[0x2e]!=0x03000690 or values[6]!=values[0x58] or
                calls[2]!=calls[0x54] or calls[0x2a]!=calls[0x6c]):
            continue
        table=values[0x3a]
        if not 24<=table<len(image)-16:
            continue
        senses=(14,13,11,7)
        if [image[table+s] for s in senses]!=list(range(4)):
            continue
        events=list(image[table-24:table])
        if any(events.count(v)!=1 for v in b'123456789*0#'):
            continue
        # The same debounced event producer receives fold6/8 and HFK72/73.
        # Close the actual GPIO base and all call edges, not just literals.
        sink=thumb_bl_target(image,entry+0x10e)
        if sink is None:
            continue
        board=[];cursor2=0
        while (bp:=image.find(_BOARD_ANCHOR,cursor2))>=0:
            cursor2=bp+2
            shape=_hashed_shape(image,bp,_BOARD_SIZE,_BOARD_HASH,(0x22,0x28,0x50,0x56),((0x10,1),(0x2c,1),(0x3e,1)))
            base=_shape(image,bp-0x5a,_BOARD_BASE,(0x14,),((0,1),(2,5)))
            if (shape is not None and base is not None and
                    base[1][2]==0x03000660 and
                    len(set(shape[1].values()))==1 and
                    all(target==sink for target in shape[0].values())):
                board.append(bp)
        if len(board)!=1:
            continue
        candidates.append(dict(grammar='direct-low-nibble-6-row-v1',
            signature='legacy-six-row-gpio660-v1',event_sink_family='source-legacy-debounced-key-event',
            sense_site=entry+0x2e,register=0x03000694,row_register=4,
            row_output=0x03000660,row_mask=0x3f,presence_site=entry-0x20,
            rows=6,columns=4,sense_bits=4,no_key=15,
            single_key_column_sense=list(senses),event_codes=events,event_table=table-24,
            provisional_mappings={bit:{'event':v,'rule':'ASCII-digit-unique-source-cell'}
                                  for bit,v in zip(range(11,23),b'123456789*0#')},
            board_init=board[0],event_sink=sink,
            source_intervals=[[entry,entry+_SCAN_SIZE],[table-24,table+16],
                              [board[0]-0x5a,board[0]-0x5a+len(_BOARD_BASE)],
                              [board[0],board[0]+_BOARD_SIZE]]))
    return candidates[0] if len(candidates)==1 else None
