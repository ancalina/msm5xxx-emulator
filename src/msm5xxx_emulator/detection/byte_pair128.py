"""Source-bound 128x128 byte-port LCD with two adjacent plane writes.

The source, rather than a handset name, proves ports, page count, column
count, and the 0x800-byte plane separation. Optical calibration is unknown.
"""
from .arm import thumb_bl_target, thumb_literal_value


_WRITERS = bytes.fromhex('012149060870f746012149068870f746')
_PAGE_COLUMN = bytes.fromhex('80b5071c38110007000f10231843fff7efff3807000ffff7ebff80bd00b50006000eb0231843fff7e3ff00bd')
_FLUSH = bytes.fromhex('00201e4d012252061e4b195c002914d000211954b023034313701023137011700b015b191e5c96701e180123db02f3181b78937001318029f2db01301028e3dbaf201070')
_PREFIX = (0xe2,0x48,0x80,0xa2,0xa1,0xc0,0x44,0,0xab,0x66,0x27,0x81,0x20,
           0x55,0x96,0x88,0,0x89,0,0x8a,0x0c,0x8b,0,0x8c,0xcc,0x8d,0,
           0x8e,0xcc,0x8f,0xcc,0x2c,0x2e,0x2f,0x40,0,0xa6,0xa4)


def find_byte_pair128_profile(image):
    group = _WRITERS + _PAGE_COLUMN
    writers = image.find(group)
    if writers < 0 or image.find(group,writers+1) >= 0:
        return None, 'byte-pair128-writers-not-unique'
    if image[writers+16:writers+16+len(_PAGE_COLUMN)] != _PAGE_COLUMN:
        return None, 'byte-pair128-page-column-unclosed'
    inits=[]
    start=writers+16+len(_PAGE_COLUMN)
    for at in range(start, min(len(image)-len(_PREFIX)*6, writers+0x800), 2):
        if all(image[at+n*6:at+n*6+2] == bytes((value,0x20)) and
               thumb_bl_target(image,at+n*6+2)==writers for n,value in enumerate(_PREFIX)):
            inits.append(at)
    flushes=[]
    for at in range(start, min(len(image)-len(_FLUSH),writers+0x1000),2):
        if all(image[at+n]==value for n,value in enumerate(_FLUSH) if n not in (2,8)):
            buf=thumb_literal_value(image,at+2,5)
            flags=thumb_literal_value(image,at+8,3)
            if (isinstance(buf,int) and flags==buf+0x1000 and
                    0x01000000<=buf<=0x01800000-0x1010):
                flushes.append((at,buf,flags))
    if len(inits)!=1 or len(flushes)!=1:
        return None, 'byte-pair128-init-flush-unclosed'
    flush,buf,flags=flushes[0]
    pools = [((pc+4)&~3)+image[pc]*4 for pc in (flush+2,flush+8)]
    return dict(class_name='source-byte-pair128-page-v1', candidate=True,
        width=128,height=128,bits_per_pixel=2,logical_y_reverse=False,
        column_bias=0,column_capacity=256,command_port=0x02000000,
        data_port=0x02000002,access_width=1,main_pages=list(range(16)),
        whole_rows_only=True,
        required_pages=16,init_row_bytes=256,icon_page=-1,init_commands=list(_PREFIX),
        init_entry=inits[0],producer_entry=flush,framebuffer_low=buf,
        plane_stride=0x800,plane_weights=[2,1],optical_polarity=None,
        optical_orientation=None,controller_part=None,
        code_intervals=[[writers,writers+16+len(_PAGE_COLUMN)],
                        [inits[0],inits[0]+6*len(_PREFIX)],[flush,flush+len(_FLUSH)]],
        literal_intervals=[[at,at+4] for at in pools],
        data_intervals=[],
        ram_intervals=[[buf,buf+0x1000],[flags,flags+16]]), 'accepted-source-byte-pair128-page'
