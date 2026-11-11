"""Byte row writer with source-linked RGB565 pixel transfers."""
from __future__ import annotations





class Row565:
    geometry_source = "runtime:source-row565"
    protocol = "source-row565"
    width,height=128,160
    def __init__(self):
        self.rgb=bytearray(self.width*self.height*3)
        self.seen=bytearray(self.width*self.height)
        self.seen_count=0;self.qualified=False
        self.stage=0;self.pending=None;self.column=None;self.row=None;self.high=None

    def write(self,address,size,value):
        if address not in (0x02000000,0x02000002):return False,None
        if size!=1 or not 0<=value<=255:
            self.stage=0;self.pending=self.high=None
            return False,None
        if address==0x02000000:
            self.high=None
            if value==3:
                self.stage=0;self.pending='column'
            elif value==5 and self.stage==1:
                self.pending='row'
            elif value==0x0b and self.stage==2:
                self.stage=3;self.pending=None
            else:
                self.stage=0;self.pending=None
            return True,None
        if self.pending=='column':
            self.column=value;self.stage=1 if value<self.width else 0;self.pending=None
            return True,None
        if self.pending=='row':
            self.row=value;self.stage=2 if value<self.height else 0;self.pending=None
            return True,None
        if self.stage!=3 or self.column is None or self.row is None or self.column>=self.width:
            return True,None
        if self.high is None:
            self.high=value;return True,None
        rgb=(self.high<<8)|value;self.high=None
        red=(rgb>>11)&31;green=(rgb>>5)&63;blue=rgb&31
        pixel=self.row*self.width+self.column;off=pixel*3
        self.rgb[off:off+3]=bytes(((red<<3)|(red>>2),(green<<2)|(green>>4),(blue<<3)|(blue>>2)))
        if not self.seen[pixel]:self.seen[pixel]=1;self.seen_count+=1
        self.column+=1
        if not self.qualified and self.seen_count==len(self.seen):
            self.qualified=True;return True,bytes(self.rgb)
        return True,bytes(self.rgb) if self.qualified else None
