"""RGB565 output from a copied, byte-wide reversed-port writer."""
from __future__ import annotations





class Reverse565:
    width,height=120,133
    geometry_source='runtime:source-reverse565'
    protocol='source-reverse565'
    disable_fast=True
    def __init__(self):
        self.rgb=bytearray(self.width*self.height*3)
        self.seen=bytearray(self.width*self.height)
        self.seen_count=0;self.qualified=False
        self.header=[];self.window=None;self.position=0;self.low=None

    def write(self,address,size,value):
        if address not in (0x02000000,0x02000004):return False,None
        if size!=1 or not 0<=value<=255:
            self.header=[];self.window=None;self.low=None
            return False,None
        if address==0x02000004:
            self.window=None;self.low=None
            expected=(4,None,5,None,6,None,7,None)
            n=len(self.header)
            if expected[n] is None or value==expected[n]:
                self.header.append(value)
                if len(self.header)==8:
                    _,x0,_,y0,_,x1,_,y1=self.header
                    self.header=[]
                    if 6<=x0<=x1<126 and 0<=y0<=y1<133:
                        self.window=(x0-6,x1-6,y0,y1);self.position=0
            else:self.header=[value] if value==4 else []
            return True,None
        if self.window is None:return True,None
        if self.low is None:self.low=value;return True,None
        rgb=self.low|(value<<8);self.low=None
        x0,x1,y0,y1=self.window;row_width=x1-x0+1
        pixel=(y0+self.position//row_width)*self.width+x0+self.position%row_width
        r=(rgb>>11)&31;g=(rgb>>5)&63;b=rgb&31;off=pixel*3
        self.rgb[off:off+3]=bytes(((r<<3)|(r>>2),(g<<2)|(g>>4),(b<<3)|(b>>2)))
        if not self.seen[pixel]:self.seen[pixel]=1;self.seen_count+=1
        self.position+=1;done=self.position==row_width*(y1-y0+1)
        if done:self.window=None
        if not self.qualified and self.seen_count==len(self.seen):
            self.qualified=True;return True,bytes(self.rgb)
        return True,bytes(self.rgb) if self.qualified and done else None
