"""Copied two-pixel RGB444 writer on a byte-addressed window panel."""
from __future__ import annotations




class SourcePacked12:
    width=height=128
    geometry_source='runtime:source-packed12'
    protocol='source-packed12'
    disable_fast=True
    def __init__(self):
        self.rgb=bytearray(self.width*self.height*3)
        self.seen=bytearray(64*128);self.seen_count=0;self.qualified=False
        self.command=None;self.rows=[];self.cols=[];self.window=None
        self.position=0;self.pixel=[];self.mode=False;self.mode_args=[]

    def write(self,address,size,value):
        if address not in (0x02000040,0x02000042):return False,None
        if size!=1 or not 0<=value<=255:
            self.command=self.window=None;self.pixel.clear();return False,None
        if address==0x02000040:
            self.window=None;self.pixel.clear();self.position=0
            if value==0xbc:self.command='mode';self.mode=False;self.mode_args=[]
            elif value==0x75:self.command='row';self.rows=[]
            elif value==0x15:self.command='col';self.cols=[]
            elif value==0x5c:
                self.command=None
                if self.mode and len(self.rows)==len(self.cols)==2:
                    y0,y1=self.rows;x0,x1=self.cols
                    if (0<=x0<=x1<=64 and 0<=y0<=y1<=129
                            and (self.qualified or (x0==0 and y0==0 and x1>=63 and y1>=127))):
                        self.window=(x0,x1,y0,y1)
            else:self.command=None
            return True,None
        if self.command=='mode' and len(self.mode_args)<3:
            self.mode_args.append(value)
            if len(self.mode_args)==3:self.mode=tuple(self.mode_args)==(2,1,2)
            return True,None
        if self.command=='row' and len(self.rows)<2:self.rows.append(value);return True,None
        if self.command=='col' and len(self.cols)<2:self.cols.append(value);return True,None
        if self.window is None:return True,None
        self.pixel.append(value)
        if len(self.pixel)<3:return True,None
        a,b,c=self.pixel;self.pixel=[]
        x0,x1,y0,y1=self.window;columns=x1-x0+1
        x=x0+self.position%columns;y=y0+self.position//columns
        if x<64 and y<128:
            at=(y*self.width+x*2)*3
            self.rgb[at:at+6]=bytes(v*17 for v in (a>>4,a&15,b>>4,b&15,c>>4,c&15))
            cell=y*64+x
            if not self.seen[cell]:self.seen[cell]=1;self.seen_count+=1
        self.position+=1;done=self.position==columns*(y1-y0+1)
        if done:self.window=None
        if not self.qualified and self.seen_count==len(self.seen):
            self.qualified=True;return True,bytes(self.rgb)
        return True,bytes(self.rgb) if self.qualified and done else None
