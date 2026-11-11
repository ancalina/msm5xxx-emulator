"""Source-linked binary-pixel window writer on a byte-wide panel."""
from __future__ import annotations




class BinaryWindow:
    disable_fast = True
    geometry_source = "runtime:source-binary-window"
    protocol = "source-binary-window"
    width,height=120,143
    def __init__(self):
        self.rgb=bytearray(self.width*self.height*3)
        self.seen=bytearray(self.width*self.height);self.seen_count=0
        self.qualified=False;self.rejected=False;self.command=None;self.rows=[];self.cols=[]
        self.transfer=None;self.position=0

    def write(self,address,size,value):
        if address not in (0x02000004,0x02000006):return False,None
        if self.rejected:return False,None
        if size!=1 or not 0<=value<=255:
            self.command=self.transfer=None;return False,None
        if address==0x02000004:
            self.transfer=None;self.position=0
            if value==0x75:self.command='row';self.rows=[]
            elif value==0x15:self.command='col';self.cols=[]
            elif value==0x5c:
                self.command=None
                if self.rows==[0,142] and self.cols==[0,119]:self.transfer=(0,0,120,143)
                elif len(self.rows)==len(self.cols)==1 and self.rows[0]<143 and self.cols[0]<120:
                    self.transfer=(self.cols[0],self.rows[0],1,1)
            else:self.command=None
            return True,None
        if self.command=='row' and len(self.rows)<2:self.rows.append(value);return True,None
        if self.command=='col' and len(self.cols)<2:self.cols.append(value);return True,None
        if self.transfer is None:return True,None
        if value not in (0,255):self.transfer=None;self.rejected=True;return True,None
        x,y,width,height=self.transfer
        pixel=(y+self.position//width)*self.width+x+self.position%width
        off=pixel*3;self.rgb[off:off+3]=bytes((value,value,value))
        if not self.seen[pixel]:self.seen[pixel]=1;self.seen_count+=1
        self.position+=1
        done=self.position==width*height
        if done:self.transfer=None
        if not self.qualified and self.seen_count==len(self.seen):
            self.qualified=True;return True,bytes(self.rgb)
        return True,bytes(self.rgb) if self.qualified and done else None
