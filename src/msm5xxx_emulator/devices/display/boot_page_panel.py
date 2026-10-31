"""Source-canvas page display, admitted by a complete observed zero clear."""
from __future__ import annotations


class BootPagePanel:
    def __init__(self, pages, planes, *, access_width=2, publish_after_clear_if_enabled=False):
        if ((access_width,pages,planes) not in ((2,9,1),(2,16,2),(1,8,1))
                or type(access_width) is not int
                or (publish_after_clear_if_enabled and (access_width,pages,planes) != (1,8,1))):
            raise ValueError('unsupported-source-raster')
        self.pages,self.planes=pages,planes
        self.access_width=access_width
        self.publish_after_clear_if_enabled=publish_after_clear_if_enabled
        self.width,self.height=128,pages*8
        self.ram=bytearray(pages*128*planes)
        self.rgb=bytearray([255])*(128*self.height*3)
        self.frame=bytes(self.rgb)
        self.page=-1;self.low=self.high=None;self.column=None;self.plane=0
        self.enabled=self.started=self.qualified=False
        self.clear_next=0;self.clear_seen=bytearray(len(self.ram));self.clear_row_count=0
        self.sequence=0;self.rejection=None

    def _publish(self):
        self.frame=bytes(self.rgb);self.sequence+=1

    def _address(self):
        self.column=(self.high|self.low) if self.high is not None and self.low is not None else None
        self.plane=0

    def write(self,address,size,value):
        if address not in (0x02000000,0x02000002) or self.rejection:
            return False
        if size != self.access_width or not 0 <= value <= 255:
            self.rejection=('source-halfword-byte-value-required' if self.access_width == 2
                            else 'source-byte-value-required');return False
        if address == 0x02000000:
            if value == 0xae:
                self.started=True;self.enabled=self.qualified=False;self.clear_next=0
                self.clear_seen[:]=bytes(len(self.clear_seen));self.clear_row_count=0
                self.page=-1;self.low=self.high=self.column=None;self.plane=0
            elif 0xb0 <= value < 0xb0+self.pages:
                self.page=value-0xb0;self.low=self.high=self.column=None;self.plane=0
            elif 0xb0 <= value <= 0xbf:
                if self.qualified:self.rejection='source-page-outside-canvas'
                self.clear_next=0;self.clear_row_count=0
                self.clear_seen[:]=bytes(len(self.clear_seen))
                self.page=-1;self.column=None
            elif 0 <= value <= 15:
                self.low=value;self._address()
            elif 0x10 <= value <= 0x1f:
                self.high=(value&15)<<4;self._address()
            elif value == 0xaf:
                self.enabled=True
                if self.started and self.clear_next == self.pages:
                    self.qualified=True;self._publish()
            else:
                self.page=-1;self.low=self.high=self.column=None;self.plane=0
            return self.qualified
        if self.page < 0 or self.column is None or self.column >= 128:
            if self.qualified:self.rejection='data-without-source-page-column'
            elif self.started:
                self.clear_next=0;self.clear_row_count=0
                self.clear_seen[:]=bytes(len(self.clear_seen))
            return False
        at=(self.page*128+self.column)*self.planes+self.plane
        previous=self.ram[at];self.ram[at]=value
        if not self.qualified and self.started:
            if value:
                self.clear_next=0;self.clear_row_count=0
                self.clear_seen[:]=bytes(len(self.clear_seen))
            elif self.page == self.clear_next and not self.clear_seen[at]:
                self.clear_seen[at]=1;self.clear_row_count+=1
                if self.clear_row_count == 128*self.planes:
                    self.clear_next+=1;self.clear_row_count=0
        if previous != value:
            for bit in range(8):
                cell=(self.page*128+self.column)*self.planes
                level=sum(((self.ram[cell+n]>>bit)&1)*(1<<(self.planes-1-n))for n in range(self.planes))
                shade=255-level*255//((1<<self.planes)-1)
                pixel=((self.page*8+bit)*128+self.column)*3
                self.rgb[pixel:pixel+3]=bytes([shade])*3
            if self.qualified and self.enabled:self._publish()
        if (self.publish_after_clear_if_enabled and self.started and self.enabled
                and not self.qualified and self.clear_next == self.pages):
            self.qualified=True;self._publish()
        self.plane+=1
        if self.plane == self.planes:self.plane=0;self.column+=1
        return self.qualified and self.rejection is None
