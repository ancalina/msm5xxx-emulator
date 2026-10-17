"""Synthetic protocol vectors; neither firmware digits nor packet captures are fixtures."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

def field(data, start, width):
    value = 0
    for at in range(start, start + width):
        value = (value << 1) | ((data[at // 8] >> (7 - at % 8)) & 1)
    return value

def crc30(data, bit_count):
    value = 0x3fffffff
    for at in range(bit_count):
        feedback = ((value >> 29) ^ field(data, at, 1)) & 1
        value = ((value << 1) ^ (0x6030b9c7 if feedback else 0)) & 0xffffffff
    return (~value) & 0x3fffffff

def put(data, start, width, value):
    for index in range(width):
        at = start + index
        mask = 1 << (7 - at % 8)
        data[at // 8] = (data[at // 8] & ~mask) | (((value >> (width - index - 1)) & 1) * mask)

def seal(packet):
    protected = len(packet) * 8 - 30
    put(packet, protected, 30, crc30(packet, protected))
    assert crc30(packet, len(packet) * 8) == 0x0b105aa5
    return packet

def make(service=3, count=3, padding=0):
    end = 160 + 4 * count
    packet = bytearray((end + 30 + 7) // 8)
    packet[0] = len(packet)
    put(packet, 10, 6, 4)
    put(packet, 30, 4, 9)
    put(packet, 131, 1, 1)
    put(packet, 132, 16, service)
    put(packet, 151, 8, count)
    for index in range(count):
        put(packet, 159 + 4 * index, 4, index % 12 + 1)
    put(packet, end, len(packet) * 8 - 30 - end, padding)
    return seal(packet)

def bits(value,width):
    return [(value>>shift)&1 for shift in range(width-1,-1,-1)]

def crc_bits(data,width,poly,initial):
    value=initial
    for bit in data:
        feedback=(value>>(width-1))^bit
        value=(value<<1)&((1<<width)-1)
        if feedback:value^=poly
    return value

def response(service,ack,seq):
    body=bits(1,8)+bits(ack,3)+bits(seq,3)+bits(1,1)+bits(0,2)+bits(0,1)+bits(0,6)+bits(20,6)+bits(3,3)+bits(0,8)+bits(service,16)+[0]*7
    packet=bits(11,8)+body
    packet+=bits(crc_bits(packet,16,0x1021,65535)^65535,16)
    data=bits(11,4)+[1]+packet+[0]*(168-1-len(packet))
    data+=bits(crc_bits(data,12,0xf13,4095),12)+[0]*8
    return bytes(sum(data[i+j]<<(7-j) for j in range(8)) for i in range(0,len(data),8))

class AutomaticServiceTests(unittest.TestCase):
    def test_complete_request_and_response_formatter(self):
        data=bytearray()
        for service in (1,3,0x8000,0xffff):
            for count in (1,3,32):
                for padding in (0,3):
                    data+=service.to_bytes(2,'little')+bytes([count])+make(service,count,padding)
        for start,width,value in ((8,2,1),(10,6,5),(27,3,1),(106,2,1),(131,1,0),
                                  (149,1,1),(150,1,1),(151,8,0),(151,8,33),(151,8,32),
                                  (151,8,1),(159,4,0),(159,4,13)):
            packet=make();put(packet,start,width,value);data+=seal(packet)
        for service in (1,3,0x8000,0xffff):
            for ack in range(8):
                for seq in range(8):data+=service.to_bytes(2,'little')+bytes([ack,seq])+response(service,ack,seq)
        native=Path(__file__).resolve().parents[1]/'experiments/qemu-tcg'
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'vectors').write_bytes(data);(p/'test.c').write_text('\n#include "msm5xxx-search2.h"\n#include <assert.h>\n#include <stdio.h>\n#include <string.h>\nstatic void reject(const uint8_t*p,unsigned n,unsigned rev){\n MSM5xxxServiceRequest out={0xa55a,0x5a},before=out;\n assert(!msm5xxx_access_service_request(p,n,rev,&out));\n assert(!memcmp(&out,&before,sizeof out));\n}\nstatic unsigned read_packet(FILE*f,uint8_t*p){\n assert(fread(p,1,1,f)==1&&p[0]<=40&&p[0]>=5);\n assert(fread(p+1,1,p[0]-1,f)==p[0]-1u);return p[0];\n}\nint main(int argc,char**argv){\n assert(argc==2);FILE*f=fopen(argv[1],"rb");assert(f);\n uint8_t original[40]={0};unsigned original_n=0;\n for(unsigned i=0;i<24;i++){\n  uint8_t expect[3],p[40];assert(fread(expect,1,3,f)==3);unsigned n=read_packet(f,p);\n  for(unsigned rev=2;rev<=3;rev++){\n   MSM5xxxServiceRequest out;assert(msm5xxx_access_service_request(p,n,rev,&out));\n   assert(out.service_option==(expect[0]|((unsigned)expect[1]<<8))&&out.digit_count==expect[2]);\n  }\n  MSM5xxxAccess stream;msm5xxx_access_init(&stream);bool accepted=false;\n  for(unsigned off=0;off<n;off+=11){uint8_t piece[11]={0};unsigned amount=n-off<11?n-off:11;memcpy(piece,p+off,amount);accepted=msm5xxx_access_push(&stream,piece,11);}\n  assert(accepted);MSM5xxxServiceRequest last;\n  assert(msm5xxx_access_last_service_request(&stream,2,&last)&&last.service_option==(expect[0]|((unsigned)expect[1]<<8))&&last.digit_count==expect[2]);\n  uint8_t invalid[10]={0};assert(!msm5xxx_access_push(&stream,invalid,10));\n  assert(!msm5xxx_access_last_service_request(&stream,2,&last));\n  if(expect[0]==3&&expect[1]==0&&expect[2]==3&&!original_n){memcpy(original,p,n);original_n=n;}\n }\n for(unsigned i=0;i<13;i++){uint8_t p[40];unsigned n=read_packet(f,p);reject(p,n,2);reject(p,n,3);}\n assert(original_n==26);\n for(unsigned bit=0;bit<original_n*8;bit++){\n  original[bit/8]^=1u<<(7-bit%8);reject(original,original_n,2);original[bit/8]^=1u<<(7-bit%8);\n }\n for(unsigned revision=0;revision<8;revision++)if(revision!=2&&revision!=3)reject(original,original_n,revision);\n reject(NULL,26,2);reject(original,0,2);reject(original,25,2);reject(original,256,2);\n assert(!msm5xxx_access_service_request(original,original_n,2,NULL));\n for(unsigned i=0;i<256;i++){\n  uint8_t head[4],expect[24],out[24];assert(fread(head,1,4,f)==4&&fread(expect,1,24,f)==24);\n  assert(msm5xxx_traffic_service_response(head[0]|((unsigned)head[1]<<8),head[2],head[3],out));\n  assert(!memcmp(out,expect,24));MSM5xxxTrafficResponse state;\n  assert(msm5xxx_traffic_response_init(&state,out,24)&&state.sequence==head[3]&&state.pending&&!state.delivered);\n }\n assert(fgetc(f)==EOF);fclose(f);\n uint8_t out[24],before[24];memset(out,0xa5,24);memcpy(before,out,24);\n assert(!msm5xxx_traffic_service_response(3,8,0,out)&&!memcmp(out,before,24));\n assert(!msm5xxx_traffic_service_response(3,0,8,out)&&!memcmp(out,before,24));\n assert(!msm5xxx_traffic_service_response(3,0,0,NULL));\n puts("PASS 48body accepts,26CRC-valid badbody rejects,208bit errors,revision/length/null atomicity;256exact response vectors/CRCs/lifecycleinitialization");\n}\n')
            subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O1','-g','-Wall','-Wextra',
                            '-Werror','-fsanitize=address,undefined','-I',str(native),str(p/'test.c'),
                            str(native/'msm5xxx-search2.c'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test'),str(p/'vectors')],check=True,timeout=20)

    def test_native_request_owner_and_profiles(self):
        import hashlib
        native=Path(__file__).resolve().parents[1]/'experiments/qemu-tcg'
        fixtures=Path(__file__).resolve().parents[2]/'firmwares'
        cases=(('x350_VC22.bin','7a6a4df853b51a4b44e86c3334330c12facad2954eef5a94031724ff1ff44073'),
               ('schx150.bin','347057aeb9985579bb31c64e7fa20dc18486b7fb59aea82a682d4b10d9711de0'))
        if not all((fixtures/name).is_file() for name,_ in cases):self.skipTest('original packet/profile ROM fixtures unavailable')
        for name,digest in cases:self.assertEqual(hashlib.sha256((fixtures/name).read_bytes()).hexdigest(),digest)
        source=(native/'msm5xxx-poc.c').read_text()
        harness='\n#include "msm5xxx-search2.h"\n#include <assert.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#define G_N_ELEMENTS(x) (sizeof(x)/sizeof((x)[0]))\ntypedef struct{uint64_t ram_size;} MachineState;\ntypedef struct{\n MachineState parent;uint32_t primary_nor_size,ram_base;uint32_t tx_init_route[7];uint64_t tx_frame_period_ns;\n bool traffic_service_enabled,traffic_service_request_valid,traffic_service_tx_seen;\n uint32_t traffic_service_route[4],traffic_service_reject_reason;\n uint8_t traffic_service_request_sequence,traffic_service_next_sequence,traffic_service_revision;\n uint16_t traffic_service_option;\n uint64_t traffic_service_requests,traffic_service_rejections,traffic_service_duplicates;\n bool decoder_traffic_frame_enabled,decoder_traffic_response_seen;\n uint8_t decoder_traffic_frame[24],tx_traffic_bytes[24],tx_traffic_length;\n bool tx_traffic_open;\n MSM5xxxTrafficResponse decoder_traffic_response;\n MSM5xxxAccess tx_access;\n} MSM5xxxPOCMachineState;\n#define MACHINE(s) (&(s)->parent)\nstatic uint8_t *rom,revision;static size_t rom_size;static unsigned reads;\nstatic uint16_t lduw_le_p(const uint8_t*p){return p[0]|((uint16_t)p[1]<<8);}\nstatic void cpu_physical_memory_read(uint32_t address,void*out,size_t size){\n reads++;\n if(address==0x13800ac&&size==1){*(uint8_t*)out=revision;return;}\n assert(address<=rom_size&&size<=rom_size-address);memcpy(out,rom+address,size);\n}\nstatic uint32_t msm5xxx_poc_guest_u32(uint32_t address){uint8_t b[4];cpu_physical_memory_read(address,b,4);return b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24);}\n'
        for marker in ['static bool msm5xxx_poc_class_literal(MSM5xxxPOCMachineState *s,', 'static bool msm5xxx_poc_decoder_bl(MSM5xxxPOCMachineState *s,\n', 'static bool msm5xxx_poc_tx_traffic_callback(MSM5xxxPOCMachineState *s,', 'static void msm5xxx_poc_traffic_service_clear(', 'static bool msm5xxx_poc_traffic_service_addresses(', 'static bool msm5xxx_poc_traffic_service_layout(', 'static void msm5xxx_poc_traffic_service_request(']:
            start=source.index(marker);harness+=source[start:source.index('\n}',start)+2]+'\n'
        harness+='static const uint8_t packet0[26]={26,4,0,2,64,0,0,0,0,0,0,0,0,0,0,0,16,0,48,6,36,96,42,210,27,5};\nstatic const uint8_t packet1[26]={26,4,4,2,64,0,0,0,0,0,0,0,0,0,0,0,16,0,48,6,36,96,63,133,227,243};\nstatic const uint8_t packet2[26]={26,4,4,2,64,0,0,0,0,0,0,0,0,0,0,0,16,0,16,6,36,96,5,228,60,47};\n\nstatic void feed(MSM5xxxPOCMachineState*s,const uint8_t*p){\n msm5xxx_access_init(&s->tx_access);bool accepted=false;\n for(unsigned off=0;off<26;off+=11){uint8_t piece[11]={0};unsigned n=26-off<11?26-off:11;memcpy(piece,p+off,n);accepted=msm5xxx_access_push(&s->tx_access,piece,11);}\n assert(accepted);msm5xxx_poc_traffic_service_request(s);\n}\nint main(int argc,char**argv){\n assert(argc==3);static const uint32_t routes[2][4]={{0x1081c,0xf71e,0x11638,0x13800ac},{0x1086c,0xf76e,0x11688,0x13800ac}};\n static const uint32_t tx[2][7]={{0xa7fb0,0x1383190,0x13e1fc4,0x13d5c68,0xa8026,0x30258,0xa7e4a},{0xa7b94,0x1382f98,0x13e3e78,0x13d7894,0xa7c08,0x30328,0xa7a2e}};\n for(unsigned c=0;c<2;c++){\n  FILE*f=fopen(argv[c+1],"rb");assert(f&&!fseek(f,0,SEEK_END));long size=ftell(f);assert(size>0);rewind(f);rom_size=size;rom=malloc(rom_size);assert(rom&&fread(rom,1,rom_size,f)==rom_size);fclose(f);\n  MSM5xxxPOCMachineState s={.parent={0x800000},.ram_base=0x1000000,.primary_nor_size=rom_size};\n  unsigned before=reads;msm5xxx_poc_traffic_service_request(&s);assert(reads==before);\n  memcpy(s.tx_init_route,tx[c],sizeof(s.tx_init_route));s.tx_frame_period_ns=20000000;memcpy(s.traffic_service_route,routes[c],sizeof(s.traffic_service_route));s.traffic_service_enabled=true;assert(msm5xxx_poc_traffic_service_layout(&s));\n  s.traffic_service_route[3]^=1;assert(!msm5xxx_poc_traffic_service_layout(&s));s.traffic_service_route[3]^=1;\n  rom[routes[c][0]]^=1;assert(!msm5xxx_poc_traffic_service_layout(&s));rom[routes[c][0]]^=1;\n  uint32_t cb;assert(msm5xxx_poc_class_literal(&s,s.tx_init_route[0]+0x5a,1,&cb));\n  rom[cb&~1u]^=1;revision=2;feed(&s,packet0);\n  assert(s.traffic_service_reject_reason==6&&!s.traffic_service_request_valid&&!s.decoder_traffic_frame_enabled);\n  rom[cb&~1u]^=1;\n  revision=2;feed(&s,packet0);assert(s.traffic_service_requests==1&&s.traffic_service_option==3&&s.traffic_service_request_valid&&s.decoder_traffic_response.pending&&s.traffic_service_next_sequence==1);\n  uint8_t frame[24];memcpy(frame,s.decoder_traffic_frame,24);\n  MSM5xxxPOCMachineState unsupported=s;feed(&unsupported,packet2);\n  assert(unsupported.traffic_service_reject_reason==2&&!unsupported.decoder_traffic_response.pending&&!unsupported.decoder_traffic_frame_enabled);\n  assert(s.decoder_traffic_response.pending&&s.traffic_service_request_valid);\n\n  feed(&s,packet0);assert(s.traffic_service_requests==1&&s.traffic_service_duplicates==1&&!memcmp(frame,s.decoder_traffic_frame,24));\n  feed(&s,packet1);assert(s.traffic_service_reject_reason==3&&s.traffic_service_requests==1&&!memcmp(frame,s.decoder_traffic_frame,24));\n  s.traffic_service_tx_seen=true;s.decoder_traffic_response_seen=true;feed(&s,packet1);\n  assert(s.traffic_service_requests==2&&s.decoder_traffic_response.sequence==1&&!s.traffic_service_tx_seen);\n  msm5xxx_poc_traffic_service_clear(&s);assert(!s.traffic_service_request_valid&&!s.decoder_traffic_frame_enabled&&!s.decoder_traffic_response.pending&&!s.tx_traffic_open);\n  revision=3;feed(&s,packet1);assert(s.traffic_service_requests==3&&s.decoder_traffic_response.sequence==2&&s.traffic_service_next_sequence==3);\n  s.traffic_service_tx_seen=true;feed(&s,packet2);\n  assert(s.traffic_service_reject_reason==2&&!s.traffic_service_request_valid&&!s.decoder_traffic_frame_enabled);\n  msm5xxx_poc_traffic_service_clear(&s);revision=6;feed(&s,packet0);assert(s.traffic_service_reject_reason==1&&!s.traffic_service_request_valid&&!s.decoder_traffic_frame_enabled);\n  revision=2;feed(&s,packet2);assert(s.traffic_service_reject_reason==2&&!s.traffic_service_request_valid&&!s.decoder_traffic_frame_enabled);\n  msm5xxx_poc_traffic_service_clear(&s);s.traffic_service_next_sequence=7;feed(&s,packet0);\n  assert(s.decoder_traffic_response.sequence==7&&s.traffic_service_next_sequence==0);\n  msm5xxx_poc_traffic_service_clear(&s);feed(&s,packet1);\n  assert(s.decoder_traffic_response.sequence==0&&s.traffic_service_next_sequence==1);\n  free(rom);\n }\n puts("PASS two ROM native profiles,FIFO-API ownership/revision/defaultoff/duplicate/busy/reset/unsupported-service guards");\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'test.c').write_text(harness)
            subprocess.run([os.environ.get('CC','cc'),'-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I',str(native),str(p/'test.c'),
                            str(native/'msm5xxx-search2.c'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test'),*(str(fixtures/name) for name,_ in cases)],check=True,timeout=20)
