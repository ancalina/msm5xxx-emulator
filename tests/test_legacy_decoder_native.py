"""Exercise legacy decoded FIFO selection and interrupt cadence."""
from pathlib import Path
import subprocess
import tempfile
import unittest


def packet(kind, length):
    bits = [0] * (length * 8)
    for at, value in ((0, length), (8, kind)):
        bits[at:at+8] = [(value >> (7-i)) & 1 for i in range(8)]
    crc = 0x3fffffff
    for bit in bits[:-30]:
        feedback = (crc >> 29 ^ bit) & 1
        crc = ((crc << 1) ^ (0x6030b9c7 if feedback else 0)) & 0x3fffffff
    crc ^= 0x3fffffff
    bits[-30:] = [(crc >> (29-i)) & 1 for i in range(30)]
    return bytes(sum(bits[i+j] << (7-j) for j in range(8)) for i in range(0,len(bits),8))


class LegacyDecoderNativeTests(unittest.TestCase):
    def test_fifo_and_roll(self):
        native = Path(__file__).resolve().parents[1] / 'native/qemu'
        source = (native/'msm5xxx-poc.c').read_text()
        start = source.index('static void msm5xxx_poc_legacy_decoder_tick(')
        end = source.index('static uint64_t msm5xxx_poc_sbi_read(', start)
        code = source[start:end]
        harness = r'''
#include "msm5xxx-search2.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t hwaddr;
typedef struct {int unused;} MemoryRegion;
typedef struct {int64_t deadline; bool armed;} QEMUTimer;
typedef struct {uint64_t (*read)(void *,hwaddr,unsigned);void (*write)(void *,hwaddr,uint64_t,unsigned);int endianness;struct{int min_access_size,max_access_size;}valid,impl;} MemoryRegionOps;
#define DEVICE_LITTLE_ENDIAN 0
#define QEMU_CLOCK_VIRTUAL 0
#define G_N_ELEMENTS(x) (sizeof(x)/sizeof((x)[0]))
typedef struct {
 uint64_t legacy_epoch,legacy_clock_origin,legacy_roll,legacy_frame;
 uint16_t legacy_decoder_mode,legacy_decoder_words[14],legacy_combiner,rex_irq_pending[1];
 uint8_t legacy_sync[26],legacy_paging[4][255],legacy_paging_lengths[4];
 unsigned legacy_decoder_cursor;QEMUTimer *legacy_decoder_timer,*legacy_roll_timer;MemoryRegion msm;
} MSM5xxxPOCMachineState;
static int64_t now;
static uint8_t backing[4096];
static int64_t qemu_clock_get_ns(int x){(void)x;return now;}
static void timer_mod(QEMUTimer *t,int64_t d){t->deadline=d;t->armed=true;}
static void timer_del(QEMUTimer *t){t->armed=false;}
static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState*s){(void)s;}
static uint8_t* memory_region_get_ram_ptr(MemoryRegion*m){(void)m;return backing;}
static uint64_t msm5xxx_poc_backing_read(uint8_t*b,hwaddr o,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)b[o+i]<<(8*i);return v;}
static void msm5xxx_poc_backing_write(uint8_t*b,hwaddr o,uint64_t v,unsigned n){for(unsigned i=0;i<n;i++)b[o+i]=v>>(8*i);}
'''
        harness += code
        sync = packet(1,26)
        pagings = [packet(k,5) for k in (1,2,14,4)]
        arr = lambda data: ','.join(str(x) for x in data)
        harness += f'''
int main(void) {{
 MSM5xxxPOCMachineState s={{0}};QEMUTimer decoder={{0}},roll={{0}};
 s.legacy_decoder_timer=&decoder;s.legacy_roll_timer=&roll;
 uint8_t sync[]={{ {arr(sync)} }};memcpy(s.legacy_sync,sync,sizeof sync);
'''
        for i, p in enumerate(pagings):
            harness += f'uint8_t p{i}[]={{ {arr(p)} }};memcpy(s.legacy_paging[{i}],p{i},sizeof p{i});s.legacy_paging_lengths[{i}]=sizeof p{i};\n'
        harness += r'''
 msm5xxx_poc_legacy_decoder_write(&s,8,0x40,2);
 assert(decoder.armed && decoder.deadline==80000000);
 now=decoder.deadline;msm5xxx_poc_legacy_decoder_tick(&s);
 assert(s.rex_irq_pending[0]==0x10 && s.legacy_frame==1);
 uint16_t expected[8];assert(msm5xxx_sync_clock_frame(s.legacy_sync,26,0,0,expected));
 msm5xxx_poc_legacy_decoder_write(&s,0x58,0,2);
 for(unsigned i=0;i<6;i++)assert(msm5xxx_poc_legacy_decoder_read(&s,0x10,2)==expected[i]);
 msm5xxx_poc_legacy_decoder_write(&s,0x58,6,2);
 assert(msm5xxx_poc_legacy_decoder_read(&s,0x10,2)==0);
 now=decoder.deadline;msm5xxx_poc_legacy_decoder_tick(&s);
 assert(s.legacy_frame==1); /* Preserve an unread frame while IRQ is pending. */
 s.rex_irq_pending[0]=0;
 now=decoder.deadline;msm5xxx_poc_legacy_decoder_tick(&s);assert(s.legacy_frame==2);
 msm5xxx_poc_legacy_decoder_write(&s,8,0x20,2);
 assert(s.legacy_frame==0 && decoder.deadline==now+20000000);
 s.rex_irq_pending[0]=0;now=decoder.deadline;msm5xxx_poc_legacy_decoder_tick(&s);
 assert(s.legacy_frame==1 && (s.rex_irq_pending[0]&0x10));
 s.legacy_clock_origin=0;s.legacy_roll=1;now=msm5xxx_combiner_deadline(1);
 msm5xxx_poc_legacy_roll_tick(&s);assert(s.rex_irq_pending[0]&0x100);
 assert(roll.deadline==(int64_t)msm5xxx_combiner_deadline(2));
 msm5xxx_poc_legacy_combiner_write(&s,0,0,1);
 uint64_t snap=msm5xxx_poc_legacy_combiner_read(&s,4,2);
 now+=10000;assert(msm5xxx_poc_legacy_combiner_read(&s,4,2)==snap);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory);(path/'test.c').write_text(harness)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Wno-unused-const-variable','-Werror',
                            '-I',str(native),str(path/'test.c'),str(native/'msm5xxx-search2.c'),
                            '-o',str(path/'test')],check=True)
            subprocess.run([str(path/'test')],check=True)
