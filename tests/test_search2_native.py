"""Compile the real search transport core; supply results, never RF assumptions."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from corpus import FIRMWARE_ROOT


class Search2NativeTests(unittest.TestCase):
    def test_machine_probe_gate_timer_irq_and_native_fallback(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        source = (native / "msm5xxx-poc.c").read_text()
        start = source.index("static bool msm5xxx_poc_radio_irq_gate(")
        # Keep all coupled search/decoder callbacks, ending at their own final ops.
        last_ops = source.index("static const MemoryRegionOps msm5xxx_poc_decoder_init_ops = {", start)
        functions = source[start:source.index("\n};", last_ops) + len("\n};")]
        mmio_start = source.index("static bool msm5xxx_poc_mmio_access_pc(")
        mmio_end = source.index("\n}", mmio_start) + len("\n}")
        mmio = source[mmio_start:mmio_end] + "\n"
        branch_start = source.index("static bool msm5xxx_poc_arm_b_target(")
        branch = source[branch_start:
                        source.index("static uint32_t msm5xxx_poc_guest_u32(", branch_start)]
        harness = r'''
#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "msm5xxx-search2.h"
typedef uint32_t hwaddr;
typedef struct { bool armed; int64_t deadline; } QEMUTimer;
typedef struct { uintptr_t mem_io_pc; } CPUState;
static CPUState test_cpu={1};
static CPUState *current_cpu=&test_cpu;
static int raw_pc_delta;
static bool unwind_available=true, pc_relative=true;
#define INSN_START_WORDS 3
#define CF_PCREL 0x20000
static int qemu_target_page_mask(void) { return -4096; }
static bool tcg_cflags_has(CPUState *cpu,unsigned flags) { (void)cpu;assert(flags==CF_PCREL);return pc_relative; }
typedef struct { uint32_t (*get_pc)(CPUState *); } CPUClass;
static uint32_t current_pc;
static uint32_t get_pc(CPUState *cpu) { (void)cpu; return current_pc+raw_pc_delta; }
static bool cpu_unwind_state_data(CPUState *cpu,uintptr_t pc,uint64_t *data) {
    assert(cpu==&test_cpu && pc==1);
    data[0]=pc_relative ? (current_pc&4095) : current_pc;
    data[1]=data[2]=0;
    return unwind_available;
}
static CPUClass cpu_class={get_pc};
#define CPU_GET_CLASS(cpu) (&cpu_class)
#define CPU(cpu) (cpu)
#define QEMU_CLOCK_VIRTUAL 0
#define DEVICE_LITTLE_ENDIAN 0
#define G_N_ELEMENTS(a) (sizeof(a)/sizeof((a)[0]))
static int64_t now=1000000;
static int64_t qemu_clock_get_ns(int unused) { (void)unused; return now; }
static void timer_mod(QEMUTimer *t, int64_t deadline) { t->armed=true; t->deadline=deadline; }
static void timer_del(QEMUTimer *t) { t->armed=false; }
static uint8_t rom[0x4000], ram[0x1000], backing[0x1000];
static uint16_t lduw_le_p(const uint8_t *p) { return p[0]|(p[1]<<8); }
static void *memory_region_get_ram_ptr(void *mr) { (void)mr; return backing; }
static void cpu_physical_memory_read(uint32_t address, void *out, size_t size) {
    if (address<sizeof(rom) && size<=sizeof(rom)-address) memcpy(out,rom+address,size);
    else {
        assert(address>=0x1000000 && address-0x1000000<=sizeof(ram)-size);
        memcpy(out,ram+address-0x1000000,size);
    }
}
static uint32_t msm5xxx_poc_guest_u32(uint32_t a) {
    uint8_t b[4];cpu_physical_memory_read(a,b,4);
    return b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;
}
static uint64_t msm5xxx_poc_backing_read(uint8_t *b, hwaddr off, unsigned size) {
    uint64_t v=0;assert(off+size<=sizeof(backing));
    for (unsigned i=0;i<size;i++) v|=(uint64_t)b[off+i]<<(8*i);
    return v;
}
static void msm5xxx_poc_backing_write(uint8_t *b, hwaddr off, uint64_t v, unsigned size) {
    assert(off+size<=sizeof(backing));
    for (unsigned i=0;i<size;i++) b[off+i]=v>>(8*i);
}
typedef struct {
    uint64_t ram_size;
} MachineState;
typedef struct {
    MachineState parent;
    bool rex_irq_enabled,rex_irq_c80,rex_irq_read_consume;
    unsigned rex_irq_bank_count;
    uint32_t rex_irq_status_address,rex_irq_enable_address;
    uint16_t rex_irq_pending[2];
    bool search2_probe_done,search2_probe_rejected;
    uint32_t search2_route[9],ram_base;
    MSM5xxxSearch2 search2;
    uint32_t search2_reject_pc,search2_reject_value;
    uint32_t search2_reject_reason,search2_reject_expected_pc;
    bool search2_virtual;
    uint32_t search2_position,search2_pending_position,search2_pilot_phase;
    uint16_t search2_peak_energy;
    uint16_t search2_samples[8];
    uint64_t search2_submits,search2_completions,search2_result_reads,search2_rejections;
    int64_t search2_delay_ns;
    QEMUTimer *search2_timer;
    CPUState *cpu;
    unsigned msm;
    bool decoder_sync_enabled,decoder_sync_have_frame,combiner_position_latched;
    uint32_t combiner_position_reader,combiner_roll_isr,decoder_sync_consumer;
    uint64_t decoder_sync_epoch,decoder_sync_roll,decoder_sync_frames;
    uint64_t decoder_sync_reads,decoder_sync_overruns,combiner_position_latches;
    uint16_t decoder_sync_words[14],combiner_position_snapshot;
    uint8_t decoder_sync_message[MSM5XXX_SYNC_MAX_BYTES],decoder_sync_message_length;
    unsigned decoder_sync_cursor;
    QEMUTimer *tx_init_timer;
    uint32_t tx_init_route[7];
    uint64_t tx_init_delay_ns,tx_init_fires,tx_init_cancels;
    uint64_t tx_frame_period_ns,tx_frame_fires,tx_frame_overruns;
    int64_t tx_init_deadline;
    uint8_t *rex_irq_backing;
    bool tx_init_enabled,tx_init_active,tx_init_seen,tx_init_owned_pending;
    bool tx_frame_running;
    uint8_t tx_init_last_mode;
    MSM5xxxAccess tx_access;
    uint32_t tx_fifo_mode_base,tx_fifo_writer;
    uint32_t tx_fifo_reject_reason,tx_fifo_reject_pc;
    uint64_t tx_fifo_rejections;
    uint8_t tx_fifo_bytes[12],tx_fifo_length;
    bool tx_fifo_enabled,tx_fifo_open,tx_fifo_rejected;
    MSM5xxxPagingStream access_paging;
    uint64_t access_ack_queued,access_ack_encoded,access_ack_rejections;
    uint64_t access_ack_resets;
    uint32_t access_ack_reject_reason;
    uint8_t access_station_sequence,access_assignment_code;
    bool access_response_probe,access_response_blocked;
    bool decoder_traffic_enabled, decoder_traffic_frame_enabled;
    bool decoder_traffic_response_enabled,decoder_traffic_response_seen;
    MSM5xxxTrafficResponse decoder_traffic_response;
    uint64_t decoder_traffic_acks,decoder_traffic_ack_rejections;
    uint64_t decoder_traffic_response_frames;
    bool traffic_service_enabled,traffic_service_request_valid,traffic_service_tx_seen;
    uint32_t traffic_service_route[4],traffic_service_reject_reason;
    uint8_t traffic_service_request_sequence,traffic_service_next_sequence,traffic_service_revision;
    uint16_t traffic_service_option;
    uint64_t traffic_service_requests,traffic_service_rejections,traffic_service_duplicates;
    uint8_t tx_traffic_bytes[24],tx_traffic_length;
    bool tx_traffic_open;
    uint8_t decoder_traffic_frame[24];
    uint32_t decoder_traffic_route[8], decoder_traffic_reject_reason;
    uint16_t decoder_traffic_words[MSM5XXX_TRAFFIC_MAX_WORDS];
    unsigned decoder_traffic_count;
    uint64_t decoder_traffic_frames, decoder_traffic_reads;
    uint64_t decoder_traffic_crc_passes, decoder_traffic_crc_failures;
    uint64_t decoder_traffic_frame_rejections;
    bool decoder_paging_enabled,decoder_paging_started;
    uint32_t decoder_paging_isr,decoder_paging_reader,decoder_paging_status;
    uint32_t decoder_paging_initializer,decoder_paging_count,decoder_paging_consumer;
    uint32_t decoder_paging_cache,decoder_paging_layout;
    uint8_t decoder_paging_messages[MSM5XXX_PAGING_MESSAGES][MSM5XXX_PAGING_MAX_BYTES];
    uint8_t decoder_paging_lengths[MSM5XXX_PAGING_MESSAGES];
    uint64_t decoder_radio_tick,decoder_paging_frames,decoder_paging_bootstraps;
    QEMUTimer *decoder_init_timer;
    bool decoder_init_enabled,decoder_init_active,decoder_init_done;
    uint32_t decoder_init_reader,decoder_init_write_pc,decoder_init_isr,decoder_init_mask,decoder_init_reject_reason;
    uint64_t decoder_init_delay_ns,decoder_init_fires,decoder_init_rejections;
    uint16_t rex_irq_mask;
    MSM5xxxFingers fingers;
    bool finger_enabled;
    uint32_t finger_read_pc,finger_masks_i,finger_masks_q;
    uint64_t finger_latches,finger_reads,finger_fallback_writes;
    uint64_t primary_nor_size;
    QEMUTimer *search1_timer;
    bool search1_enabled,search1_active,search1_have_results,search1_rejected;
    uint32_t search1_first_store,search1_result_loop,search1_position,search1_pending_position;
    uint8_t search1_packet[MSM5XXX_SEARCH1_PARAMETERS];
    bool search1_conditional,search1_config_valid,search1_config_known;
    uint8_t search1_verified_config[4];
    unsigned search1_sub,search1_selector;
    uint16_t search1_results[8],search1_pending_results[8];
    uint64_t search1_submits,search1_completions,search1_result_reads,search1_rejections;
    uint32_t search1_reject_reason,search1_reject_pc,search1_reject_access,search1_reject_value;
    uint32_t search1_abort_pc;uint64_t search1_aborts;
} MSM5xxxPOCMachineState;
#define MACHINE(state) (&(state)->parent)
static unsigned irq_updates;
static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s) { (void)s;irq_updates++; }
typedef struct {
    uint64_t (*read)(void *,hwaddr,unsigned);
    void (*write)(void *,hwaddr,uint64_t,unsigned);
    unsigned endianness;
    struct { unsigned min_access_size,max_access_size; } valid,impl;
} MemoryRegionOps;
''' + mmio + branch + functions + r'''
static void set32(uint8_t *p, uint32_t v) {
    for (unsigned i=0;i<4;i++) p[i]=v>>(i*8);
}
static void set16(uint8_t *p,uint16_t v) {p[0]=v;p[1]=v>>8;}
static void literal(unsigned pc,unsigned pool,unsigned reg,uint32_t value) {
    assert(pool>=((pc+4)&~3u) && !((pool-((pc+4)&~3u))&3));
    set16(rom+pc,0x4800|(reg<<8)|((pool-((pc+4)&~3u))/4));set32(rom+pool,value);
}
static void bl(unsigned pc,unsigned target) {
    uint32_t d=target-(pc+4);set16(rom+pc,0xf000|((d>>12)&0x7ff));set16(rom+pc+2,0xf800|((d>>1)&0x7ff));
}
static void initialize(MSM5xxxPOCMachineState *s,QEMUTimer *timer) {
    memset(s,0,sizeof(*s)); memset(ram,0,sizeof(ram)); memset(backing,0,sizeof(backing));
    *timer=(QEMUTimer){0};s->search2_timer=timer;
    s->cpu=&test_cpu;current_cpu=&test_cpu;raw_pc_delta=0;unwind_available=true;pc_relative=true;
    s->rex_irq_enabled=true;s->rex_irq_bank_count=2;s->rex_irq_backing=backing;
    s->rex_irq_status_address=0x3000620;s->rex_irq_enable_address=0x3000628;
    s->ram_base=0x1000000;s->parent.ram_size=sizeof(ram);
    s->tx_init_last_mode=UINT8_MAX;
    uint32_t route[]={0x100,0x200,0x1000100,0x300,0x400,0x1000104,0x500,0x600,0x80};
    memcpy(s->search2_route,route,sizeof(route));s->search2_delay_ns=1000;
    for (unsigned i=0;i<8;i++) s->search2_samples[i]=0x110+i;
    const uint8_t writer[]={0x8e,0x80,0x04,0x9a,0x8a,0x80,0x03,0x9a,0x8a,0x80,0x8c,0x80,
        0xc2,0x08,0x8a,0x80,0x3a,0x7a,0x40,0x03,0x92,0x02,0x10,0x43,
        0xba,0x7a,0x12,0x02,0x10,0x43,0x7a,0x7a,0x10,0x43,0x88,0x80};
    const uint8_t reader[]={0xb5,0x89,0x4a,0,0x12,0x18,0x95,0x85,0xb5,0x89,1,0x31,
        9,6,9,0x16,4,0x29,0x95,0x84,0xf4,0xdb};
    memcpy(rom+0x100,writer,sizeof(writer));memcpy(rom+0x200,reader,sizeof(reader));
    set32(rom+0x18,0xea000000|(((0x1000000-0x20)/4)&0xffffff));
    set32(ram,0xea000000|(((0x600u-0x1000008u)/4)&0xffffff));
    set32(ram+0x100,0x301);set32(ram+0x104,0x501);
    msm5xxx_search2_init(&s->search2);
    msm5xxx_poc_search2_ops.write(s,20,3,1);
}
static void submit(MSM5xxxPOCMachineState *s) {
    unsigned sites[]={0,4,8,10,14,34};
    uint16_t packet[]={0xffbe,0x56a5,0x465c,0,63,0xe000};
    for (unsigned i=0;i<6;i++) {
        current_pc=0x100+sites[i];
        msm5xxx_poc_search2_ops.write(s,4,packet[i],2);
        if (i<5) assert(!s->search2_timer->armed);
    }
}
int main(void) {
    MSM5xxxPOCMachineState s;QEMUTimer timer;
    memset(&s,0,sizeof s);assert(!msm5xxx_poc_traffic_service_layout(&s));
    initialize(&s,&timer);assert(msm5xxx_poc_search2_gate(&s));
    backing[0x8c]=4;
    assert(msm5xxx_poc_fingers_ops.read(&s,0x2c,2)==4);
    msm5xxx_poc_fingers_ops.write(&s,0x2c,7,1);
    assert(backing[0x8c]==7 && s.fingers.filter_gain==0 && !s.finger_latches);
    s.rex_irq_pending[0]=0x10;submit(&s);
    assert(s.search2_submits==1 && timer.armed && timer.deadline==now+1000);
    assert(!s.search2_completions && s.rex_irq_pending[0]==0x10);
    now=timer.deadline;msm5xxx_poc_search2_complete(&s);
    assert(s.search2_completions==1 && s.rex_irq_pending[0]==0x90 && irq_updates==1);
    assert(msm5xxx_poc_search2_ops.read(&s,8,1)==2);
    assert(msm5xxx_poc_search2_ops.read(&s,8,1)==0);
    for (unsigned i=0;i<8;i++) assert(msm5xxx_poc_search2_ops.read(&s,12,2)==0x110+i);
    assert(s.search2_result_reads==8 && !s.search2_rejections);
    backing[0x818]=0x5a;
    assert(msm5xxx_poc_search2_ops.read(&s,24,1)==0x5a);

    initialize(&s,&timer);current_pc=0x102;
    msm5xxx_poc_search2_ops.write(&s,4,0x8000,2);
    assert(s.search2_probe_rejected && s.search2_rejections==1 && !timer.armed);
    assert(!s.search2.queue_sub && backing[0x805]==0x80);
    assert(s.search2_reject_reason==MSM5XXX_SEARCH2_REJECT_WRITER);
    assert(s.search2_reject_pc==0x102 && s.search2_reject_expected_pc==0x100);
    assert(s.search2_reject_value==0x8000);

    initialize(&s,&timer);raw_pc_delta=-2;submit(&s);
    assert(s.search2_submits==1 && timer.armed && !s.search2_rejections);
    assert(raw_pc_delta==-2); /* Access-PC lookup never rewrites raw CPU state. */
    initialize(&s,&timer);pc_relative=false;raw_pc_delta=-2;submit(&s);
    assert(s.search2_submits==1 && !s.search2_rejections);
    initialize(&s,&timer);unwind_available=false;current_pc=0x100;
    msm5xxx_poc_search2_write(&s,4,0x8000,2);
    assert(s.search2_probe_rejected && !s.search2.queue_sub && !timer.armed);
    initialize(&s,&timer);current_cpu=NULL;current_pc=0x100;
    msm5xxx_poc_search2_write(&s,4,0x8000,2);
    assert(s.search2_probe_rejected && !s.search2.queue_sub && !timer.armed);
    initialize(&s,&timer);submit(&s);
    msm5xxx_poc_search2_ops.write(&s,0,1,1);
    assert(!timer.armed && s.search2_probe_rejected && !s.rex_irq_pending[0]);
    initialize(&s,&timer);submit(&s);set32(ram+0x104,0);
    msm5xxx_poc_search2_complete(&s);
    assert(!s.search2_completions && !s.rex_irq_pending[0] && s.search2_rejections==1);
    initialize(&s,&timer);rom[0x100]^=1;
    assert(!msm5xxx_poc_search2_gate(&s));
    backing[0x808]=0x73;assert(msm5xxx_poc_search2_ops.read(&s,8,1)==0x73);
    initialize(&s,&timer);s.rex_irq_read_consume=true;
    assert(!msm5xxx_poc_search2_gate(&s));

    initialize(&s,&timer);s.search2_virtual=true;
    s.search2_peak_energy=64000;s.search2_pilot_phase=0;
    /* Real dummy packet advances residual -1; read aliases are not FIFO backing. */
    submit(&s);msm5xxx_poc_search2_complete(&s);
    assert(s.search2_position==511 && s.search2_completions==1);
    assert(msm5xxx_poc_search2_read(&s,0,2)==511);
    assert(msm5xxx_poc_search2_read(&s,4,2)==0);
    for (unsigned i=0;i<8;i++) assert(msm5xxx_poc_search2_read(&s,12,2)==0);
    uint16_t packet[]={0xffbe,0x56a5,0x465c,4,0,0};
    unsigned sites[]={0,4,8,10,14,34};
    for (unsigned n=0;n<9;n++) {
        for (unsigned i=0;i<6;i++) {
            current_pc=0x100+sites[i];
            msm5xxx_poc_search2_write(&s,4,packet[i],2);
        }
        assert(s.search2_submits==n+2);
    }
    assert(s.search2.active && s.search2.queued_records==8);
    for (unsigned n=0;n<8;n++) msm5xxx_poc_search2_complete(&s);
    assert(s.search2.result_records==8 && !s.search2.active);
    assert(s.search2.queued_records==1 && s.search2_position==639);
    assert(msm5xxx_poc_search2_read(&s,12,2)==49000);
    assert(msm5xxx_poc_search2_read(&s,12,2)==0);
    for (unsigned i=2;i<8;i++) assert(msm5xxx_poc_search2_read(&s,12,2)==0);
    assert(s.search2.active && !s.search2.queued_records);
    msm5xxx_poc_search2_complete(&s);
    assert(s.search2_position==655 && s.search2_completions==10);
    assert(!s.search2_rejections && s.search2.result_records==8);
    for (unsigned n=0;n<8;n++) {
        for (unsigned i=0;i<8;i++) assert(msm5xxx_poc_search2_read(&s,12,2)==0);
    }
    assert(!s.search2.result_records);
    s.search2_position=0x3ffff;
    assert(msm5xxx_poc_search2_read(&s,0,2)==0xffff);
    assert(msm5xxx_poc_search2_read(&s,4,2)==3);

    initialize(&s,&timer);QEMUTimer legacy_timer={0};
    s.search2_virtual=true;s.search2_peak_energy=64000;s.search2_pilot_phase=0x1fc28;
    s.search1_enabled=true;s.search1_first_store=0x700;s.search1_result_loop=0x900;
    s.search1_timer=&legacy_timer;s.primary_nor_size=sizeof(rom);
    const uint16_t ops[]={0x700a,0x7108,0x7010,0x7308,0x7101,0x7201,0x7301,0x7110,
        0x7211,0x7310,0x7003,0x7102,0x7201,0x7301,0x7008,0x7108,0x7208};
    const uint8_t loop[]={0x08,0x72,0x8b,0x88,0x42,0x00,0xd2,0x19,0x93,0x85,0x8b,0x89,
        1,0x30,0,4,0,0x14,4,0x28,0x93,0x84,0xf3,0xdb};
    for (unsigned i=0;i<17;i++) {rom[0x700+search1_sites[i]]=ops[i];rom[0x701+search1_sites[i]]=ops[i]>>8;}
    memcpy(rom+0x900,loop,sizeof(loop));memcpy(rom+0x726,"\x03\x20\x00\x06",4);
    int deltas[]={-4,8,14,112,134,152};unsigned regs[]={1,2,1,2,0,1};
    uint32_t values[]={0x3000040,0x3000010,0x3000030,0x3000010,0x3000020,0x3000030};
    for (unsigned i=0;i<6;i++) {
        unsigned pc=0x700+deltas[i],slot=0xa00+i*4;
        uint16_t op=0x4800|(regs[i]<<8)|((slot-((pc+4)&~3u))/4);
        rom[pc]=op;rom[pc+1]=op>>8;set32(rom+slot,values[i]);
    }
    assert(msm5xxx_poc_search1_gate(&s));
    const uint8_t bytes[]={0,1,0x20,1,0x32,0xad,0,0x10,0x7e,0x3f,0x52,0x13,0x3f,0x76,0,0,0};
    for (unsigned i=0;i<17;i++) {
        current_pc=0x700+search1_sites[i];
        msm5xxx_poc_search1_ops.write(&s,search1_offsets[i],bytes[i],1);
        if (i<16) assert(!legacy_timer.armed);
    }
    assert(s.search1_active && !s.search1_have_results && s.search1_submits==1 && legacy_timer.armed);
    assert(!s.search1_completions && s.search1_position==0 && !s.rex_irq_pending[0]);
    msm5xxx_poc_search1_complete(&s);
    assert(!s.search1_active && s.search1_completions==1 && s.search1_position==1024);
    assert(s.search2.status==1 && s.rex_irq_pending[0]==0x80);
    for (unsigned i=0;i<4;i++) {
        current_pc=0x900;msm5xxx_poc_search1_write(&s,0x48,i,1);
        current_pc=0x902;assert(msm5xxx_poc_search1_read(&s,0x44,2)==(i==0 ? 64000 : 0));
        current_pc=0x90a;assert(msm5xxx_poc_search1_read(&s,0x4c,2)==(i==0 ? 10 : 0));
    }
    assert(s.search1_result_reads==8 && !s.search1_rejections);
    for (unsigned i=0;i<17;i++) {
        current_pc=0x700+search1_sites[i];
        msm5xxx_poc_search1_write(&s,search1_offsets[i],bytes[i],1);
    }
    assert(s.search1_active && s.search1_results[0]==64000 && s.search1_pending_results[0]==0);
    msm5xxx_poc_search1_complete(&s);
    assert(s.search1_position==2048 && s.search1_results[0]==0);

    /* A firmware-qualified teardown cancels only this search and can be retried. */
    s.search1_abort_pc=0x183e;
    const uint8_t abort_body[]={0xf0,0xb5,0x1e,0x4c,0x00,0x27,0x20,0x79,0x1d,0x4e,0x1e,0x4d,0x00,0x28,0x02,0xd1,0x28,0x78,0x00,0x28,0x1e,0xd0,0x6f,0x70,0x1a,0xf1,0xd6,0xf8,0x29,0x78,0x00,0x04,0x00,0x0c,0x00,0x29,0x07,0xd0,0x18,0x49,0x02,0x23,0x0a,0x88,0x1a,0x43,0x32,0x70,0x09,0x88,0x19,0x43,0x31,0x70,0x21,0x79,0x00,0x29,0x02,0xd0,0x13,0x49,0x0f,0x70,0x0f,0x71,0x00,0x28,0x01,0xd1,0x1a,0xf1,0xcd,0xf8,0x11,0x49,0x09,0x20,0x08,0x80,0x27,0x71,0x2f,0x70,0x30,0x7a,0xff,0xf7,0xbd,0xfb,0x01,0x20,0x68,0x70,0x0d,0x4d,0x01,0x21,0x28,0x1c,0xeb,0xf7,0xb6,0xfd,0x0b,0x48,0xeb,0xf7,0xec,0xfd,0x01,0x21,0xc9,0x02,0x28,0x1c,0xeb,0xf7,0xae,0xfd,0x27,0x60,0xf0,0xbd};
    memcpy(rom+0x1800,abort_body,sizeof(abort_body));
    literal(0x1802,0x1880,4,0x1000700);literal(0x180a,0x1884,5,0x1000720);
    literal(0x1808,0x1888,6,0x3000800);literal(0x183c,0x188c,1,0x3000040);
    literal(0x184a,0x1890,1,0x4800020);
    literal(0x1826,0x1894,1,0x1000740);literal(0x1868,0x1898,0,0x1000760);literal(0x185e,0x189c,5,0x1000780);
    const unsigned abort_calls[]={0x1818,0x1846,0x1856,0x1864,0x186a,0x1874};
    for(unsigned i=0;i<6;i++)bl(abort_calls[i],0x800);

    literal(0x8da,0x980,5,0x1000700);literal(0x404,0x484,1,0x1000720);
    set32(ram+0x700,0x1000800);ram[0x704]=1;
    assert(msm5xxx_poc_search1_abort_gate(&s));
    for(unsigned i=0;i<17;i++) {
        current_pc=0x700+search1_sites[i];msm5xxx_poc_search1_write(&s,search1_offsets[i],bytes[i],1);
    }
    assert(s.search1_active&&legacy_timer.armed);
    uint32_t abort_position=s.search1_position;s.rex_irq_pending[0]=0x90;s.search2.status=3;
    current_pc=0x183e;msm5xxx_poc_search1_write(&s,0x40,0,2);
    assert(s.search1_active&&legacy_timer.armed&&!s.search1_aborts);
    msm5xxx_poc_search1_write(&s,0x40,0,1);
    assert(!s.search1_active&&!s.search1_have_results&&!legacy_timer.armed&&!s.search1_rejected);
    assert(s.search1_aborts==1&&!s.search1_sub&&!s.search1_selector);
    assert(s.search1_position==abort_position&&s.rex_irq_pending[0]==0x90&&s.search2.status==2);
    current_pc=0x1840;msm5xxx_poc_search1_write(&s,0x44,0,1);
    assert(s.search1_aborts==1);msm5xxx_poc_search1_complete(&s);
    assert(!s.search1_rejections&&s.search1_completions==2&&s.rex_irq_pending[0]==0x90);
    for(unsigned i=0;i<17;i++) {
        current_pc=0x700+search1_sites[i];msm5xxx_poc_search1_write(&s,search1_offsets[i],bytes[i],1);
    }
    assert(s.search1_active&&legacy_timer.armed);msm5xxx_poc_search1_complete(&s);
    assert(s.search1_completions==3&&!s.search1_rejections);
    rom[0x183e]^=1;assert(!msm5xxx_poc_search1_abort_gate(&s));rom[0x183e]^=1;
    rom[0x180c]^=1;assert(!msm5xxx_poc_search1_abort_gate(&s));rom[0x180c]^=1;
    ram[0x704]=0;assert(!msm5xxx_poc_search1_abort_gate(&s));ram[0x704]=1;

    literal(0x404,0x484,1,0x1000730);assert(!msm5xxx_poc_search1_abort_gate(&s));literal(0x404,0x484,1,0x1000720);
    current_pc=0x700;msm5xxx_poc_search1_write(&s,0x40,0,1);
    current_pc=0x706;msm5xxx_poc_search1_write(&s,0x44,1,1);
    assert(s.search1_rejected && s.search1_rejections==1 && !legacy_timer.armed);
    assert(s.search1_reject_reason==4&&s.search1_reject_pc==0x706);
    assert(s.search1_reject_access==0x10044&&s.search1_reject_value==1);
    s.search1_active=true;msm5xxx_poc_search1_complete(&s);
    assert(s.search1_rejections==2&&s.search1_reject_reason==4&&s.search1_reject_pc==0x706);
    assert(s.search1_reject_access==0x10044&&s.search1_reject_value==1);


    initialize(&s,&timer);s.search2_virtual=true;s.primary_nor_size=sizeof(rom);
    QEMUTimer decoder_timer={0};s.decoder_init_timer=&decoder_timer;
    s.decoder_init_enabled=true;s.decoder_init_reader=0xa00;
    s.decoder_init_write_pc=0xc34;s.decoder_init_isr=0xd00;
    s.decoder_init_delay_ns=80000000;s.rex_irq_mask=0x200;
    uint16_t init_reader[]={0xb500,0x4a0f,0x2100,0x8311,0x2206,0x1c01,0x480d,0xf000,0xf877,0xbd00};
    for(unsigned i=0;i<10;i++){rom[0xa00+2*i]=init_reader[i];rom[0xa01+2*i]=init_reader[i]>>8;}
    set32(rom+0xa40,0x3000a40);set32(rom+0xa44,0x3000a70);
    const uint8_t copy_code[]={0x90,0xb5,0,0x23,4,0xe0,4,0x88,0x1f,0x1c,
        0x7f,0,0xcc,0x53,1,0x33,0x93,0x42,0xf8,0xdb,0x90,0xbd};
    memcpy(rom+0xb00,copy_code,sizeof(copy_code));
    uint32_t d=0xa00u-(0xd56u+4);
    set32(rom+0xd56,(0xf000|((d>>12)&0x7ff))|((0xf800|((d>>1)&0x7ff))<<16));
    const uint16_t init_writer[]={0x88b9,0x4b15,0x4019,0x80b9,0x88b9,0x8121};
    for(unsigned i=0;i<6;i++){rom[0xc2a+2*i]=init_writer[i];rom[0xc2b+2*i]=init_writer[i]>>8;}
    rom[0xc10]=0x1b;rom[0xc11]=0x4c;
    memcpy(rom+0xc12,"\x19\x40\x40\x23\x19\x43\xb9\x80\xb9\x88\x21\x81",12);
    set32(rom+0xc80,0x3000a00);set32(rom+0xc84,0xfff8);
    set32(ram+0xd0,0x3000620);set32(ram+0xd4,0x3000628);
    set32(ram+0xd8,0x10);set32(ram+0xe4,0xd01);
    uint32_t mask=0;assert(msm5xxx_poc_decoder_init_gate(&s,&mask)&&mask==0x10);
    current_pc=0xc34;raw_pc_delta=-2;
    msm5xxx_poc_decoder_init_ops.write(&s,0,0x40,2);
    assert(s.decoder_init_active && decoder_timer.armed && decoder_timer.deadline==now+80000000);
    assert(!s.rex_irq_pending[0] && !s.decoder_init_fires);
    msm5xxx_poc_decoder_init_complete(&s);
    assert(s.decoder_init_done && !s.decoder_init_active && s.decoder_init_fires==1);
    assert(s.rex_irq_pending[0]==0x10 && msm5xxx_poc_decoder_init_ops.read(&s,0,2)==0x40);
    msm5xxx_poc_decoder_init_complete(&s);assert(s.decoder_init_fires==1);
    msm5xxx_poc_decoder_init_ops.write(&s,0,0x40,2);assert(!s.decoder_init_active);
    s.decoder_init_done=false;s.rex_irq_pending[0]=0;
    msm5xxx_poc_decoder_init_write(&s,0,0x40,2);assert(s.decoder_init_active);
    msm5xxx_poc_decoder_init_write(&s,0,0,1);
    assert(!s.decoder_init_active && !decoder_timer.armed);
    msm5xxx_poc_decoder_init_complete(&s);assert(!s.rex_irq_pending[0]);
    current_pc=0xc32;msm5xxx_poc_decoder_init_write(&s,0,0x40,2);
    assert(!s.decoder_init_active);
    current_pc=0xc34;rom[0xb06]^=1;
    msm5xxx_poc_decoder_init_write(&s,0,0x40,2);assert(!s.decoder_init_active);rom[0xb06]^=1;
    set32(ram+0xd8,0x30);assert(!msm5xxx_poc_decoder_init_gate(&s,&mask));set32(ram+0xd8,0x10);
    msm5xxx_poc_decoder_init_write(&s,0,0x40,2);assert(s.decoder_init_active);
    set32(ram+0xe4,0xd03);msm5xxx_poc_decoder_init_complete(&s);
    assert(!s.decoder_init_active && !s.rex_irq_pending[0] && s.decoder_init_fires==1);
    s.decoder_init_enabled=false;assert(!msm5xxx_poc_decoder_init_gate(&s,&mask));

    s.decoder_init_enabled=true;set32(ram+0xe4,0xd01);
    s.decoder_sync_enabled=true;s.combiner_position_reader=0xe00;s.combiner_roll_isr=0x500;
    const uint8_t position_code[]={0x08,0xb5,0,0,0,0,1,4,9,0x0c,0x1d,0x48,
        0,0x22,2,0x71,2,0x7a,0,0xab,0x1a,0x70,0,0x7b,0x58,0x70,0,0x29,1,0xd1,
        0,0,0,0,0,0xa8,0,0x88,8,0xbd};
    memcpy(rom+0xe00,position_code,40);set32(rom+0xe80,0x30000f0);
    d=0xe00u-(0x6aau+4);set32(rom+0x6aa,(0xf000|((d>>12)&0x7ff))|((0xf800|((d>>1)&0x7ff))<<16));
    d=0xe00u-(0x7a4u+4);set32(rom+0x7a4,(0xf000|((d>>12)&0x7ff))|((0xf800|((d>>1)&0x7ff))<<16));
    set32(ram+0x60,0x3000620);set32(ram+0x64,0x3000628);set32(ram+0x68,0x100);set32(ram+0x74,0x501);
    const uint8_t sync[]={0x1a,0x01,0x03,0x03,0x24,0x68,0xac,0xf1,0x2a,0x48,0xd1,0x59,0xe2,0x6a,0xc4,0x8d,0x15,0x9e,0x24,0x4a,0x48,0xd1,0x72,0x58,0x21,0xa9};
    memcpy(s.decoder_sync_message,sync,sizeof(sync));s.decoder_sync_message_length=sizeof(sync);
    s.decoder_sync_consumer=0xf00;
    memcpy(rom+0xf16,"\x48\x22\x00\x92\xf8\x1d\x01\x30\x2a\x1c\x18\x23\x00\x21\x06\x1c",16);
    memcpy(rom+0xf42,"\x18\x22\x00\x92\x00\x23\x48\x21\x30\x1c\x2a\x1c",12);
    const unsigned copy_calls[]={0xf26,0xf4e};
    for(unsigned i=0;i<2;i++){d=0x850u-(copy_calls[i]+4);set32(rom+copy_calls[i],(0xf000|((d>>12)&0x7ff))|((0xf800|((d>>1)&0x7ff))<<16));}
    const unsigned get_calls[]={0xf66,0xd0c};
    for(unsigned i=0;i<2;i++){d=0x800u-(get_calls[i]+4);set32(rom+get_calls[i],(0xf000|((d>>12)&0x7ff))|((0xf800|((d>>1)&0x7ff))<<16));}
    assert(msm5xxx_poc_decoder_sync_gate(&s,&mask)&&mask==0x100);
    current_pc=0xc34;s.decoder_init_done=false;msm5xxx_poc_decoder_init_write(&s,0,0x40,2);
    uint64_t epoch=s.decoder_sync_epoch;assert(decoder_timer.deadline==now+26666667);
    for(unsigned roll=1;roll<=12;roll++) {
        now=epoch+msm5xxx_combiner_deadline(roll);s.rex_irq_pending[0]=0;
        msm5xxx_poc_decoder_init_complete(&s);
        assert(s.decoder_sync_roll==roll&&s.decoder_init_active);
        assert(s.rex_irq_pending[0]&0x100);
        assert(!!(s.rex_irq_pending[0]&0x10)==!(roll%3));
        msm5xxx_poc_combiner_position_ops.write(&s,0,0,1);
        uint16_t pos=msm5xxx_poc_combiner_position_ops.read(&s,4,1)|msm5xxx_poc_combiner_position_ops.read(&s,8,1)<<8;
        assert(pos==(roll%3)<<14);
        msm5xxx_poc_combiner_position_ops.write(&s,4,0xaa,1);
        assert(msm5xxx_poc_combiner_position_ops.read(&s,4,1)==(pos&255));
        if(roll==3) assert(s.decoder_init_done&&!s.decoder_sync_have_frame);
        if(roll==6) {
            assert(s.decoder_sync_frames==1&&s.decoder_sync_have_frame);
            msm5xxx_poc_decoder_output_ops.write(&s,0,6,2);
            assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0);
            assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0);
            msm5xxx_poc_decoder_output_ops.write(&s,0,0,2);
            assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0);
            unsigned cursor=s.decoder_sync_cursor;
            msm5xxx_poc_decoder_output_ops.read(&s,0x18,1);assert(s.decoder_sync_cursor==cursor);
            msm5xxx_poc_decoder_output_ops.write(&s,0,8,2);
            msm5xxx_poc_decoder_output_ops.read(&s,0x18,2);assert(s.decoder_sync_cursor==8);
        }
    }
    assert(s.decoder_sync_frames==3);
    /* A disabled decoder and a rejected search queue do not stop PN rolls. */
    set32(ram+0xe4,0);s.search2_probe_rejected=true;
    uint64_t prior_frames=s.decoder_sync_frames;
    for(unsigned roll=13;roll<=15;roll++) {
        now=epoch+msm5xxx_combiner_deadline(roll);s.rex_irq_pending[0]=0;
        msm5xxx_poc_decoder_init_complete(&s);
        assert(s.decoder_init_active&&s.decoder_sync_roll==roll);
        assert(s.rex_irq_pending[0]==0x100&&s.decoder_sync_frames==prior_frames);
    }
    msm5xxx_poc_decoder_init_write(&s,0,0,2);assert(s.decoder_init_active);
    set32(ram+0xe4,0xd01);current_pc=0xc34;
    msm5xxx_poc_decoder_init_write(&s,0,0x40,2);
    assert(s.decoder_init_active&&!s.decoder_init_done&&s.decoder_sync_epoch==epoch&&s.decoder_sync_roll==15);
    assert(s.decoder_sync_frames==0&&decoder_timer.deadline==(int64_t)(epoch+msm5xxx_combiner_deadline(16)));
    set32(ram+0x74,0x503);msm5xxx_poc_decoder_init_complete(&s);
    assert(!s.decoder_init_active&&!s.decoder_sync_have_frame&&s.decoder_init_reject_reason==4);
    /* Paging callback bootstrap uses the original IRQ; it cannot write guest RAM. */
    set32(ram+0x74,0x501);set32(ram+0xe4,0xd01);
    s.decoder_paging_enabled=true;s.decoder_paging_reader=0x1000;s.decoder_paging_status=0x1100;
    s.decoder_paging_initializer=0x1200;s.decoder_paging_isr=0x1400;
    s.decoder_paging_consumer=0x1700;s.decoder_paging_count=0x1000400;
    memcpy(rom+0x1000,"\x00\xb5",2);literal(0x1002,0x1080,2,0x3000a40);
    memcpy(rom+0x1004,"\x00\x21\x11\x83",4);literal(0x1008,0x1084,1,s.decoder_paging_count);
    memcpy(rom+0x100a,"\x0a\x88\x01\x1c",4);literal(0x100e,0x1088,0,0x3000a70);
    bl(0x1010,0xb00);set16(rom+0x1014,0xbd00);
    literal(0x1100,0x1180,1,s.decoder_paging_count);literal(0x1102,0x1184,2,0x3000a40);
    memcpy(rom+0x1104,"\x09\x88\x11\x83",4);literal(0x1108,0x1188,2,0x3000a60);
    memcpy(rom+0x110a,"\x11\x8a\x41\x70\x09\x12\x01\x70\x11\x8a\x41\x80\xf7\x46",14);
    set16(rom+0x1210,0x88a1);literal(0x120e,0x1280,3,0xff9f);
    literal(0x1212,0x1284,5,0x3000a00);
    memcpy(rom+0x1214,"\x19\x40\x20\x23\x19\x43\xa1\x80\xa1\x88\x29\x81",12);
    set16(rom+0x122c,0x88a1);literal(0x122e,0x1288,3,0xfff8);
    memcpy(rom+0x1230,"\x19\x40\xa1\x80\xa1\x88\x29\x81",8);bl(0x1204,0x1300);
    literal(0x1302,0x1380,1,s.decoder_paging_count);
    memcpy(rom+0x1304,"\x00\x28\x03\xd0\x01\x28\x04\xd1\x06\x20\x00\xe0\x0c\x20\x08\x80",16);
    bl(0x14da,0x1100);bl(0x1562,0x1000);bl(0x15e2,0x1200);
    memcpy(rom+0x1746,"\xa2\x88\x00\x21\x28\x1c\x00\x92\x63\x88\x32\x1c",12);
    bl(0x1754,0x850);bl(0x1786,0x850);
    s.decoder_paging_cache=0x1000500;s.decoder_paging_layout=0x1800;
    memcpy(rom+0x170e,"\xf5\x1f\x11\x3d\xec\x1d\x2f\x34",8);
    const unsigned cache_sites[]={0x170c,0x171a,0x1728,0x1730,0x173e,0x1752,0x1796};
    const unsigned cache_regs[]={6,0,1,0,0,7,7};
    for(unsigned i=0;i<7;i++)literal(cache_sites[i],0x1b00+i*4,cache_regs[i],s.decoder_paging_cache+(i?0:0x22));
    memcpy(rom+0x1718,"\xf9\x1d",2);memcpy(rom+0x171c,"\x01\x31\x18\x22\x28\x1c",6);
    memcpy(rom+0x177a,"\x62\x88\x00\x23\x28\x1c\x00\x92\xa1\x88\x32\x1c",12);
    bl(0x17c6,0x800);literal(0x15c0,0x16a0,0,0x1000600);literal(0x17c4,0x1b40,0,0x1000600);
    memcpy(rom+0x1800,"\xc0\x20\x00\xe0\x60\x20\x48\x87",8);
    set16(rom+0x180a,0x2048);literal(0x17fa,0x1b80,1,s.decoder_paging_cache);
    literal(0x1808,0x1b84,5,s.decoder_paging_cache+0x40);literal(0x180c,0x1b88,1,s.decoder_paging_cache);
    memcpy(rom+0x180e,"\xa8\x80\x48\x8f\x48\x38\x68\x80\x4e\x8f\x70\x08\x00\x04\x00\x0c\x88\x87",18);


static const uint8_t messages[4][255] = {
{0x21,0x01,0x00,0x00,0x00,0x07,0xff,0xfc,0x00,0x00,0x00,0x00,0x40,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2a,0xa8,0x00,0x00,0x1c,0x81,0x10,0x09,0x79,0xa5,0xea},
{0x13,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x80,0x15,0x0f,0x55,0x01},
{0x09,0x03,0x00,0x00,0x20,0x2d,0xdb,0x83,0x55},
{0x09,0x04,0x00,0x00,0x07,0x7f,0x20,0x13,0x58},
};
static const uint8_t lengths[4]={33,19,9,9};

    memcpy(s.decoder_paging_messages,messages,sizeof(messages));memcpy(s.decoder_paging_lengths,lengths,4);
    current_pc=0xc34;msm5xxx_poc_decoder_init_write(&s,0,0x40,2);
    assert(s.decoder_init_active&&s.decoder_radio_tick==0);
    epoch=s.decoder_sync_epoch;assert(decoder_timer.deadline==(int64_t)epoch+6666667);
    set32(ram+0xe4,0x1401);assert(msm5xxx_poc_decoder_paging_gate(&s,&mask)&&mask==0x10);
    uint8_t saved_ram[sizeof(ram)];memcpy(saved_ram,ram,sizeof(ram));
    for(unsigned tick=1;tick<=12;tick++) {
        now=epoch+msm5xxx_radio_deadline(tick);s.rex_irq_pending[0]=0;
        msm5xxx_poc_decoder_init_complete(&s);
        assert(s.decoder_radio_tick==tick&&s.decoder_sync_roll==tick/4);
        assert(!!(s.rex_irq_pending[0]&0x100)==!(tick%4));
        assert(!!(s.rex_irq_pending[0]&0x10)==(tick==12));
    }
    assert(s.decoder_paging_bootstraps==1&&!s.decoder_paging_started&&!s.decoder_sync_have_frame);
    assert(!memcmp(ram,saved_ram,sizeof(ram)));
    /* Only firmware count/mode writes unlock a valid frame, both rates. */
    for(unsigned rate=0;rate<2;rate++) {
        unsigned count=rate?6:12;set16(ram+0x400,count);
        msm5xxx_poc_backing_write(backing,0xa40,96,2);
        current_pc=0x1234;msm5xxx_poc_decoder_init_write(&s,0,0x20,2);
        if(!rate)assert(!s.decoder_paging_started);
        uint64_t frame0=s.decoder_paging_frames;
        current_pc=0x1236;msm5xxx_poc_decoder_init_write(&s,0,0x20,2);
        assert(s.decoder_paging_started&&s.decoder_paging_frames==frame0);
        uint64_t tick0=s.decoder_radio_tick;
        for(unsigned i=1;i<=3;i++) {
            now=epoch+msm5xxx_radio_deadline(tick0+i);s.rex_irq_pending[0]=0;
            msm5xxx_poc_decoder_init_complete(&s);
            assert(!!(s.rex_irq_pending[0]&0x10)==(i==3));
        }
        assert(s.decoder_paging_frames==frame0+1&&s.decoder_sync_have_frame);
        uint16_t expected[14];assert(msm5xxx_paging_decoder_frame(messages,lengths,rate,frame0,expected));
        msm5xxx_poc_decoder_output_write(&s,0,0,2);
        for(unsigned i=0;i<count+2;i++)assert(msm5xxx_poc_decoder_output_read(&s,0x18,2)==expected[i]);
        assert(s.decoder_sync_cursor==count+2);
        unsigned cursor=s.decoder_sync_cursor;msm5xxx_poc_decoder_output_read(&s,0x18,1);
        assert(s.decoder_sync_cursor==cursor);
        /* Receiver reconfiguration must not rewind the transmitter's carry. */
        uint64_t frames=s.decoder_paging_frames,tick=s.decoder_radio_tick;
        current_pc=0x1236;msm5xxx_poc_decoder_init_write(&s,0,0x20,2);
        assert(s.decoder_paging_frames==frames&&s.decoder_radio_tick==tick);
        assert(!s.decoder_sync_have_frame&&s.decoder_sync_epoch==epoch);
        for(unsigned i=1;i<=3;i++) {
            now=epoch+msm5xxx_radio_deadline(tick+i);s.rex_irq_pending[0]=0;
            msm5xxx_poc_decoder_init_complete(&s);
        }
        assert(s.decoder_paging_frames==frames+1&&s.decoder_sync_have_frame);
        assert(msm5xxx_paging_decoder_frame(messages,lengths,rate,frames,expected));
        msm5xxx_poc_decoder_output_write(&s,0,0,2);
        for(unsigned i=0;i<count+2;i++)assert(msm5xxx_poc_decoder_output_read(&s,0x18,2)==expected[i]);
    }
    rom[0x110a]^=1;assert(!msm5xxx_poc_decoder_paging_gate(&s,&mask));rom[0x110a]^=1;
    rom[0x1710]^=1;assert(!msm5xxx_poc_decoder_paging_gate(&s,&mask));rom[0x1710]^=1;
    rom[0x1812]^=1;assert(!msm5xxx_poc_decoder_paging_gate(&s,&mask));rom[0x1812]^=1;
    uint64_t ticks=s.decoder_radio_tick;set32(ram+0xe4,0x1601);s.rex_irq_pending[0]=0x10;
    msm5xxx_poc_decoder_init_complete(&s);assert(s.decoder_radio_tick==ticks+1&&!(s.rex_irq_pending[0]&0x10));
    assert(!s.decoder_paging_started&&!s.decoder_sync_have_frame);

    /* Original traffic driver class: descriptor-backed erasure, never qualified data. */
    static const uint8_t traffic_reader[]={0xf0,0xb5,0x04,0x1c,0x17,0x1c,0x24,0x48,0xc9,0x00,0x08,0x18,0xc5,0x1f,0x09,0x3d,0x00,0x2a,0x20,0x4e,0x01,0xd0,0x01,0x2f,0x0c,0xd1,0x28,0x7a,0x40,0x08,0x30,0x83,0x28,0x7b,0x40,0x08,0x02,0x04,0x12,0x0c,0x21,0x1c,0x1c,0x48,0x4e,0xf0,0xde,0xf9,0x00,0x2f,0x01,0xd0,0x02,0x2f,0x0d,0xd1,0x68,0x7a,0x40,0x08,0x30,0x83,0x68,0x7b,0x40,0x08,0x02,0x04,0x12,0x0c,0xe1,0x1d,0x1d,0x31,0x14,0x48,0x4e,0xf0,0xce,0xf9,0x00,0x2f,0x01,0xd0,0x03,0x2f,0x0d,0xd1,0xa8,0x7a,0x40,0x08,0x30,0x83,0xa8,0x7b,0x40,0x08,0x02,0x04,0x12,0x0c,0xe1,0x1d,0x2f,0x31,0x0c,0x48,0x4e,0xf0,0xbe,0xf9,0x00,0x2f,0x01,0xd0,0x04,0x2f,0x0b,0xd1,0xe8,0x7a,0x40,0x08,0x30,0x83,0xe8,0x7b,0x40,0x08,0x02,0x04,0x12,0x0c,0xe1,0x1d,0x39,0x31,0x04,0x48,0x4e,0xf0,0xae,0xf9,0xf0,0xbd};
    static const uint8_t traffic_metrics[]={0xb0,0xb5,0x1d,0x4a,0xc0,0x00,0x80,0x18,0xc2,0x1f,0x09,0x3a,0x50,0x7a,0x1b,0x4b,0x40,0x08,0x02,0x38,0x18,0x83,0x1a,0x48,0x07,0x8a,0x0f,0x71,0x3f,0x12,0x0f,0x70,0x07,0x8a,0x0f,0x81,0x97,0x7a,0x7f,0x08,0x02,0x3f,0x1f,0x83,0x07,0x8a,0x4f,0x71,0x3f,0x12,0x4f,0x70,0x07,0x8a,0x4f,0x81,0xd7,0x7a,0x7f,0x08,0x02,0x3f,0x1f,0x83,0x07,0x8a,0x8f,0x71,0x3f,0x12,0x8f,0x70,0x07,0x8a,0x8f,0x81,0xd7,0x7a,0xd2,0x7b,0x7f,0x08,0x52,0x08,0xba,0x18,0x1a,0x83,0x02,0x8a,0xca,0x71,0x12,0x12,0xca,0x70,0x00,0x8a,0xc8,0x81,0x48,0x79,0x40,0x00,0x48,0x71,0x88,0x79,0x80,0x00,0x88,0x71,0xc8,0x79,0xc0,0x00,0xc8,0x71,0xb0,0xbd};
    static const uint8_t traffic_init[]={0xb0,0xb5,0x07,0x1c,0xff,0xf7,0x96,0xfb,0x8d,0xf1,0x7e,0xfe,0x26,0x4c,0x27,0x4b,0xa1,0x88,0x27,0x4d,0x19,0x40,0x20,0x23,0x19,0x43,0xa1,0x80,0xa1,0x88,0x29,0x81,0x00,0x28,0x01,0xd1,0x8d,0xf1,0x7e,0xfe,0x8d,0xf1,0x6e,0xfe,0xa1,0x88,0x21,0x4b,0x19,0x40,0xa1,0x80,0xa1,0x88,0x29,0x81,0x00,0x28,0x01,0xd1,0x8d,0xf1,0x72,0xfe,0x1d,0x4d,0x1e,0x4c,0x03,0x2f,0x0c,0xdb,0x8d,0xf1,0x5e,0xfe,0x21,0x8a,0x1c,0x4b,0x19,0x40,0x02,0x23,0x19,0x43,0x21,0x82,0x21,0x8a,0x29,0x80,0x00,0x28,0x0c,0xd1,0x09,0xe0,0x8d,0xf1,0x51,0xfe,0x21,0x8a,0x15,0x4b,0x19,0x40,0x21,0x82,0x21,0x8a,0x29,0x80,0x00,0x28,0x01,0xd1,0x8d,0xf1,0x55,0xfe,0x12,0x48,0x5f,0xf0,0xca,0xf8,0x00,0x28,0x07,0xd1,0x38,0x1c,0x00,0xf0,0x4f,0xf9,0x01,0x21,0x38,0x1c,0x00,0xf0,0x4f,0xfa,0xb0,0xbd,0x00,0x21,0x01,0x72,0x0b,0x4a,0x07,0x73,0x01,0x1c,0x10,0x1c,0x5f,0xf0,0xa7,0xf8,0xb0,0xbd};

    memcpy(rom+0x2000,traffic_reader,sizeof(traffic_reader));
    memcpy(rom+0x2100,traffic_metrics,sizeof(traffic_metrics));
    memcpy(rom+0x2200,traffic_init,sizeof(traffic_init));
    const uint8_t traffic_callback[]={0xf0,0xb5,0x86,0xb0,0xf4,0x48,0x00,0x88,0x84,0x06,0xa4,0x0e,0x03,0x2c};
    memcpy(rom+0x2400,traffic_callback,sizeof(traffic_callback));
    uint32_t traffic_route[]={0x2400,0x2000,0x2100,0x2200,0x1000700,0x1000800,0x3700,0x3f00};
    memcpy(s.decoder_traffic_route,traffic_route,sizeof(traffic_route));
    literal(0x2006,0x20a0,0,0x1000808);literal(0x2012,0x20a4,6,0x3000a40);
    for(unsigned i=0;i<4;i++){literal(0x202a+0x20*i,0x20a8,0,0x3000a70);bl(0x202c+0x20*i,0xb00);}
    literal(0x2102,0x2180,2,0x1000808);literal(0x210e,0x2184,3,0x3000a40);
    literal(0x2116,0x2188,0,0x3000a60);
    literal(0x220e,0x22b0,3,0xffdf);literal(0x2212,0x22b4,5,0x3000a00);
    literal(0x222e,0x22b8,3,0xfff8);literal(0x2240,0x22bc,5,0x3000a60);
    literal(0x2404,0x2600,0,0x3000a60);literal(0x2418,0x2604,0,0x1000700);
    bl(0x241e,0x2100);bl(0x258c,0x2000);
    static const uint8_t traffic_rows[]={
        0,0,0,0,0,0,0,0,0,28,44,54,24,12,6,4,
        0,40,62,76,36,18,10,6,0,28,44,56,24,12,8,4,
        0,28,44,56,24,12,8,4,0,40,62,76,36,18,10,6};
    memcpy(rom+0x3700,traffic_rows,sizeof(traffic_rows));
    memcpy(ram+0x800,traffic_rows,sizeof(traffic_rows));
    set32(rom+0x3f00,0x2f00);set32(rom+0x3f04,0x1000000);set32(rom+0x3f08,0x1000);
    ram[0x701]=1;set16(ram+0x702,0xffff);set32(ram+0xe4,0x2401);
    msm5xxx_poc_backing_write(backing,0xa08,0x20,2);
    assert(!s.decoder_traffic_enabled&&!msm5xxx_poc_decoder_traffic_gate(&s,&mask));
    s.decoder_traffic_enabled=true;
    assert(msm5xxx_poc_decoder_traffic_gate(&s,&mask)&&mask==0x10&&!s.decoder_traffic_reject_reason);
    assert(!msm5xxx_poc_decoder_paging_gate(&s,&mask)&&!msm5xxx_poc_decoder_init_gate(&s,&mask));
    for(unsigned i=0;i<MSM5XXX_TRAFFIC_MAX_WORDS;i++)s.decoder_traffic_words[i]=0xa5a5;
    uint64_t traffic_tick=s.decoder_radio_tick,traffic_fires=s.decoder_init_fires;
    memcpy(saved_ram,ram,sizeof(ram));s.rex_irq_pending[0]=0x200;
    for(unsigned i=1;i<=3;i++){
        now=epoch+msm5xxx_radio_deadline(traffic_tick+i);
        msm5xxx_poc_decoder_init_complete(&s);
        assert(s.decoder_radio_tick==traffic_tick+i&&s.decoder_init_active);
        assert(s.rex_irq_pending[0]&0x200);
        if(!((traffic_tick+i)%3))assert(s.rex_irq_pending[0]&0x10);
    }
    assert(s.decoder_traffic_frames==1&&s.decoder_traffic_count==31&&s.decoder_sync_have_frame);
    assert(s.decoder_init_fires==traffic_fires+1&&(s.rex_irq_pending[0]&0x10));
    assert(!memcmp(saved_ram,ram,sizeof(ram)));
    for(unsigned i=0;i<31;i++)assert(!s.decoder_traffic_words[i]);
    for(unsigned i=31;i<MSM5XXX_TRAFFIC_MAX_WORDS;i++)assert(s.decoder_traffic_words[i]==0xa5a5);
    msm5xxx_poc_backing_write(backing,0xa70,0x44336b5a,4);
    msm5xxx_poc_decoder_output_ops.write(&s,0,0,2);
    assert(msm5xxx_poc_decoder_output_ops.read(&s,0,2)==0);
    uint64_t reads=s.decoder_traffic_reads;
    assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,1)==0x5a&&!s.decoder_sync_cursor);
    assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,4)==0x44336b5a&&!s.decoder_sync_cursor);
    for(unsigned i=0;i<31;i++)assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0);
    assert(s.decoder_traffic_reads==reads+31&&s.decoder_sync_cursor==31);
    assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0x6b5a&&s.decoder_sync_cursor==31);
    /* Original metric selectors address only zero erasure metadata, not good flags. */
    const unsigned metric_selectors[]={12,20,25,29};
    for(unsigned i=0;i<4;i++){
        msm5xxx_poc_decoder_output_ops.write(&s,0,metric_selectors[i],2);
        assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0);
        assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0);
    }
    assert(s.decoder_traffic_reads==reads+39);
    msm5xxx_poc_decoder_output_ops.write(&s,0,31,2);
    assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0x6b5a&&s.decoder_sync_cursor==31);
    assert(msm5xxx_poc_decoder_output_ops.read(&s,0x1a,2)==0x4433&&s.decoder_sync_cursor==31);
    assert(s.decoder_traffic_reads==reads+39);
    /* An explicit decoded codeword supplies payload and CRC, never guest state. */
    s.decoder_traffic_frame_enabled=true;
    s.decoder_traffic_frame[21]=3;s.decoder_traffic_frame[22]=0xd7;
    for(unsigned bad=0;bad<2;bad++){
        s.decoder_traffic_frame[0]=bad?0x80:0;
        uint64_t frames=s.decoder_traffic_frames;
        s.rex_irq_pending[0]&=~0x10;
        do{now+=6666667;msm5xxx_poc_decoder_init_complete(&s);}
        while(s.decoder_radio_tick%3);
        assert(s.decoder_traffic_frames==frames+1&&s.decoder_traffic_count==31);
        assert(s.rex_irq_pending[0]&0x10);
        assert(s.decoder_traffic_crc_passes==1&&s.decoder_traffic_crc_failures==bad);
        assert(!s.decoder_traffic_frame_rejections&&!memcmp(saved_ram,ram,sizeof(ram)));
        msm5xxx_poc_decoder_output_ops.write(&s,0,0,2);
        for(unsigned i=0;i<31;i++){
            unsigned expected=i<12?s.decoder_traffic_frame[2*i]|(s.decoder_traffic_frame[2*i+1]<<8):
                (i==12&&!bad?0x100:0);
            assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==expected);
        }
    }
    {
        MSM5xxxPOCMachineState old_state=s;QEMUTimer old_timer=timer;
        int64_t old_now=now;unsigned old_irq=irq_updates;
        s.traffic_service_enabled=true;s.decoder_traffic_response_enabled=true;
        s.traffic_service_request_valid=true;s.traffic_service_tx_seen=false;
        s.decoder_traffic_response_seen=false;s.decoder_traffic_response_frames=0;
        assert(msm5xxx_traffic_service_response(3,0,0,s.decoder_traffic_frame));
        assert(msm5xxx_traffic_response_init(&s.decoder_traffic_response,s.decoder_traffic_frame,24));
        do{now+=6666667;msm5xxx_poc_decoder_init_complete(&s);}while(s.decoder_radio_tick%3);
        /* A receiver may need the service response before enabling its transmitter. */
        assert(s.decoder_traffic_response.pending&&s.decoder_traffic_response.delivered);
        assert(s.decoder_traffic_response_frames==1&&!s.traffic_service_tx_seen);
        s.traffic_service_tx_seen=true;
        do{now+=6666667;msm5xxx_poc_decoder_init_complete(&s);}while(s.decoder_radio_tick%3);
        assert(s.decoder_traffic_response.delivered&&s.decoder_traffic_response_frames==2);
        s.decoder_traffic_response.pending=false;
        ram[0x701]=4;now+=6666667;msm5xxx_poc_decoder_init_complete(&s);ram[0x701]=1;
        do{now+=6666667;msm5xxx_poc_decoder_init_complete(&s);}while(s.decoder_radio_tick%3);
        assert(!s.decoder_traffic_response.pending&&s.decoder_traffic_response_frames==2);
        assert(s.decoder_traffic_words[0]==0xb0&&s.decoder_traffic_words[12]==0x100);
        s=old_state;timer=old_timer;now=old_now;irq_updates=old_irq;
        puts("automatic response does not wait for dependentTXhandoff / ACK does not replay across RX callback gap PASS");
    }
    s.decoder_traffic_frame_enabled=false;
    /* Every rejected route leaves the port on native backing without cursor progress. */
    for(unsigned mode=0;mode<6;mode++)if(mode!=1){
        ram[0x701]=mode;assert(!msm5xxx_poc_decoder_traffic_gate(&s,&mask));
        assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0x6b5a&&s.decoder_sync_cursor==31);
    }
    ram[0x701]=1;
    for(unsigned submode=0;submode<2;submode++){
        set16(ram+0x702,submode?0xffff:3);assert(msm5xxx_poc_decoder_traffic_gate(&s,&mask));
    }
    const unsigned traffic_mutations[]={0x2000,0x2013,0x210c,0x2200,0x241e,0x258c,0xb06,0x20a8,0x2184,0x22bc};
    for(unsigned i=0;i<G_N_ELEMENTS(traffic_mutations);i++){
        rom[traffic_mutations[i]]^=1;assert(!msm5xxx_poc_decoder_traffic_gate(&s,&mask));
        assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0x6b5a&&s.decoder_sync_cursor==31);
        rom[traffic_mutations[i]]^=1;
    }
    ram[0x808]^=2;assert(!msm5xxx_poc_decoder_traffic_gate(&s,&mask));ram[0x808]^=2;
    rom[0x3708]^=2;assert(!msm5xxx_poc_decoder_traffic_gate(&s,&mask));rom[0x3708]^=2;
    set32(ram+0xd8,0x20);assert(!msm5xxx_poc_decoder_traffic_gate(&s,&mask));set32(ram+0xd8,0x10);
    rom[0x3f04]^=4;assert(!msm5xxx_poc_decoder_traffic_gate(&s,&mask));rom[0x3f04]^=4;
    msm5xxx_poc_backing_write(backing,0xa08,0x40,2);assert(!msm5xxx_poc_decoder_traffic_gate(&s,&mask));
    msm5xxx_poc_backing_write(backing,0xa08,0x20,2);
    assert(msm5xxx_poc_decoder_traffic_gate(&s,&mask));
    /* A matching but invalid descriptor cannot turn into an output frame or IRQ. */
    ram[0x808]=rom[0x3708]=2;s.rex_irq_pending[0]=0x210;
    uint64_t erasures=s.decoder_traffic_frames;
    while(s.decoder_radio_tick%3!=2){now+=6666667;msm5xxx_poc_decoder_init_complete(&s);}
    now+=6666667;msm5xxx_poc_decoder_init_complete(&s);
    assert(s.decoder_traffic_frames==erasures&&!s.decoder_traffic_count&&!s.decoder_sync_have_frame);
    assert(s.decoder_traffic_reject_reason==4&&!(s.rex_irq_pending[0]&0x10)&&(s.rex_irq_pending[0]&0x200));
    assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0x6b5a);
    ram[0x808]=rom[0x3708]=0;
    /* Withdrawal drops only the owned decoder IRQ/output, never other pending bits. */
    set32(ram+0xe4,0x1601);s.rex_irq_pending[0]=0x210;
    now+=6666667;msm5xxx_poc_decoder_init_complete(&s);
    assert(!s.decoder_sync_have_frame&&!s.decoder_traffic_count&&s.decoder_traffic_frames==erasures);
    assert(!(s.rex_irq_pending[0]&0x10)&&(s.rex_irq_pending[0]&0x200));
    assert(msm5xxx_poc_decoder_output_ops.read(&s,0x18,2)==0x6b5a);

    /* Explicit one-shot init event: real gate, no firmware-state writes. */
    initialize(&s,&timer);s.primary_nor_size=sizeof(rom);
    QEMUTimer tx_timer={0};s.tx_init_timer=&tx_timer;
    uint32_t tx_route[]={0x1300,0x10000c8,0x1000400,0x1000440,0x1376,0x1200,0x1604};
    memcpy(s.tx_init_route,tx_route,sizeof(tx_route));s.tx_init_delay_ns=1000;
    s.decoder_sync_enabled=s.decoder_init_active=s.decoder_paging_started=true;
    s.combiner_roll_isr=0x500;s.combiner_position_reader=0xe00;
    s.decoder_sync_consumer=0xf00;s.decoder_init_isr=0xd00;
    s.decoder_init_mask=0x10;s.rex_irq_mask=0x200;
    set32(ram+0x60,0x3000620);set32(ram+0x64,0x3000628);
    set32(ram+0x68,0x100);set32(ram+0x74,0x501);
    set16(rom+0x1300,0xb5f0);literal(0x1302,0x1400,4,0x100040c);
    literal(0x1314,0x1404,6,0x1000400);bl(0x1320,0x1200);
    memcpy(rom+0x136e,"\x00\x25\x35\x70\x10\x21",6);
    literal(0x1374,0x1410,0,0x1000440);bl(0x1376,0x700);
    literal(0x1600,0x1700,1,0x1301);set16(rom+0x1602,0x2004);
    bl(0x1604,0x1100);bl(0x322,0x1100);bl(0x8c6,0x700);
    set32(ram+0xc8,0x1301);set32(ram+0xb4,0x3000620);
    set32(ram+0xb8,0x3000628);set32(ram+0xbc,8);set16(backing+8,8);
    ram[0x400]=1;
    msm5xxx_poc_tx_init_poll(&s);assert(!tx_timer.armed); /* default off */
    s.tx_init_enabled=true;assert(msm5xxx_poc_tx_init_ready(&s));
    now=1000000;s.rex_irq_pending[0]=0x210;
    msm5xxx_poc_tx_init_poll(&s);assert(tx_timer.armed&&s.tx_init_active&&s.tx_init_seen);
    assert(tx_timer.deadline==1001000);
    msm5xxx_poc_tx_init_fire(&s);assert(s.rex_irq_pending[0]==0x210&&!s.tx_init_fires);
    now=1001000;msm5xxx_poc_tx_init_fire(&s);
    assert(s.rex_irq_pending[0]==0x218&&s.tx_init_fires==1&&!s.tx_init_active);
    msm5xxx_poc_tx_init_fire(&s);msm5xxx_poc_tx_init_poll(&s);assert(s.tx_init_fires==1&&!s.tx_init_active);
    s.rex_irq_pending[0]&=~8;ram[0x400]=0;msm5xxx_poc_tx_init_poll(&s);
    assert(!s.tx_init_seen&&!s.tx_init_owned_pending&&s.rex_irq_pending[0]==0x210);
    ram[0x400]=1;msm5xxx_poc_tx_init_poll(&s);assert(s.tx_init_active);
    set16(backing+8,0);now+=1000;msm5xxx_poc_tx_init_fire(&s);
    assert(!s.tx_init_active&&!s.tx_init_seen&&s.tx_init_fires==1&&s.rex_irq_pending[0]==0x210);
    set16(backing+8,8);msm5xxx_poc_tx_init_poll(&s);assert(s.tx_init_active);
    rom[0x1300]^=1;msm5xxx_poc_tx_init_poll(&s);assert(!s.tx_init_active&&!tx_timer.armed);
    rom[0x1300]^=1;msm5xxx_poc_tx_init_poll(&s);assert(s.tx_init_active);
    msm5xxx_poc_tx_init_cancel(&s);now+=1000;msm5xxx_poc_tx_init_fire(&s);
    assert(s.tx_init_fires==1);assert(s.rex_irq_pending[0]==0x210);
    /* An existing unowned pending event must never be stolen/cleared. */
    s.rex_irq_pending[0]|=8;msm5xxx_poc_tx_init_poll(&s);assert(!s.tx_init_active);
    msm5xxx_poc_tx_init_cancel(&s);assert(s.rex_irq_pending[0]==0x218);
    s.rex_irq_pending[0]&=~8;msm5xxx_poc_tx_init_poll(&s);now+=1000;msm5xxx_poc_tx_init_fire(&s);
    assert(s.tx_init_owned_pending&&s.rex_irq_pending[0]==0x218);
    msm5xxx_poc_tx_init_cancel(&s);assert(s.rex_irq_pending[0]==0x210&&!s.tx_init_owned_pending);
    assert(msm5xxx_poc_decoder_sync_gate(&s,&mask));
    uint64_t fires=s.tx_init_fires;
    msm5xxx_poc_tx_init_poll(&s);assert(s.tx_init_active);
    set16(backing+0xe8,0x20);now+=1000;
    msm5xxx_poc_tx_init_fire(&s);
    assert(!s.tx_init_active&&s.tx_init_fires==fires&&s.rex_irq_pending[0]==0x210);
    set16(backing+0xe8,0);msm5xxx_poc_tx_init_poll(&s);now+=1000;
    msm5xxx_poc_tx_init_fire(&s);assert(s.tx_init_owned_pending);
    set16(backing+0xe8,0x20);msm5xxx_poc_decoder_sync_tick(&s);
    assert(!s.tx_init_owned_pending&&!s.decoder_init_active&&s.rex_irq_pending[0]==0x210);
    set16(backing+0xe8,0);s.decoder_init_active=true;
    msm5xxx_poc_tx_init_poll(&s);assert(s.tx_init_active);
    set32(ram+0x74,0x503);now+=1000;msm5xxx_poc_tx_init_fire(&s);
    assert(!s.tx_init_active&&s.rex_irq_pending[0]==0x210);
    puts("tx init opt-in / gate / delay / one-shot / cancellation / stale / IRQ ownership / RX withdrawal PASS");
    /* A configured recurring cadence begins only after the original init clears its flag. */
    set32(ram+0x74,0x501);set16(backing+0xe8,0);set16(backing+0x2a8,0);
    msm5xxx_poc_tx_init_cancel(&s);s.rex_irq_pending[0]=0x210;
    literal(0x137c,0x1414,7,0x1000368);bl(0x138c,0x1200);
    memcpy(rom+0x1398,"\x01\x22\x00\x21\x78\x73\xf8\x1d\x1e\x30",10);
    bl(0x13a2,0x1800);literal(0x1908,0x1980,0,0x3000298);bl(0x190a,0x1b00);
    memcpy(rom+0x1b00,"\xb0\xb5\x00\x23\x57\x08\x7c\x00\x06\xe0\xcf\x5c\x5d\x1c\x6b\x1c\x4d\x5d\x2d\x02\x2f\x43\x07\x80\x9c\x42\xf6\xdc\x52\x08\x01\xd3\xc9\x5c\x01\x80\xb0\xbd",38);
    s.tx_frame_period_ns=2000;s.tx_init_fires=0;ram[0x400]=0;
    assert(msm5xxx_poc_tx_init_ready(&s));
    /* The bound TX initializer also works after RX leaves paging for traffic. */
    {
        MSM5xxxPOCMachineState paging=s;
        QEMUTimer paging_timer=tx_timer;int64_t paging_now=now;
        uint8_t paging_ram[sizeof(ram)],paging_backing[sizeof(backing)];
        memcpy(paging_ram,ram,sizeof(ram));memcpy(paging_backing,backing,sizeof(backing));
        s.decoder_paging_started=false;
        assert(!msm5xxx_poc_tx_context_ready(&s));
        s.decoder_paging_enabled=s.decoder_traffic_enabled=s.search2_virtual=true;
        s.decoder_init_reader=0xa00;
        memcpy(s.decoder_traffic_route,traffic_route,sizeof(traffic_route));
        memcpy(ram+0x800,traffic_rows,sizeof(traffic_rows));
        set32(ram+0xd0,0x3000620);set32(ram+0xd4,0x3000628);
        set32(ram+0xd8,0x10);set32(ram+0xe4,0x2401);
        ram[0x701]=1;set16(ram+0x702,0xffff);set16(backing+0xa08,0x20);
        assert(msm5xxx_poc_decoder_traffic_gate(&s,&mask));
        assert(msm5xxx_poc_tx_init_ready(&s));
        ram[0x400]=1;s.rex_irq_pending[0]=0x210;
        msm5xxx_poc_tx_init_poll(&s);assert(s.tx_init_active&&tx_timer.armed);
        now+=1000;msm5xxx_poc_tx_init_fire(&s);
        assert(s.tx_init_fires==1&&s.tx_init_owned_pending&&s.rex_irq_pending[0]==0x218);
        assert(!s.decoder_paging_started);
        s.decoder_traffic_enabled=false;msm5xxx_poc_tx_init_poll(&s);
        assert(!s.tx_init_active&&!tx_timer.armed&&s.rex_irq_pending[0]==0x210);
        s.decoder_traffic_enabled=true;
        ram[0x701]=2;assert(!msm5xxx_poc_tx_context_ready(&s));ram[0x701]=1;
        set32(ram+0xe4,0x2403);assert(!msm5xxx_poc_tx_context_ready(&s));set32(ram+0xe4,0x2401);
        ram[0x80c]^=2;assert(!msm5xxx_poc_tx_context_ready(&s));ram[0x80c]^=2;
        rom[0x2000]^=1;assert(!msm5xxx_poc_tx_context_ready(&s));rom[0x2000]^=1;
        set16(backing+0x2a8,0x80);assert(!msm5xxx_poc_tx_context_ready(&s));set16(backing+0x2a8,0);
        set16(backing+0xe8,0x20);assert(!msm5xxx_poc_tx_context_ready(&s));set16(backing+0xe8,0);
        assert(msm5xxx_poc_tx_init_ready(&s));
        /* A bound immediate mode1->0 rearm is distinct from held armed=1. */
        uint8_t saved_mode_shape[10];memcpy(saved_mode_shape,rom+0x1324,10);
        memcpy(rom+0x1324,"\x70\x78\x00\x28\x0a\xd0\x01\x28\x1a\xd1",10);
        msm5xxx_poc_tx_init_cancel(&s);
        assert(s.tx_init_last_mode==UINT8_MAX);
        s.rex_irq_pending[0]=0x210;ram[0x400]=1;ram[0x401]=1;
        uint64_t before_mode=s.tx_init_fires;
        msm5xxx_poc_tx_init_poll(&s);assert(s.tx_init_active&&s.tx_init_last_mode==1);
        now+=1000;msm5xxx_poc_tx_init_fire(&s);
        assert(s.tx_init_fires==before_mode+1&&s.tx_init_seen&&s.tx_init_owned_pending);
        ram[0x401]=0;
        msm5xxx_poc_tx_init_poll(&s);
        assert(!s.tx_init_active&&s.tx_init_last_mode==1&&s.rex_irq_pending[0]==0x218);
        s.rex_irq_pending[0]&=~8;msm5xxx_poc_tx_init_poll(&s);
        assert(s.tx_init_active&&s.tx_init_last_mode==0&&!s.tx_init_owned_pending);
        now+=1000;msm5xxx_poc_tx_init_fire(&s);
        assert(s.tx_init_fires==before_mode+2&&s.rex_irq_pending[0]==0x218);
        s.rex_irq_pending[0]&=~8;
        for(unsigned held=0;held<3;held++)msm5xxx_poc_tx_init_poll(&s);
        assert(!s.tx_init_active&&s.tx_init_fires==before_mode+2);
        /* Reverse0->1 and unknown mode cannot reset seen. */
        ram[0x401]=1;msm5xxx_poc_tx_init_poll(&s);assert(!s.tx_init_active&&s.tx_init_last_mode==0);
        ram[0x401]=2;msm5xxx_poc_tx_init_poll(&s);assert(!s.tx_init_active&&s.tx_init_last_mode==0);
        /* A stale admitted mode is canceled before IRQ, then mode0 admits afresh. */
        msm5xxx_poc_tx_init_cancel(&s);ram[0x401]=1;
        msm5xxx_poc_tx_init_poll(&s);assert(s.tx_init_active&&s.tx_init_last_mode==1);
        ram[0x401]=0;now+=1000;msm5xxx_poc_tx_init_fire(&s);
        assert(!s.tx_init_active&&!s.tx_init_seen&&s.tx_init_last_mode==UINT8_MAX);
        assert(s.tx_init_fires==before_mode+2&&s.rex_irq_pending[0]==0x210);
        msm5xxx_poc_tx_init_poll(&s);assert(s.tx_init_active&&s.tx_init_last_mode==0);
        msm5xxx_poc_tx_init_cancel(&s);
        /* A foreign pending IRQ must not consume the mode transition. */
        ram[0x401]=1;msm5xxx_poc_tx_init_poll(&s);now+=1000;msm5xxx_poc_tx_init_fire(&s);
        s.rex_irq_pending[0]&=~8;msm5xxx_poc_tx_init_poll(&s);
        s.rex_irq_pending[0]|=8;ram[0x401]=0;
        msm5xxx_poc_tx_init_poll(&s);assert(!s.tx_init_active&&s.tx_init_last_mode==1&&!s.tx_init_owned_pending);
        s.rex_irq_pending[0]&=~8;msm5xxx_poc_tx_init_poll(&s);
        assert(s.tx_init_active&&s.tx_init_last_mode==0);
        msm5xxx_poc_tx_init_cancel(&s);
        /* Unknown opcode/bounds never widen admission to another mode class. */
        rom[0x1324]^=1;assert(msm5xxx_poc_tx_init_mode(&s)==UINT8_MAX);rom[0x1324]^=1;
        uint64_t saved_nor=s.primary_nor_size;s.primary_nor_size=0x132d;
        assert(msm5xxx_poc_tx_init_mode(&s)==UINT8_MAX);s.primary_nor_size=saved_nor;
        uint32_t saved_armed=s.tx_init_route[2];s.tx_init_route[2]=s.ram_base+sizeof(ram)-1;
        assert(msm5xxx_poc_tx_init_mode(&s)==UINT8_MAX);s.tx_init_route[2]=saved_armed;
        s.tx_frame_period_ns=0;assert(msm5xxx_poc_tx_init_mode(&s)==UINT8_MAX);
        ram[0x401]=1;msm5xxx_poc_tx_init_poll(&s);
        assert(s.tx_init_active&&s.tx_init_last_mode==UINT8_MAX);
        ram[0x401]=0;now+=1000;msm5xxx_poc_tx_init_fire(&s);
        assert(s.tx_init_owned_pending&&s.rex_irq_pending[0]==0x218);
        msm5xxx_poc_tx_init_cancel(&s);assert(s.tx_init_last_mode==UINT8_MAX&&s.rex_irq_pending[0]==0x210);
        s.tx_frame_period_ns=2000;
        memcpy(rom+0x1324,saved_mode_shape,10);
        s=paging;tx_timer=paging_timer;now=paging_now;
        memcpy(ram,paging_ram,sizeof(ram));memcpy(backing,paging_backing,sizeof(backing));
    }
    rom[0x1b16]^=1;assert(!msm5xxx_poc_tx_init_ready(&s));rom[0x1b16]^=1;
    set32(rom+0x1980,0x300029a);assert(!msm5xxx_poc_tx_init_ready(&s));set32(rom+0x1980,0x3000298);
    rom[0x1398]^=1;assert(!msm5xxx_poc_tx_init_ready(&s));rom[0x1398]^=1;
    msm5xxx_poc_tx_init_poll(&s);assert(!s.tx_frame_running&&!tx_timer.armed);
    ram[0x400]=1;msm5xxx_poc_tx_init_poll(&s);now+=1000;
    msm5xxx_poc_tx_init_fire(&s);assert(s.tx_init_fires==1&&s.rex_irq_pending[0]==0x218);
    s.rex_irq_pending[0]&=~8;ram[0x400]=0;msm5xxx_poc_tx_init_poll(&s);
    assert(s.tx_frame_running&&s.tx_init_active&&tx_timer.deadline==now+2000);
    now+=1999;msm5xxx_poc_tx_init_fire(&s);assert(!s.tx_frame_fires);
    now++;msm5xxx_poc_tx_init_fire(&s);
    assert(s.tx_frame_fires==1&&s.tx_init_fires==1&&s.rex_irq_pending[0]==0x218);
    now+=2000;msm5xxx_poc_tx_init_fire(&s);
    assert(s.tx_frame_fires==1&&s.tx_frame_overruns==1&&s.rex_irq_pending[0]==0x218);
    s.rex_irq_pending[0]&=~8;msm5xxx_poc_tx_init_poll(&s);now+=2000;
    msm5xxx_poc_tx_init_fire(&s);assert(s.tx_frame_fires==2&&s.rex_irq_pending[0]==0x218);
    /* Actual clock disable cancels owned IRQ8, preserving other devices' pending bits. */
    set16(backing+0x2a8,0x80);now+=2000;msm5xxx_poc_tx_init_fire(&s);
    assert(!s.tx_frame_running&&!tx_timer.armed&&s.rex_irq_pending[0]==0x210);
    set16(backing+0x2a8,0);s.rex_irq_pending[0]|=8;
    msm5xxx_poc_tx_init_poll(&s);now+=2000;msm5xxx_poc_tx_init_fire(&s);
    assert(s.tx_frame_overruns==2&&!s.tx_init_owned_pending);
    set16(backing+0x2a8,0x80);msm5xxx_poc_tx_init_poll(&s);
    assert(s.rex_irq_pending[0]==0x218); /* Unowned IRQ8 must survive cancellation. */
    s.rex_irq_pending[0]&=~8;set16(backing+0x2a8,0);msm5xxx_poc_tx_init_poll(&s);
    ram[0x400]=1;msm5xxx_poc_tx_init_poll(&s);
    assert(!s.tx_frame_running&&s.tx_init_active&&tx_timer.deadline==now+1000);
    now+=1000;msm5xxx_poc_tx_init_fire(&s);assert(s.tx_init_fires==2);
    s.rex_irq_pending[0]&=~8;ram[0x400]=0;msm5xxx_poc_tx_init_poll(&s);
    set16(backing+8,0);now+=2000;msm5xxx_poc_tx_init_fire(&s);
    assert(!s.tx_frame_running&&s.rex_irq_pending[0]==0x210);
    set16(backing+8,8);now=INT64_MAX-1000;msm5xxx_poc_tx_init_poll(&s);
    assert(!s.tx_frame_running&&!s.tx_init_active);
    now=10000;assert(msm5xxx_poc_tx_frame_schedule(&s,6000,now));
    assert(tx_timer.deadline==12000); /* Keep phase and skip missed ticks without an IRQ burst. */
    assert(!msm5xxx_poc_tx_frame_schedule(&s,now+1,now));
    s.tx_init_route[4]=0x1374;
    memcpy(rom+0x136c,"\x00\x25\x35\x70\x10\x21",6);
    literal(0x1372,0x1410,0,0x1000440);bl(0x1374,0x700);
    literal(0x137a,0x1414,7,0x1000368);bl(0x138a,0x1200);
    memcpy(rom+0x1396,"\x01\x22\x00\x21\x78\x73\xf8\x1d\x1e\x30",10);
    bl(0x13a0,0x1800);assert(msm5xxx_poc_tx_init_ready(&s));
    puts("tx frame explicit cadence / init prerequisite / backpressure / clock withdrawal / IRQ ownership / rearm / overflow PASS");
    /* Collector adds no data or state until the full native class is bound. */
    assert(msm5xxx_poc_tx_fifo_ops.read==msm5xxx_poc_tx_fifo_read&&msm5xxx_poc_tx_fifo_ops.write==msm5xxx_poc_tx_fifo_write);
    literal(0x1802,0x1984,6,0x1000500);set16(rom+0x1806,0x7b30);
    s.tx_fifo_mode_base=0x1000500;s.tx_fifo_writer=0x1b00;
    s.tx_fifo_enabled=true;s.tx_frame_running=true;ram[0x50c]=1;
    assert(msm5xxx_poc_tx_init_ready(&s));
    set32(rom+0x1984,0x1000504);assert(!msm5xxx_poc_tx_init_ready(&s));
    set32(rom+0x1984,0x1000500);
    uint8_t access_piece[12]={0x09,0x04,0x14,0x40,0x00,0x16,0x04,0x27,0x93,0,0,0xa5};
    msm5xxx_access_init(&s.tx_access);current_pc=0x1b16;raw_pc_delta=6;
    set16(backing+8,0); /* IRQ delivery pauses; the in-flight callback still writes. */
    assert(!msm5xxx_poc_tx_init_ready(&s)&&msm5xxx_poc_tx_context_ready(&s));
    msm5xxx_poc_tx_fifo_begin(&s);
    for(unsigned i=0;i<6;i++) {
        msm5xxx_poc_tx_fifo_write(&s,0,access_piece[2*i]|access_piece[2*i+1]<<8,2);
    }
    assert(!s.tx_access.pieces&&!s.tx_access.packets); /* Wait for the frame boundary. */
    assert(!s.tx_fifo_rejected&&s.tx_fifo_length==12);
    assert(msm5xxx_poc_tx_fifo_read(&s,0,2)==(access_piece[10]|0xa500));
    set16(backing+8,8);
    msm5xxx_poc_tx_fifo_begin(&s);
    assert(s.tx_access.pieces==1&&s.tx_access.packets==1);
    assert(s.tx_access.last.length==9&&s.tx_access.last.sequence==5);
    /* A seventh word invalidates the entire frame, including a complete prefix. */
    for(unsigned i=0;i<6;i++) msm5xxx_poc_tx_fifo_write(&s,0,access_piece[2*i]|access_piece[2*i+1]<<8,2);
    msm5xxx_poc_tx_fifo_write(&s,0,0xffff,2);
    assert(s.tx_fifo_rejected&&s.tx_fifo_rejections==1&&!s.tx_access.window_length);
    assert(s.tx_fifo_reject_reason==6&&s.tx_fifo_reject_pc==current_pc);
    msm5xxx_poc_tx_fifo_begin(&s);assert(s.tx_access.packets==1);
    ram[0x50c]=2;msm5xxx_poc_tx_fifo_write(&s,0,0x1234,2);
    assert(s.tx_fifo_rejected&&msm5xxx_poc_tx_fifo_read(&s,0,2)==0x1234);
    assert(s.tx_fifo_reject_reason==2&&s.tx_fifo_reject_pc==0);
    ram[0x50c]=1;msm5xxx_poc_tx_fifo_begin(&s);current_pc=0x1b18;
    msm5xxx_poc_tx_fifo_write(&s,0,0x5678,2);assert(s.tx_fifo_rejected);
    assert(s.tx_fifo_reject_reason==5&&s.tx_fifo_reject_pc==current_pc);
    current_pc=0x1b16;msm5xxx_poc_tx_fifo_begin(&s);unwind_available=false;
    msm5xxx_poc_tx_fifo_write(&s,0,0x9abc,2);assert(s.tx_fifo_rejected);
    assert(s.tx_fifo_reject_reason==4);
    unwind_available=true;msm5xxx_poc_tx_fifo_begin(&s);
    msm5xxx_poc_tx_fifo_write(&s,1,0x55,1);assert(s.tx_fifo_rejected);
    assert(s.tx_fifo_reject_reason==1);
    msm5xxx_poc_tx_fifo_begin(&s);set16(backing+0x2a8,0x80);
    msm5xxx_poc_tx_fifo_write(&s,0,0x7777,2);
    assert(s.tx_fifo_rejected&&s.tx_fifo_reject_reason==3&&s.tx_fifo_reject_pc==0);
    set16(backing+0x2a8,0);
    msm5xxx_poc_tx_fifo_begin(&s);msm5xxx_poc_tx_fifo_write(&s,0,0x4444,2);
    msm5xxx_poc_tx_fifo_begin(&s);assert(!s.tx_access.window_length&&s.tx_access.packets==1);
    /* A delayed/coalesced interrupt cannot join bytes across missing frames. */
    msm5xxx_poc_tx_fifo_write(&s,0,0x2222,2);
    s.tx_init_active=true;s.tx_init_deadline=now;s.rex_irq_pending[0]|=8;
    msm5xxx_poc_tx_init_fire(&s);assert(!s.tx_fifo_open&&!s.tx_fifo_length);
    s.rex_irq_pending[0]&=~8;msm5xxx_poc_tx_fifo_begin(&s);
    msm5xxx_poc_tx_fifo_write(&s,0,0x3333,2);
    s.tx_init_deadline=now-3*(int64_t)s.tx_frame_period_ns;
    msm5xxx_poc_tx_init_fire(&s);assert(s.tx_fifo_open&&!s.tx_fifo_length);
    msm5xxx_poc_tx_init_cancel(&s);assert(!s.tx_fifo_open&&!s.tx_access.window_length);
    assert(s.tx_access.packets==1); /* Last metadata/counters survive normal cancellation. */
    puts("native access FIFO / backing / precise-PC / mode / full-frame / overflow / gaps / cancel PASS");

    {
        const uint8_t reverse[26]={0x1a,0x04,0x08,0x02,0x44,0x8d,0x15,0xaa,0xb1,0x35,0x79,0xbd,0xf0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x7b,0x96,0xbf}, expected_ack[14]={0x0e,0x07,0x41,0x0a,0x24,0x68,0xad,0x55,0x80,0x80,0x22,0x67,0x73,0xeb};
        const uint8_t broadcast[4][255]={{0x21,0x01,0x00,0x00,0x00,0x07,0xff,0xfc,0x00,0x00,0x00,0x00,0x40,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2a,0xa8,0x00,0x00,0x1c,0x81,0x10,0x09,0x79,0xa5,0xea},{0x13,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x80,0x15,0x0f,0x55,0x01},{0x09,0x03,0x00,0x00,0x20,0x2d,0xdb,0x83,0x55},{0x09,0x04,0x00,0x00,0x07,0x7f,0x20,0x13,0x58}};
        const uint8_t lengths[4]={33,19,9,9};
        uint8_t pieces[44]={0};uint16_t expected_words[14];
        memcpy(pieces+11,reverse,sizeof(reverse));
        memcpy(s.decoder_paging_messages,broadcast,sizeof(broadcast));
        memcpy(s.decoder_paging_lengths,lengths,sizeof(lengths));
        s.decoder_paging_enabled=true;
        s.decoder_sync_message_length=26;s.decoder_sync_message[1]=1;s.decoder_sync_message[2]=3;
        assert(msm5xxx_poc_access_response_layout(&s));
        s.decoder_paging_enabled=false;assert(!msm5xxx_poc_access_response_layout(&s));s.decoder_paging_enabled=true;
        s.decoder_sync_enabled=false;assert(!msm5xxx_poc_access_response_layout(&s));s.decoder_sync_enabled=true;
        s.decoder_sync_message[2]=6;assert(!msm5xxx_poc_access_response_layout(&s));s.decoder_sync_message[2]=3;
        s.decoder_sync_message_length=25;assert(!msm5xxx_poc_access_response_layout(&s));s.decoder_sync_message_length=26;
        s.decoder_paging_lengths[3]=8;assert(!msm5xxx_poc_access_response_layout(&s));s.decoder_paging_lengths[3]=9;
        s.decoder_paging_messages[2][1]=9;assert(!msm5xxx_poc_access_response_layout(&s));s.decoder_paging_messages[2][1]=3;
        s.access_response_probe=true;msm5xxx_poc_access_response_reset(&s);
        s.decoder_paging_frames=0;assert(msm5xxx_poc_paging_frame(&s,0));s.decoder_paging_frames++;
        s.tx_frame_running=true;current_pc=0x1b16;
        msm5xxx_access_init(&s.tx_access);set16(backing+8,0);
        assert(msm5xxx_poc_tx_context_ready(&s));msm5xxx_poc_tx_fifo_begin(&s);
        for(unsigned part=0;part<4;part++) {
            for(unsigned word=0;word<6;word++) {
                unsigned at=part*11+2*word;
                uint16_t value=pieces[at];value|=(uint16_t)(word==5?0xa5:pieces[at+1])<<8;
                msm5xxx_poc_tx_fifo_write(&s,0,value,2);
            }
            msm5xxx_poc_tx_fifo_begin(&s);
            assert(s.access_ack_queued==(part==3));
        }
        assert(s.tx_access.packets==1&&s.tx_access.last.address_valid);
        assert(s.access_paging.reply_pending&&!memcmp(s.access_paging.reply,expected_ack,14));
        assert(s.access_station_sequence==1&&!s.access_ack_rejections);
        msm5xxx_poc_tx_init_cancel(&s);assert(s.access_paging.reply_pending&&!s.tx_frame_running);
        for(unsigned frame=0;frame<3;frame++) {
            assert(msm5xxx_poc_paging_frame(&s,0));s.decoder_paging_frames++;
            assert(s.access_ack_encoded==(frame?1:0));
        }
        assert(!s.access_paging.reply_pending&&!s.access_paging.reply_active);
        assert(msm5xxx_poc_paging_frame(&s,1)&&s.access_response_blocked);
        assert(msm5xxx_paging_decoder_frame(broadcast,lengths,1,s.decoder_paging_frames,expected_words));
        assert(!memcmp(s.decoder_sync_words,expected_words,sizeof(expected_words)));
        assert(s.access_ack_rejections==1&&s.access_ack_reject_reason==3);
        msm5xxx_poc_access_response_queue(&s);assert(s.access_ack_rejections==2&&s.access_ack_queued==1);
        msm5xxx_poc_access_response_reset(&s);s.decoder_paging_frames=0;
        assert(!s.access_response_blocked&&!s.access_paging.initialized&&s.access_station_sequence==1);
        s.access_response_probe=false;msm5xxx_poc_access_response_queue(&s);
        assert(s.access_ack_queued==1&&s.access_ack_rejections==2);
        assert(msm5xxx_poc_paging_frame(&s,0)&&!s.access_paging.initialized);
        puts("native valid FIFO -> queued ACK / TX clock independence / RX reset / rate fallback / defaultoff PASS");
        {
            const uint8_t assignment[16]={0x10,0x08,0x45,0x0a,0x24,0x68,0xad,0x55,0x80,0x10,0x04,0x00,0x08,0x6b,0x03,0xcc};
            s.access_response_probe=true;s.access_assignment_code=1;
            msm5xxx_poc_access_response_reset(&s);s.decoder_paging_frames=0;
            msm5xxx_access_init(&s.tx_access);s.tx_frame_running=true;current_pc=0x1b16;
            msm5xxx_poc_tx_fifo_begin(&s);
            for(unsigned part=0;part<4;part++) {
                for(unsigned word=0;word<6;word++) {
                    unsigned at=part*11+2*word;
                    uint16_t value=pieces[at];value|=(uint16_t)(word==5?0xa5:pieces[at+1])<<8;
                    msm5xxx_poc_tx_fifo_write(&s,0,value,2);
                }
                msm5xxx_poc_tx_fifo_begin(&s);
                assert(s.access_ack_queued==1+(part==3));
            }
            assert(s.access_paging.reply_length==16&&!memcmp(s.access_paging.reply,assignment,16));
            assert(s.access_station_sequence==2&&s.access_ack_rejections==2);
            msm5xxx_poc_tx_init_cancel(&s);assert(s.access_paging.reply_pending);
            for(unsigned frame=0;frame<2;frame++) {
                assert(msm5xxx_poc_paging_frame(&s,0));s.decoder_paging_frames++;
            }
            assert(s.access_ack_encoded==2&&!s.access_paging.reply_active);
            msm5xxx_poc_access_response_reset(&s);assert(!s.access_paging.reply_pending);
            puts("native fresh FIFO -> explicit assignment / clock-independent reply / reset PASS");
        }
    }

}

'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                            "-Wextra", "-Werror", "-I", str(native),
                            str(path / "check.c"), str(native / "msm5xxx-search2.c"),
                            "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_traffic_callback_class_and_negative_rom_mutations(self):
        import hashlib

        native = Path(__file__).resolve().parents[1] / "native/qemu"
        fixtures = FIRMWARE_ROOT
        cases = (
            ("x350_VC22.bin", "7a6a4df853b51a4b44e86c3334330c12facad2954eef5a94031724ff1ff44073"),
            ("schx150.bin", "347057aeb9985579bb31c64e7fa20dc18486b7fb59aea82a682d4b10d9711de0"),
        )
        if not all((fixtures / name).is_file() for name, _ in cases):
            self.skipTest("original encoder callback ROM fixtures unavailable")
        for name, expected in cases:
            self.assertEqual(hashlib.sha256((fixtures / name).read_bytes()).hexdigest(), expected)
        source = (native / "msm5xxx-poc.c").read_text()

        def function(marker):
            start = source.index(marker)
            return source[start:source.index("\n}", start) + 2]

        harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define G_N_ELEMENTS(a) (sizeof(a)/sizeof((a)[0]))
typedef struct{uint64_t ram_size;} MachineState;
typedef struct{MachineState parent;uint32_t primary_nor_size,ram_base,tx_init_route[7];uint64_t tx_frame_period_ns;} MSM5xxxPOCMachineState;
#define MACHINE(s) (&(s)->parent)
static uint8_t *rom;static size_t rom_size;
static uint16_t lduw_le_p(const uint8_t*p){return p[0]|(p[1]<<8);}
static void cpu_physical_memory_read(uint32_t a,void*out,size_t n){assert(a<=rom_size&&n<=rom_size-a);memcpy(out,rom+a,n);}
static uint32_t msm5xxx_poc_guest_u32(uint32_t a){uint8_t p[4];cpu_physical_memory_read(a,p,4);return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
'''
        for marker in (
            "static bool msm5xxx_poc_class_literal(MSM5xxxPOCMachineState *s,",
            "static bool msm5xxx_poc_decoder_bl(MSM5xxxPOCMachineState *s,\n",
            "static bool msm5xxx_poc_tx_traffic_callback(MSM5xxxPOCMachineState *s,",
        ):
            harness += function(marker) + "\n"
        harness += r'''
static const uint32_t routes[2][7]={{0xa7fb0,0x1383190,0x13e1fc4,0x13d5c68,0xa8026,0x30258,0xa7e4a},{0xa7b94,0x1382f98,0x13e3e78,0x13d7894,0xa7c08,0x30328,0xa7a2e}};
static const unsigned calls[]={8,16,28,42,50,60,78,86,94,100,114,142,152,166,176,186,194,202,232,238,244},literals[]={12,32,118,120,128,156,158,198,206,214,242};
int main(int argc,char**argv){assert(argc==3);unsigned mutations=0;
 for(unsigned c=0;c<2;c++){
  FILE*f=fopen(argv[c+1],"rb");assert(f);assert(!fseek(f,0,SEEK_END));long n=ftell(f);assert(n>0);rewind(f);rom_size=n;rom=malloc(rom_size);assert(rom);assert(fread(rom,1,rom_size,f)==rom_size);fclose(f);
  MSM5xxxPOCMachineState s={.parent={0x800000},.ram_base=0x1000000,.primary_nor_size=rom_size,.tx_frame_period_ns=20000000};
  memcpy(s.tx_init_route,routes[c],sizeof(s.tx_init_route));uint32_t cb;assert(msm5xxx_poc_class_literal(&s,s.tx_init_route[0]+0x5a,1,&cb));
  assert(msm5xxx_poc_tx_traffic_callback(&s,cb));
  assert(!msm5xxx_poc_tx_traffic_callback(&s,0)&&!msm5xxx_poc_tx_traffic_callback(&s,cb&~1u));
  s.tx_frame_period_ns=0;assert(!msm5xxx_poc_tx_traffic_callback(&s,cb));s.tx_frame_period_ns=20000000;
  unsigned entry=cb&~1u;
  for(unsigned i=0;i<252;i++){
   bool skip=false;for(unsigned j=0;j<G_N_ELEMENTS(calls);j++)if(i>=calls[j]&&i<calls[j]+4)skip=true;
   for(unsigned j=0;j<G_N_ELEMENTS(literals);j++)if(i==literals[j])skip=true;
   if(skip)continue;rom[entry+i]^=1;assert(!msm5xxx_poc_tx_traffic_callback(&s,cb));rom[entry+i]^=1;mutations++;
  }
  for(unsigned j=0;j<G_N_ELEMENTS(calls);j++){unsigned i=entry+calls[j]+1;rom[i]^=0x80;assert(!msm5xxx_poc_tx_traffic_callback(&s,cb));rom[i]^=0x80;mutations++;}
  for(unsigned j=0;j<G_N_ELEMENTS(literals);j++){
   unsigned pc=entry+literals[j];uint16_t h=lduw_le_p(rom+pc);unsigned pool=((pc+4)&~3u)+4*(h&255);rom[pool]^=1;
   assert(!msm5xxx_poc_tx_traffic_callback(&s,cb));rom[pool]^=1;mutations++;
  }
  unsigned reg=s.tx_init_route[0]+0x5c;rom[reg]^=1;assert(!msm5xxx_poc_tx_traffic_callback(&s,cb));rom[reg]^=1;
  s.tx_init_route[2]+=4;assert(!msm5xxx_poc_tx_traffic_callback(&s,cb));s.tx_init_route[2]-=4;
  assert(msm5xxx_poc_tx_traffic_callback(&s,cb));free(rom);
 }
 printf("PASS two original ROM callback bindings; %u opcode/call/literal mutations rejected\n",mutations);
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / "check.c").write_text(harness)
            subprocess.run(["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                            "-Wno-misleading-indentation", "-fsanitize=address,undefined",
                            str(path / "check.c"), "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check"), *(str(fixtures / name) for name, _ in cases)],
                           check=True, timeout=10)

    def test_paging_rates_carry_som_crc_and_shared_deadlines(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
#include "msm5xxx-search2.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static uint8_t messages[4][255] = {
{0x21,0x01,0x00,0x00,0x00,0x07,0xff,0xfc,0x00,0x00,0x00,0x00,0x40,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2a,0xa8,0x00,0x00,0x1c,0x81,0x10,0x09,0x79,0xa5,0xea},
{0x13,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x80,0x15,0x0f,0x55,0x01},
{0x09,0x03,0x00,0x00,0x20,0x2d,0xdb,0x83,0x55},
{0x09,0x04,0x00,0x00,0x07,0x7f,0x20,0x13,0x58},
};
static uint8_t lengths[4]={33,19,9,9};
static const uint8_t golden[2][8][24] = {
{
{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x80,0x80,0x00,0x00,0x03,0xff,0xfe,0x00,0x00,0x00,0x00,0x10,0x20,0x00},
{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0xaa,0x00,0x00,0x03,0x90,0x22,0x01,0x2f,0x34,0xbd,0x40,0x00,0x00,0x00,0x00,0x00},
{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x89,0x81,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x20},
{0x05,0x43,0xd5,0x40,0x40,0x00,0x00,0x00,0x00,0x84,0x81,0x80,0x00,0x10,0x16,0xed,0xc1,0xaa,0x80,0x00,0x00,0x00,0x00,0x00},
{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x84,0x82,0x00,0x00,0x03,0xbf,0x90,0x09,0xac,0x00,0x00,0x00,0x00,0x00,0x00},
{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x80,0x80,0x00,0x00,0x03,0xff,0xfe,0x00,0x00,0x00,0x00,0x10,0x20,0x00},
},
{
{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x80,0x80},
{0x00,0x00,0x03,0x7f,0xff,0x00,0x00,0x00,0x00,0x08,0x10,0x00},
{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xaa,0x40,0x00,0x00},
{0xe4,0x08,0x80,0x25,0xe6,0x97,0xa8,0x00,0x00,0x89,0x81,0x00},
{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x10},
{0x02,0xa1,0xea,0x50,0x10,0x00,0x00,0x00,0x00,0x84,0x81,0x80},
{0x00,0x10,0x16,0x76,0xe0,0xd5,0x40,0x00,0x00,0x84,0x82,0x00},
{0x00,0x03,0xbf,0x48,0x04,0xd6,0x00,0x00,0x00,0x90,0x80,0x80},
},
};
int main(void) {
 uint16_t words[14], prev[14];
 unsigned rate, n, i, packet;
 for(rate=0;rate<2;rate++) {
  unsigned bytes=rate?12:24, cycle=rate?7:5, payload=rate?94:190;
  unsigned packet_at=0, packet_frame=0;
  memset(prev,0,sizeof(prev));
  for(n=0;n<2*cycle+1;n++) {
   uint8_t logical[24]={0};
   assert(msm5xxx_paging_decoder_frame(messages,lengths,rate,n,words));
   if(n<=cycle) for(i=0;i<bytes;i++) assert(((words[i/2]>>(8*(i%2)))&255)==golden[rate][n][i]);
   for(i=bytes/2;i<14;i++) assert(words[i]==0);
   /* Independently reconstruct logical P[n] from H[n] tail and H[n+1] head. */
   if(n) {
    unsigned bit, subbits=bytes*4;
    for(i=0;i<bytes;i++) logical[i]= i<bytes-9 ? (prev[(i+9)/2]>>(8*((i+9)%2)))&255 : (words[(i-(bytes-9))/2]>>(8*((i-(bytes-9))%2)))&255;
    for(bit=0;bit<bytes*8;bit++) {
     unsigned value=(logical[bit/8]>>(7-bit%8))&1;
     if(bit%subbits==0) assert(value==(!packet_frame&&!bit));
     else {
      unsigned at=packet_frame*payload+(bit/subbits)*(subbits-1)+bit%subbits-1;
      unsigned expected=at<lengths[packet_at]*8 ? (messages[packet_at][at/8]>>(7-at%8))&1 : 0;
      assert(value==expected);
     }
    }
    if(++packet_frame==(lengths[packet_at]*8+payload-1)/payload) { packet_frame=0;packet_at=(packet_at+1)%4; }
   }
   memcpy(prev,words,sizeof(prev));
  }
  assert(msm5xxx_paging_decoder_frame(messages,lengths,rate,UINT64_MAX,words));
 }
 assert(!msm5xxx_paging_decoder_frame(messages,lengths,2,0,words));
 assert(!msm5xxx_paging_decoder_frame(NULL,lengths,0,0,words));
 assert(!msm5xxx_paging_decoder_frame(messages,NULL,0,0,words));
 assert(!msm5xxx_paging_decoder_frame(messages,lengths,0,0,NULL));
 for(packet=0;packet<4;packet++) {
  uint8_t saved=lengths[packet];lengths[packet]=4;
  assert(!msm5xxx_paging_decoder_frame(messages,lengths,0,0,words));lengths[packet]=saved;
  messages[packet][0]^=1;assert(!msm5xxx_paging_decoder_frame(messages,lengths,0,0,words));messages[packet][0]^=1;
  messages[packet][saved-1]^=1;assert(!msm5xxx_paging_decoder_frame(messages,lengths,0,0,words));messages[packet][saved-1]^=1;
 }

 {
  MSM5xxxAccessPacket p={.length=26,.type=4,.format=0,.sequence=5,.address_mode=0,
   .address_length=9,.address_valid=true,.network24=0x123456,.network10=0x2ab};
  const uint8_t expected[14]={0x0e,0x07,0xad,0x0a,0x24,0x68,0xad,0x55,0x80,0x80,0x1e,0xff,0xbd,0xb6}, second[14]={0x0e,0x07,0xd1,0x0a,0x24,0x68,0xad,0x55,0x80,0x80,0x09,0x81,0x69,0x93};
  uint8_t ack[14], packet4[4][255]={{0}}, len4[4]={14,14,14,14};
  assert(msm5xxx_access_ack(&p,3,ack)&&!memcmp(ack,expected,14));
  for(unsigned a=0;a<8;a++) for(unsigned b=0;b<8;b++) {
   p.sequence=a;assert(msm5xxx_access_ack(&p,b,ack));assert(ack[2]==((a<<5)|(b<<2)|1));
   for(i=0;i<4;i++) memcpy(packet4[i],ack,14);
   for(rate=0;rate<2;rate++) assert(msm5xxx_paging_decoder_frame(packet4,len4,rate,0,words));
  }
  p.sequence=5;
  for(unsigned bad=0;bad<10;bad++) {
   MSM5xxxAccessPacket q=p;unsigned station=3;memset(ack,0xa5,14);
   switch(bad) {
   case 0:q.type=3;break;case 1:q.format=1;break;case 2:q.sequence=8;break;
   case 3:q.address_mode=1;break;case 4:q.address_length=8;break;
   case 5:q.address_valid=false;break;case 6:q.network24=0x1000000;break;
   case 7:q.network10=0x400;break;case 8:station=8;break;default:break;
   }
   assert(!msm5xxx_access_ack(bad==9?NULL:&q,station,ack));
   for(i=0;i<14;i++) assert(ack[i]==0xa5);
  }
  assert(!msm5xxx_access_ack(&p,3,NULL));
  for(rate=0;rate<2;rate++) {
   MSM5xxxPagingStream stream,saved;
   unsigned bytes=rate?12:24, cycle=rate?7:5, payload=rate?94:190, reply_frames=rate?2:1;
   msm5xxx_paging_stream_init(&stream);
   for(n=0;n<3*cycle+2;n++) {
    assert(msm5xxx_paging_decoder_frame(messages,lengths,rate,n,prev));
    assert(msm5xxx_paging_stream_frame(&stream,messages,lengths,rate,words)&&!memcmp(prev,words,sizeof(words)));
   }
   saved=stream;memset(words,0xa5,sizeof(words));
   assert(!msm5xxx_paging_stream_frame(&stream,messages,lengths,1-rate,words)&&!memcmp(&stream,&saved,sizeof(stream)));
   for(i=0;i<14;i++) assert(words[i]==0xa5a5);
   msm5xxx_paging_stream_init(&stream);unsigned ordinal=0,fragment=0;
   for(n=0;n<2*cycle+reply_frames+1;n++) {
    if(n==1) {
     assert(msm5xxx_paging_stream_queue(&stream,expected));saved=stream;
     assert(!msm5xxx_paging_stream_queue(&stream,second)&&!memcmp(&stream,&saved,sizeof(stream)));
    }
    assert(msm5xxx_paging_stream_frame(&stream,messages,lengths,rate,words));
    if(n) {
     uint8_t logical[24];unsigned sub=bytes*4;
     const uint8_t *data=ordinal==1?expected:messages[(ordinal-(ordinal>1))%4];
     unsigned length=ordinal==1?14:lengths[(ordinal-(ordinal>1))%4];
     for(i=0;i<bytes;i++) logical[i]= i<bytes-9 ? (prev[(i+9)/2]>>(8*((i+9)%2)))&255 : (words[(i-bytes+9)/2]>>(8*((i-bytes+9)%2)))&255;
     for(unsigned bit=0;bit<bytes*8;bit++) {
      unsigned value=(logical[bit/8]>>(7-bit%8))&1;
      if(bit%sub==0) assert(value==(!fragment&&!bit));
      else {unsigned at=fragment*payload+(bit/sub)*(sub-1)+bit%sub-1;assert(value==(at<length*8?((data[at/8]>>(7-at%8))&1):0));}
     }
     if(++fragment==(length*8+payload-1)/payload) {fragment=0;ordinal++;}
    }
    memcpy(prev,words,sizeof(words));
   }
   assert(ordinal==9&&!fragment&&stream.replies_encoded==1);
   msm5xxx_paging_stream_init(&stream);assert(msm5xxx_paging_stream_queue(&stream,expected));
   for(n=0;n<2*reply_frames+1;n++) {
    if(n==reply_frames) assert(msm5xxx_paging_stream_queue(&stream,second));
    assert(msm5xxx_paging_stream_frame(&stream,messages,lengths,rate,words));
    if(n) {
     unsigned ordinal2=(n-1)/reply_frames,fragment2=(n-1)%reply_frames,sub=bytes*4;
     const uint8_t *data=ordinal2?second:expected;
     for(unsigned bit=0;bit<bytes*8;bit++) {
      unsigned pos=bit/8,value;
      uint8_t byte=pos<bytes-9 ? (prev[(pos+9)/2]>>(8*((pos+9)%2)))&255 : (words[(pos-bytes+9)/2]>>(8*((pos-bytes+9)%2)))&255;
      value=(byte>>(7-bit%8))&1;
      if(bit%sub==0) assert(value==(!fragment2&&!bit));
      else {unsigned at=fragment2*payload+(bit/sub)*(sub-1)+bit%sub-1;assert(value==(at<112?((data[at/8]>>(7-at%8))&1):0));}
     }
    }
    memcpy(prev,words,sizeof(words));
   }
   assert(stream.replies_encoded==2&&stream.packet_index==0);
   msm5xxx_paging_stream_init(&stream);memcpy(ack,expected,14);ack[13]^=1;saved=stream;
   assert(!msm5xxx_paging_stream_queue(&stream,ack)&&!memcmp(&stream,&saved,sizeof(stream)));
  }
  puts("access ACK factory / both-rate carry / boundary insertion / back-to-back / rejection atomicity PASS");
 }

 for(n=0;n<10000;n++) assert(msm5xxx_radio_deadline(n)==(n*80000000ULL+11)/12);
 {uint64_t ticks[]={UINT64_MAX,UINT64_MAX/80000000*12,UINT64_MAX/80000000*12+11,UINT64_MAX/80000000*12-1};
  for(i=0;i<sizeof(ticks)/sizeof(*ticks);i++) { __uint128_t exact=((__uint128_t)ticks[i]*80000000+11)/12; assert(msm5xxx_radio_deadline(ticks[i])==(exact>UINT64_MAX?UINT64_MAX:(uint64_t)exact)); }
 }
 puts("PASS: both rates, golden frames, two-cycle carry/SOM/padding, invalid inputs/CRC, large frames/deadlines");
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                            "-Wextra", "-Werror", "-I", str(native),
                            str(path / "check.c"), str(native / "msm5xxx-search2.c"),
                            "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_fifo_aliases_full_wrap_status_and_stale_completion(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
#include <assert.h>
#include <string.h>
#include "msm5xxx-search2.h"

static uint16_t read_reg(MSM5xxxSearch2 *s, unsigned off) {
    uint16_t v = 0xdead;
    assert(msm5xxx_search2_read(s, off, 2, &v));
    return v;
}
static void submit(MSM5xxxSearch2 *s, unsigned tag, bool dump) {
    for (unsigned i=0; i<6; i++)
        assert(msm5xxx_search2_write(s, 4, 2, i ? tag+i : (dump ? 0x8000 : 0)));
}
static void drain(MSM5xxxSearch2 *s, const uint16_t words[8]) {
    for (unsigned i=0; i<8; i++) assert(read_reg(s, 12) == words[i]);
}
int main(void) {
    const uint8_t legacy[]={0,1,0x20,1,0x32,0xad,0,0x10,0x7e,0x3f,0x52,0x13,0x3f,0x76,0,0,0};
    MSM5xxxSearch2Parameters decoded;
    assert(msm5xxx_search1_decode(legacy,&decoded));
    assert(decoded.phase_index==254 && decoded.window_word==256 && decoded.phase_fraction==0);
    assert(decoded.mask_i==0x1352 && decoded.mask_q==0x763f && decoded.gain==2 && decoded.integration==1);
    uint8_t phase_packet[17];memcpy(phase_packet,legacy,17);
    for (unsigned phase=0;phase<512;phase++) {
        uint16_t packed=(phase<<6)-2;
        phase_packet[8]=packed;phase_packet[9]=packed>>8;
        assert(msm5xxx_search1_decode(phase_packet,&decoded));
        assert(decoded.phase_index==phase);
    }
    uint8_t invalid[17];memcpy(invalid,legacy,17);invalid[14]=1;
    assert(!msm5xxx_search1_decode(invalid,&decoded));
    invalid[14]=0;invalid[4]|=8;
    assert(!msm5xxx_search1_decode(invalid,&decoded));
    const uint8_t sync_message[]={0x1a,0x01,0x03,0x03,0x24,0x68,0xac,0xf1,0x2a,0x48,0xd1,0x59,0xe2,0x6a,0xc4,0x8d,0x15,0x9e,0x24,0x4a,0x48,0xd1,0x72,0x58,0x21,0xa9};
    const uint8_t sync_frames[3][12]={{0x8d,0x00,0x81,0x81,0x49,0x1a,0x2b,0x3c,0x25,0x49,0x1a,0x2b},
        {0x1e,0x26,0xac,0x48,0x68,0xac,0xf1,0x22,0x29,0x23,0x45,0xc9},
        {0x30,0x43,0x52,0,0,0,0,0,0,0,0,0}};
    uint16_t decoded_words[8];
    for(unsigned i=0;i<6;i++) {
        assert(msm5xxx_sync_frame(sync_message,sizeof(sync_message),i,decoded_words));
        for(unsigned w=0;w<6;w++) assert(decoded_words[w]==(sync_frames[i%3][2*w]|sync_frames[i%3][2*w+1]<<8));
        assert(!decoded_words[6]&&!decoded_words[7]);
    }
    uint8_t previous_tail[3]={0};
    for(unsigned frame=0;frame<7;frame++) {
        assert(msm5xxx_sync_decoder_frame(sync_message,sizeof(sync_message),frame,decoded_words));
        uint8_t raw[12],logical[12];
        for(unsigned i=0;i<12;i++)raw[i]=decoded_words[i/2]>>(8*(i%2));
        memcpy(logical,previous_tail,3);memcpy(logical+3,raw,9);memcpy(previous_tail,raw+9,3);
        if(!frame){const uint8_t zero[12]={0};assert(!memcmp(logical,zero,12));}
        else assert(!memcmp(logical,sync_frames[(frame-1)%3],12));
    }
    uint8_t corrupt[sizeof(sync_message)];
    for(unsigned i=0;i<sizeof(sync_message)*8;i++) {
        memcpy(corrupt,sync_message,sizeof(corrupt));corrupt[i/8]^=1<<(i%8);
        assert(!msm5xxx_sync_frame(corrupt,sizeof(corrupt),0,decoded_words));
    }
    assert(!msm5xxx_sync_frame(NULL,0,0,decoded_words));
    for(uint64_t i=1;i<=10000;i++) {
        uint64_t d=msm5xxx_combiner_deadline(i);
        assert(d==(i*80000000+2)/3);
        assert((msm5xxx_combiner_position(d)>>14)==i%3);
        assert((msm5xxx_combiner_position(d-1)>>14)==(i-1)%3);
        assert(msm5xxx_combiner_deadline(i+3)-d==80000000);
    }
    assert(msm5xxx_combiner_deadline(300000000001ULL)==8000000000026666667ULL);
    assert(msm5xxx_combiner_deadline(UINT64_MAX)==UINT64_MAX);
    MSM5xxxSearch2 s, before;
    MSM5xxxSearch2Job a, b, old;
    uint16_t value, words[8] = {1, 0xffff, 2, 0x8000, 0, 0x7fff, 8, 9};
    msm5xxx_search2_init(&s);
    assert(!msm5xxx_search2_begin(&s, &a));
    for (unsigned i=0; i<5; i++) {
        assert(msm5xxx_search2_write(&s,4,2,i ? i : 0x8000));
        assert(read_reg(&s,16)==(i+1)*0x100);
        assert(!msm5xxx_search2_begin(&s,&a));
    }
    assert(msm5xxx_search2_write(&s,4,2,5));
    assert(read_reg(&s,16)==0x1000);
    assert(msm5xxx_search2_begin(&s,&a));
    assert(read_reg(&s,16)==0x1010 && a.parameters[5]==5);
    before=s;
    assert(!msm5xxx_search2_begin(&s,&b) && !memcmp(&s,&before,sizeof(s)));
    assert(!msm5xxx_search2_complete(&s,NULL,words));
    assert(!msm5xxx_search2_complete(&s,&a,NULL));
    assert(msm5xxx_search2_complete(&s,&a,words));
    assert(!msm5xxx_search2_complete(&s,&a,words));
    assert(!msm5xxx_search2_dump_requested(&s));
    assert(msm5xxx_search2_write(&s,20,1,1));
    assert(!msm5xxx_search2_dump_requested(&s));
    assert(msm5xxx_search2_write(&s,20,1,3));
    assert(msm5xxx_search2_dump_requested(&s));
    assert(read_reg(&s,20)==0x1000); /* Direction+width alias of dump enable. */
    assert(msm5xxx_search2_read(&s,8,1,&value) && value==2);
    assert(!msm5xxx_search2_dump_requested(&s));
    assert(msm5xxx_search2_read(&s,8,1,&value) && value==0);
    for (unsigned i=0;i<7;i++) assert(read_reg(&s,12)==words[i]);
    assert(read_reg(&s,20)==0x1007 && s.result_records==1);
    assert(read_reg(&s,12)==words[7]);
    assert(read_reg(&s,20)==0x1010 && s.result_records==0);
    before=s; value=0xbeef;
    assert(!msm5xxx_search2_read(&s,12,2,&value) && value==0xbeef);
    assert(!memcmp(&s,&before,sizeof(s)));

    /* Invalid widths/commands cannot consume results or alter any state. */
    const unsigned offsets[]={0,4,8,12,16,20,24,255};
    for (unsigned i=0;i<8;i++) for (unsigned width=0;width<=4;width++) {
        before=s;
        bool ok=msm5xxx_search2_read(&s,offsets[i],width,&value);
        if (!ok) assert(!memcmp(&s,&before,sizeof(s)));
        s=before;
        ok=msm5xxx_search2_write(&s,offsets[i],width,0xffff);
        if (!ok) assert(!memcmp(&s,&before,sizeof(s)));
        s=before;
    }
    assert(!msm5xxx_search2_read(&s,8,1,NULL));
    for (unsigned command=1;command<=2;command++) {
        before=s;
        assert(!msm5xxx_search2_write(&s,0,1,command));
        assert(!memcmp(&s,&before,sizeof(s)));
    }

    /* Equal hardware pointers can mean FULL, not just EMPTY. */
    msm5xxx_search2_reset(&s);
    for (unsigned n=0;n<8;n++) submit(&s,n*16,false);
    assert(s.queued_records==8 && read_reg(&s,16)==0);
    before=s;
    assert(!msm5xxx_search2_write(&s,4,2,7));
    assert(!memcmp(&s,&before,sizeof(s)));
    for (unsigned n=0;n<8;n++) {
        assert(msm5xxx_search2_begin(&s,&a) && a.parameters[1]==n*16+1);
        assert(msm5xxx_search2_complete(&s,&a,words));
    }
    assert(s.result_records==8 && read_reg(&s,20)==0);
    submit(&s,123,false);
    assert(msm5xxx_search2_begin(&s,&a));
    before=s;
    assert(!msm5xxx_search2_complete(&s,&a,words));
    assert(!memcmp(&s,&before,sizeof(s)));
    for (unsigned i=0;i<7;i++) assert(read_reg(&s,12)==words[i]);
    assert(!msm5xxx_search2_complete(&s,&a,words));
    assert(read_reg(&s,12)==words[7]);
    assert(msm5xxx_search2_complete(&s,&a,words));
    for (unsigned n=0;n<8;n++) drain(&s,words);
    assert(!s.result_records);

    /* Reset invalidates in-flight responses, even after a new job begins. */
    submit(&s,1,true); assert(msm5xxx_search2_begin(&s,&old));
    before=s;
    assert(!msm5xxx_search2_write(&s,0,1,12));
    assert(!memcmp(&s,&before,sizeof(s)));
    msm5xxx_search2_reset(&s);
    submit(&s,1,true); assert(msm5xxx_search2_begin(&s,&a));
    assert(a.epoch!=old.epoch);
    before=s;
    assert(!msm5xxx_search2_complete(&s,&old,words));
    assert(!memcmp(&s,&before,sizeof(s)));
    assert(msm5xxx_search2_complete(&s,&a,words));

    /* Pointer strobes are independent; status/data are not invented by them. */
    submit(&s,2,false);
    assert(msm5xxx_search2_write(&s,0,1,8));
    assert(read_reg(&s,16)==0 && s.result_records==1 && s.status==2);
    submit(&s,3,false);
    assert(msm5xxx_search2_write(&s,0,1,4));
    assert(read_reg(&s,20)==0 && s.queued_records==1 && s.status==2);
    assert(msm5xxx_search2_read(&s,8,1,&value) && value==2);
    assert(msm5xxx_search2_begin(&s,&a));
    assert(msm5xxx_search2_complete(&s,&a,words));
    assert(msm5xxx_search2_read(&s,8,1,&value) && value==0);

    /* A captured packet, then every phase boundary in the same packing class. */
    MSM5xxxSearch2Parameters p, previous;
    a=(MSM5xxxSearch2Job){.parameters={0xffbe,0x56a5,0x465c,0,63,0xe000}};
    assert(msm5xxx_search2_decode(&a,&p));
    assert(p.dump && p.phase_index==511 && p.phase_fraction==511);
    assert(!p.window_word && !p.integration && !p.gain && !p.chips);
    for (unsigned phase=0;phase<512;phase++) for (unsigned dump=0;dump<2;dump++) {
        a.parameters[0]=(((phase<<6)-2)&0x7fff)|(dump<<15);
        a.parameters[3]=0xffff;
        a.parameters[4]=0;
        a.parameters[5]=0x1fff;
        assert(msm5xxx_search2_decode(&a,&p));
        assert(p.phase_index==phase && p.dump==(bool)dump);
        assert(p.window_word==0xffff && !p.phase_fraction);
        assert(p.integration==7 && p.gain==3 && p.chips==255);
    }
    const unsigned bad_indices[]={0,1,2,4,1,2};
    const uint16_t bad_values[]={0,0x8000,0x8000,64,0,0};
    for (unsigned i=0;i<6;i++) {
        b=a; b.parameters[bad_indices[i]]=bad_values[i]; previous=p;
        assert(!msm5xxx_search2_decode(&b,&p));
        assert(!memcmp(&p,&previous,sizeof(p)));
    }
    assert(!msm5xxx_search2_decode(NULL,&p));
    assert(!msm5xxx_search2_decode(&a,NULL));

    /* Repeated searches must keep the engine position, not just packet phase. */
    uint16_t virtual_words[8], unchanged[8]; uint32_t after;
    p=(MSM5xxxSearch2Parameters){.phase_index=511,.window_word=4};
    assert(msm5xxx_search2_virtual_result(&p,511,0,64000,virtual_words,&after));
    assert(virtual_words[0]==49000 && !virtual_words[1] && after==527);
    p.phase_fraction=1;
    assert(msm5xxx_search2_virtual_result(&p,511,0,64000,virtual_words,&after));
    assert(virtual_words[0]==64000 && after==528);
    const unsigned positions[]={0,511,0x3fffc}, phases[]={0,511};
    const unsigned fractions[]={0,1,511}, windows[]={0,1,4,256,8192};
    const unsigned pilots[]={0,1,0x3ffff}, energies[]={0,65535};
    for(unsigned x=0;x<3;x++) for(unsigned c=0;c<2;c++)
    for(unsigned f=0;f<3;f++) for(unsigned w=0;w<5;w++)
    for(unsigned v=0;v<3;v++) for(unsigned e=0;e<2;e++) {
        p=(MSM5xxxSearch2Parameters){.phase_index=phases[c],
            .phase_fraction=fractions[f],.window_word=windows[w]};
        assert(msm5xxx_search2_virtual_result(&p,positions[x],pilots[v],
                                             energies[e],virtual_words,&after));
        unsigned start=(positions[x]+fractions[f]+phases[c]*512)&0x3ffff;
        unsigned best=0,index=0;
        /* Independent all-bin oracle for the constant-time nearest-peak path. */
        for(unsigned i=0;i<windows[w];i++) {
            unsigned d=(start+4*i-pilots[v])&0x3ffff;
            if(d>0x20000) d=0x40000-d;
            unsigned energy=d<8 ? energies[e]*(8-d)*(8-d)/64 : 0;
            if(energy>best) {best=energy;index=i;}
        }
        assert(virtual_words[0]==best && virtual_words[1]==index);
        for(unsigned i=2;i<8;i++) assert(!virtual_words[i]);
        assert(after==((positions[x]+fractions[f]+4*windows[w])&0x3ffff));
    }
    memcpy(unchanged,virtual_words,sizeof(unchanged)); after=0x12345;
    p.window_word=8193;
    assert(!msm5xxx_search2_virtual_result(&p,0,0,1,virtual_words,&after));
    assert(after==0x12345 && !memcmp(unchanged,virtual_words,sizeof(unchanged)));
    p.window_word=1;
    assert(!msm5xxx_search2_virtual_result(&p,0x40000,0,1,virtual_words,&after));
    assert(!msm5xxx_search2_virtual_result(&p,0,0x40000,1,virtual_words,&after));
    assert(!msm5xxx_search2_virtual_result(NULL,0,0,1,virtual_words,&after));
    assert(!msm5xxx_search2_virtual_result(&p,0,0,1,NULL,&after));
    assert(!msm5xxx_search2_virtual_result(&p,0,0,1,virtual_words,NULL));
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                            "-Wextra", "-Werror", "-I", str(native),
                            str(path / "check.c"), str(native / "msm5xxx-search2.c"),
                            "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_finger_banks_separate_filter_writes_from_latched_rssi_and_position(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
#include <assert.h>
#include <string.h>
#include "msm5xxx-search2.h"
static void write_byte(MSM5xxxFingers *s,unsigned at,unsigned value) {
    assert(msm5xxx_fingers_write(s,at,1,value));
}
static unsigned read_value(MSM5xxxFingers *s,unsigned at,unsigned width) {
    uint16_t value=0xbeef;
    assert(msm5xxx_fingers_read(s,at,width,&value));
    return value;
}
static void program(MSM5xxxFingers *s,unsigned selector,unsigned slew) {
    write_byte(s,0x78,selector);
    write_byte(s,0x70,5);write_byte(s,0x74,1);
    write_byte(s,0x94,0xfe);write_byte(s,0x98,0xff);
    write_byte(s,0x9c,0);write_byte(s,0xa0,0x40);
    write_byte(s,0xa4,0);write_byte(s,0xa8,0x40);
    write_byte(s,0xb0,slew&255);write_byte(s,0xb4,(slew>>8)&255);
    write_byte(s,0xb8,(slew>>16)&255);
}
int main(void) {
    MSM5xxxFingers s;
    uint16_t mi[512]={0},mq[512]={0},untouched=0xbeef;
    mi[0]=mq[0]=0x4000;
    msm5xxx_fingers_reset(&s);write_byte(&s,0x8c,4);
    program(&s,1,0xfdfc28);write_byte(&s,0x90,0);
    assert(!msm5xxx_fingers_read(&s,0x8c,2,&untouched) && untouched==0xbeef);
    msm5xxx_fingers_latch(&s,0x1fc28,64000,mi,mq);
    assert(read_value(&s,0x8c,2)==64000); /* Not the filter parameter4. */
    assert(read_value(&s,0xb0,2)==0xfc28 && read_value(&s,0xb8,1)==1);
    assert(!msm5xxx_fingers_read(&s,0x8c,1,&untouched));
    program(&s,2,0xfdfc2c);
    msm5xxx_fingers_latch(&s,0x1fc28,64000,mi,mq);
    assert(read_value(&s,0x8c,2)==16000);
    write_byte(&s,0x78,1);assert(read_value(&s,0x8c,2)==64000);
    write_byte(&s,0xb0,8);write_byte(&s,0xb4,0);write_byte(&s,0xb8,0);
    assert(read_value(&s,0x8c,2)==64000 && read_value(&s,0xb0,2)==0xfc28);
    msm5xxx_fingers_latch(&s,0x1fc28,64000,mi,mq);
    assert(read_value(&s,0x8c,2)==0 && read_value(&s,0xb0,2)==0xfc30);
    write_byte(&s,0xb0,0xf8);write_byte(&s,0xb4,0xff);write_byte(&s,0xb8,0xff);
    msm5xxx_fingers_latch(&s,0x1fc28,0,mi,mq);
    assert(read_value(&s,0x8c,2)==0);
    msm5xxx_fingers_latch(&s,0x1fc28,64000,mi,mq);
    assert(read_value(&s,0x8c,2)==64000);
    write_byte(&s,0x9c,1);
    msm5xxx_fingers_latch(&s,0x1fc28,64000,mi,mq);
    assert(read_value(&s,0x8c,2)==0);
    write_byte(&s,0x78,3);write_byte(&s,0x70,0x20);
    assert(!msm5xxx_fingers_read(&s,0x8c,2,&untouched));
    msm5xxx_fingers_latch(&s,0x1fc28,64000,mi,mq);
    write_byte(&s,0x78,1);assert(read_value(&s,0x8c,2)==0);
    write_byte(&s,0x78,2);assert(read_value(&s,0x8c,2)==0);
    assert(!msm5xxx_fingers_write(&s,0x78,1,16));
    assert(!msm5xxx_fingers_read(&s,0x8c,2,&untouched));
    write_byte(&s,0x78,1);
    assert(!msm5xxx_fingers_write(&s,0x70,1,0x40));
    assert(!msm5xxx_fingers_read(&s,0xb0,2,&untouched));
    msm5xxx_fingers_reset(&s);write_byte(&s,0x78,1);
    assert(!msm5xxx_fingers_read(&s,0x8c,2,&untouched));
    assert(!msm5xxx_fingers_write(&s,0x8c,2,4));
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                            "-Wextra", "-Werror", "-I", str(native),
                            str(path / "check.c"), str(native / "msm5xxx-search2.c"),
                            "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_access_fifo_crc_prefix_address_bounds_gaps_and_eviction(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "msm5xxx-search2.h"
static unsigned decode(const char *hex,uint8_t *out) {
 unsigned n=strlen(hex)/2,value;
 assert(n<=255 && strlen(hex)==n*2);
 for(unsigned i=0;i<n;i++) {assert(sscanf(hex+2*i,"%2x",&value)==1);out[i]=value;}
 return n;
}
static bool feed(MSM5xxxAccess *s,const uint8_t *data,unsigned n) {
 bool accepted=false;
 for(unsigned at=0;at<n;at+=11) {
  uint8_t piece[11]={0};unsigned count=n-at<11?n-at:11;
  memcpy(piece,data+at,count);accepted|=msm5xxx_access_push(s,piece,11);
 }
 return accepted;
}
int main(void) {
 MSM5xxxAccess s;uint8_t p[255],piece[11]={0},zero[264]={0};unsigned n;
 msm5xxx_access_init(&s);assert(!s.window_length&&!s.packets&&!s.pieces&&!s.examined);
 n=decode("090414400016042793",p);assert(feed(&s,p,n));
 assert(s.last.length==9&&s.last.type==4&&s.last.format==0&&s.last.sequence==5&&!s.last.address_valid);
 assert(!msm5xxx_access_push(&s,piece,11)&&s.packets==1); /* Do not count old candidates again. */
 n=decode("09441860003b0bff8b",p);assert(feed(&s,p,n));
 assert(s.last.format==1&&s.last.sequence==3&&s.last.address_mode==255&&!s.last.address_valid);
 msm5xxx_access_init(&s);n=decode("1a041402448d15aab89abcdef00000000000000000002e93f247",p);
 memset(piece,17,11);assert(!msm5xxx_access_push(&s,piece,11));
 assert(!msm5xxx_access_push(&s,p,11));assert(!msm5xxx_access_push(&s,p+11,11));
 memset(piece,0,11);memcpy(piece,p+22,n-22);assert(msm5xxx_access_push(&s,piece,11));
 assert(s.packets==1&&s.pieces==4&&s.last.length==26&&s.last.sequence==5);
 assert(s.last.address_valid&&s.last.address_mode==0&&s.last.address_length==9);
 assert(s.last.network24==0x123456&&s.last.network10==0x2ab);
 memset(piece,0,11);
 for(unsigned i=0;i<40;i++) assert(!msm5xxx_access_push(&s,piece,11));
 assert(s.window_length==264&&s.packets==1);
 assert(feed(&s,p,n)&&s.packets==2); /* New packet after window eviction. */
 MSM5xxxAccessPacket last;memcpy(&last,&s.last,sizeof(last));uint64_t packets=s.packets;
 msm5xxx_access_gap(&s);assert(!s.window_length&&!s.examined&&s.gaps==1);
 assert(!memcmp(s.window,zero,sizeof(zero))&&!memcmp(&last,&s.last,sizeof(last))&&s.packets==packets);
 /* A missing middle piece must never manufacture a contiguous packet. */
 msm5xxx_access_init(&s);assert(!msm5xxx_access_push(&s,p,11));
 msm5xxx_access_gap(&s);assert(!msm5xxx_access_push(&s,p+11,11));
 memset(piece,0,11);memcpy(piece,p+22,n-22);assert(!msm5xxx_access_push(&s,piece,11));
 assert(!s.packets);msm5xxx_access_gap(&s);assert(feed(&s,p,n)&&s.packets==1);
 msm5xxx_access_init(&s);p[n-1]^=1;assert(!feed(&s,p,n)&&s.crc_rejections>0&&!s.packets);p[n-1]^=1;
 n=decode("1a04140a448d15aab89abcdef00000000000000000001922c82e",p);msm5xxx_access_init(&s);assert(feed(&s,p,n));
 assert(s.last.address_mode==2&&!s.last.address_valid&&!s.last.network24&&!s.last.network10);
 n=decode("1a041402048d15aab89abcdef00000000000000000002a2cf5c6",p);msm5xxx_access_init(&s);assert(feed(&s,p,n));
 assert(s.last.address_mode==0&&s.last.address_length==8&&!s.last.address_valid);
 n=decode("0c0414024000000014143833",p);msm5xxx_access_init(&s);assert(feed(&s,p,n)&&!s.last.address_valid);
 n=decode("ff041402448d15aab89abcdef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000025a56c2f",p);assert(n==255);msm5xxx_access_init(&s);
 for(unsigned i=0;i<23;i++) assert(!msm5xxx_access_push(&s,p+i*11,11));
 assert(s.window_length==253&&!(s.examined&1));
 memset(piece,0,11);memcpy(piece,p+253,2);assert(msm5xxx_access_push(&s,piece,11));
 assert(s.last.length==255&&s.last.address_valid&&s.packets==1&&s.window_length==264);
 assert(!msm5xxx_access_push(&s,piece,11)&&s.window_length==264&&s.packets==1);
 for(unsigned format=2;format<=3;format++) {
  msm5xxx_access_init(&s);memset(piece,0,11);piece[0]=9;piece[1]=(format<<6)|4;
  assert(!msm5xxx_access_push(&s,piece,11)&&s.header_rejections==1);
 }
 msm5xxx_access_init(&s);memset(piece,0,11);piece[0]=6;piece[1]=4;
 assert(!msm5xxx_access_push(&s,piece,11)&&s.header_rejections==1);
 piece[0]=7;piece[1]=0x44;assert(!msm5xxx_access_push(&s,piece,11)&&s.header_rejections==2);
 assert(!msm5xxx_access_push(&s,NULL,11)&&!s.window_length);
 assert(!msm5xxx_access_push(&s,piece,10)&&!s.window_length);
 assert(!msm5xxx_access_push(&s,piece,12)&&!s.window_length);
 assert(s.gaps==3);
 msm5xxx_access_init(&s);
 for(unsigned i=0;i<sizeof(s);i++) assert(((const uint8_t *)&s)[i]==0);
 puts("access FIFO actual-C: golden CRC/format/seq/address bounds/gaps/eviction/max255/reset PASS");
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                            "-Wextra", "-Werror", "-I", str(native),
                            str(path / "check.c"), str(native / "msm5xxx-search2.c"),
                            "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_access_assignment_golden_and_retained_reply_alias(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
#include <assert.h>
#include <string.h>
#include "msm5xxx-search2.h"
int main(void) {
 const uint8_t expected[16]={0x10,0x08,0x01,0x0a,0x24,0x68,0xad,0x55,0x80,0x10,0x04,0x00,0x03,0x47,0x4d,0x77};
 MSM5xxxAccessPacket p={.length=26,.type=4,.format=0,.sequence=0,.address_mode=0,
  .address_length=9,.address_valid=true,.network24=0x123456,.network10=0x2ab};
 uint8_t out[16],messages[4][255]={{0}},lengths[4]={16,16,16,16};
 uint16_t words[14];
 assert(msm5xxx_access_assignment(&p,0,1,out)&&!memcmp(out,expected,16));
 for(unsigned code=0;code<=129;code+=129) {
  memset(out,0xa5,sizeof(out));assert(!msm5xxx_access_assignment(&p,0,code,out));
  for(unsigned i=0;i<sizeof(out);i++) assert(out[i]==0xa5);
 }
 assert(!msm5xxx_access_assignment(NULL,0,1,out));
 assert(!msm5xxx_access_assignment(&p,0,1,NULL));
 for(unsigned i=0;i<4;i++) memcpy(messages[i],expected,16);
 for(unsigned rate=0;rate<2;rate++) for(unsigned legacy=0;legacy<2;legacy++) {
  MSM5xxxPagingStream s;uint8_t saved[16];unsigned frames=0;
  msm5xxx_paging_stream_init(&s);
  if(legacy) assert(msm5xxx_access_ack(&p,0,out));else memcpy(out,expected,16);
  assert(msm5xxx_paging_stream_queue_message(&s,out,legacy?14:16));
  while(!s.replies_encoded) {
   assert(frames++<4&&msm5xxx_paging_stream_frame(&s,messages,lengths,rate,words));
  }
  memcpy(saved,s.reply,sizeof(saved));
  if(legacy) assert(msm5xxx_paging_stream_queue(&s,s.reply));
  else assert(msm5xxx_paging_stream_queue_message(&s,s.reply,s.reply_length));
  assert(!memcmp(saved,s.reply,sizeof(saved))&&s.reply[0]==(legacy?14:16));
  while(s.replies_encoded<2) {
   assert(frames++<8&&msm5xxx_paging_stream_frame(&s,messages,lengths,rate,words));
  }
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                            "-Wextra", "-Werror", "-I", str(native),
                            str(path / "check.c"), str(native / "msm5xxx-search2.c"),
                            "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_traffic_erasure_descriptor_geometry_and_atomicity(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
#include <assert.h>
#include <string.h>
#include "msm5xxx-search2.h"
int main(void) {
 const uint8_t rows[][8] = {
  {0,28,44,54,24,12,6,4}, {0,40,62,76,36,18,10,6},
  {0,28,44,56,24,12,8,4}
 };
 const unsigned expected[] = {31,43,32};
 uint16_t buffer[45]; unsigned count;
 for(unsigned row=0;row<3;row++) {
  for(unsigned i=0;i<45;i++) buffer[i]=0xa55a;
  count=123;
  assert(msm5xxx_traffic_erasure_frame(rows[row],buffer+1,&count));
  assert(count==expected[row] && buffer[0]==0xa55a);
  for(unsigned i=1;i<45;i++) assert(buffer[i]==(i<=count?0:0xa55a));
 }
 for(unsigned field=0;field<8;field++) {
  uint8_t invalid[8];memcpy(invalid,rows[0],8);invalid[field]^=1;
  for(unsigned i=0;i<45;i++) buffer[i]=0xa55a;
  count=123;
  assert(!msm5xxx_traffic_erasure_frame(invalid,buffer+1,&count) && count==123);
  for(unsigned i=0;i<45;i++) assert(buffer[i]==0xa55a);
 }
 for(unsigned missing=0;missing<3;missing++) {
  count=123;
  assert(!msm5xxx_traffic_erasure_frame(missing==0?NULL:rows[0],
   missing==1?NULL:buffer+1,missing==2?NULL:&count));
  assert(count==123);
 }
 for(unsigned i=0;i<45;i++) buffer[i]=0xa55a;
 memcpy(buffer+1,rows[0],8);count=123;
 assert(msm5xxx_traffic_erasure_frame((const uint8_t *)(buffer+1),buffer+1,&count));
 assert(count==31 && buffer[0]==0xa55a && buffer[44]==0xa55a);
 for(unsigned i=1;i<=count;i++) assert(buffer[i]==0);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                            "-Wextra", "-Werror", "-I", str(native),
                            str(path / "check.c"), str(native / "msm5xxx-search2.c"),
                            "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_decoded_traffic_crc_payload_and_atomic_rejection(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
#include <assert.h>
#include <string.h>
#include "msm5xxx-search2.h"
int main(void) {
 const uint8_t row[8]={0,28,44,54,24,12,6,4};
 /* Fixed codeword: 172 zero information bits, CRC12=0x3d7, eight zero tail bits. */
 const uint8_t golden[24]={[21]=3,[22]=0xd7};
 uint8_t frame[24], changed[8];
 uint16_t out[MSM5XXX_TRAFFIC_MAX_WORDS];unsigned count;
 for(unsigned bit=0;bit<=184;bit++) {
  memcpy(frame,golden,24);
  if(bit<184)frame[bit/8]^=1u<<(7-bit%8);
  memset(out,0xa5,sizeof(out));count=123;
  assert(msm5xxx_traffic_decoded_frame(row,frame,24,out,&count)&&count==31);
  for(unsigned i=0;i<12;i++)assert(out[i]==(frame[2*i]|(frame[2*i+1]<<8)));
  assert(out[12]==(bit==184?0x100:0));
  for(unsigned i=13;i<MSM5XXX_TRAFFIC_MAX_WORDS;i++)assert(out[i]==(i<count?0:0xa5a5));
 }
 memset(frame,0,24);
 assert(msm5xxx_traffic_decoded_frame(row,frame,24,out,&count));
 for(unsigned i=0;i<count;i++)assert(out[i]==0);
 for(unsigned bad=0;bad<16;bad++) {
  const uint8_t *desc=changed,*input=frame;size_t size=24;
  memcpy(changed,row,8);memcpy(frame,golden,24);
  memset(out,0xa5,sizeof(out));count=123;
  if(bad<8)changed[bad]^=1;
  else switch(bad) {
   case 8:desc=NULL;break;
   case 9:input=NULL;break;
   case 10:size=0;break;
   case 11:size=23;break;
   case 12:size=25;break;
   case 13:size=SIZE_MAX;break;
   case 14:frame[23]=1;break;
   case 15:changed[4]=36;break;
  }
  assert(!msm5xxx_traffic_decoded_frame(desc,input,size,out,&count)&&count==123);
  for(unsigned i=0;i<MSM5XXX_TRAFFIC_MAX_WORDS;i++)assert(out[i]==0xa5a5);
 }
 assert(!msm5xxx_traffic_decoded_frame(row,golden,24,NULL,&count));
 assert(!msm5xxx_traffic_decoded_frame(row,golden,24,out,NULL));
 memcpy(out,golden,24);
 assert(msm5xxx_traffic_decoded_frame(row,(uint8_t *)out,24,out,&count));
 assert(count==31&&out[12]==0x100&&!memcmp(out,golden,24));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                            "-Wextra", "-Werror", "-fsanitize=undefined",
                            "-fno-sanitize-recover=all", "-I", str(native),
                            str(path / "check.c"), str(native / "msm5xxx-search2.c"),
                            "-o", str(path / "check")], check=True)
            subprocess.run([str(path / "check")], check=True, timeout=10)
