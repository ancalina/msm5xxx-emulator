"""Compile native route/status helpers with isolated guest-memory dependencies."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class NativeAudioIRQTests(unittest.TestCase):
    def test_live_gate_threshold_mask_ack_and_peer_preservation(self):
        repo = Path(__file__).resolve().parents[1]
        source = (repo / 'native/qemu/msm5xxx-poc.c').read_text()
        functions = []
        for signature in ('static bool msm5xxx_poc_ma2_irq_gate(',
                          'static uint8_t msm5xxx_poc_ma2_fifo_flags(',
                          'static void msm5xxx_poc_ma2_irq_update(',
                          'static bool msm5xxx_poc_audio_read_owned('):
            start = source.index(signature)
            functions.append(source[start:source.index('\nstatic ', start + 1)])
        code = r'''
#include <assert.h>
#include "msm5xxx-ma2-audio.c"
typedef uint64_t hwaddr;
typedef struct { bool running; struct { bool can_do_io; } neg; } CPUState;
typedef struct { uint32_t (*get_pc)(CPUState *); } CPUClass;
static CPUState test_cpu = {.running=true,.neg={.can_do_io=true}};
static CPUState *current_cpu = &test_cpu;
static uint32_t test_pc = 0x120;
static uint32_t get_pc(CPUState *cpu) { (void)cpu; return test_pc; }
static CPUClass test_class = {.get_pc=get_pc};
#define CPU(cpu) (cpu)
#define CPU_GET_CLASS(cpu) (&test_class)
#define MSM5XXX_POC_AUDIO_STATUS_REJECTED 3
static bool qemu_in_vcpu_thread(void) { return true; }
typedef struct {
    uint32_t audio_irq_route[10], ram_base, ram_size;
    uint32_t audio_irq_gate_status, audio_irq_assertions;
    uint32_t rex_irq_status_address, rex_irq_enable_address;
    bool audio_irq_configured, audio_ma2, audio_enabled, rex_irq_c80;
    bool rex_irq_read_consume, audio_stream_rejected, audio_irq_asserted;
    unsigned rex_irq_bank_count, audio_core_lock;
    uint16_t audio_command_pending_count[4], rex_irq_pending[2];
    CPUState *cpu;
    bool audio_sites_enabled;
    uint8_t audio_data_offset, audio_stream_status_pending;
    uint32_t audio_stream_reject_code;
    MSM5xxxMA2Audio ma2_audio;
} MSM5xxxPOCMachineState;
#define MACHINE(s) (s)
static bool msm5xxx_poc_audio_site_owned(const MSM5xxxPOCMachineState *s,
                                        bool write, hwaddr offset, uint32_t pc) {
    (void)s; return !write && offset == 2 && pc == 0x120;
}
static uint32_t memory[64];
static uint32_t msm5xxx_poc_guest_u32(uint32_t address) {
    assert(address >= 0x1000000 && address < 0x1000100 && !(address & 3));
    return memory[(address - 0x1000000) / 4];
}
static void qemu_mutex_lock(unsigned *p) { assert(!*p); ++*p; }
static void qemu_mutex_unlock(unsigned *p) { assert(*p == 1); --*p; }
static void msm5xxx_poc_rex_irq_update(MSM5xxxPOCMachineState *s) { (void)s; }
static void msm5xxx_poc_audio_pcm_cancel_watch(MSM5xxxPOCMachineState *s) { (void)s; }
''' + '\n'.join(functions) + r'''
int main(void) {
    MSM5xxxPOCMachineState s = {
        .audio_irq_route = {0x1000000,0x3000624,0x300062c,2,0x1000030,
                            0x1000032,0x2000,0x1000040,0x1000050,0x3000},
        .ram_base=0x1000000,.ram_size=0x100,.audio_irq_configured=true,
        .audio_ma2=true,.audio_enabled=true,.rex_irq_bank_count=2,
        .rex_irq_status_address=0x3000620,.rex_irq_enable_address=0x3000628,
    };
    msm5xxx_ma2_reset(&s.ma2_audio);
    for (unsigned i=0;i<5;i++) memory[i]=s.audio_irq_route[i+1];
    memory[5]=0x2001; memory[17]=0x10100; memory[20]=0x3001;
    s.ma2_audio.fm_irq_ctrl=0x13; s.ma2_audio.control=1;
    s.ma2_audio.fifo_count[0]=49; s.rex_irq_pending[1]=4;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.rex_irq_pending[1]==4);
    s.ma2_audio.fifo_count[0]=48;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.rex_irq_pending[1]==6);
    s.rex_irq_pending[1]&=~2u;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.rex_irq_pending[1]==6);
    assert(s.audio_irq_assertions==1);
    memory[6]=0xffff;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.audio_irq_gate_status==4);
    memory[6]=0x10000;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.audio_irq_gate_status==2);
    memory[6]=0;
    s.audio_command_pending_count[0]=1;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.rex_irq_pending[1]==4);
    s.audio_command_pending_count[0]=0; memory[20]=0;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.rex_irq_pending[1]==4);
    assert(s.audio_irq_gate_status==3);
    memory[20]=0x3001; memory[5]=0;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.audio_irq_gate_status==2);
    memory[5]=0x2001; s.ma2_audio.fm_irq_ctrl=0x10;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.rex_irq_pending[1]==4);
    s.ma2_audio.fifo_count[0]=0;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.rex_irq_pending[1]==6);
    s.ma2_audio.control=0;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.rex_irq_pending[1]==4);
    s.ma2_audio.control=1; s.ma2_audio.adpcm_irq_ctrl=1;
    msm5xxx_poc_ma2_irq_update(&s); assert(s.rex_irq_pending[1]==4);
    /* Exercise the actual owned-read branch, including pre-START occupancy.
     * These are current provisional semantics, not physical status evidence. */
    s.cpu=&test_cpu; s.audio_sites_enabled=true; s.audio_data_offset=2;
    s.ma2_audio.adpcm_irq_ctrl=0; s.ma2_audio.control=0;
    s.ma2_audio.page=MSM5XXX_MA2_PAGE_REG0;
    s.ma2_audio.index=MSM5XXX_MA2_STATUS1;
    s.ma2_audio.fm_irq_ctrl=0x13;
    s.ma2_audio.fifo_count[0]=48;
    uint64_t value=0xdead;
    assert(msm5xxx_poc_audio_read_owned(&s,2,1,&value) && value==15);
    s.ma2_audio.control=MSM5XXX_MA2_FM_START;
    s.ma2_audio.fifo_count[0]=49;
    assert(msm5xxx_poc_audio_read_owned(&s,2,1,&value) && value==14);
    memory[20]=0; value=0xdead;
    assert(!msm5xxx_poc_audio_read_owned(&s,2,1,&value) && value==0xdead);
    memory[20]=0x3001; s.audio_stream_rejected=true;
    assert(!msm5xxx_poc_audio_read_owned(&s,2,1,&value) && value==0xdead);
    s.audio_stream_rejected=false; test_pc=0x122;
    assert(!msm5xxx_poc_audio_read_owned(&s,2,1,&value) && value==0xdead);
    test_pc=0x120;
    assert(!msm5xxx_poc_audio_read_owned(&s,2,2,&value) && value==0xdead);
    assert(!s.audio_core_lock);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(code)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror',
                            '-I', str(repo / 'native/qemu'),
                            str(path / 'check.c'),'-o',str(path / 'check')], check=True)
            subprocess.run([str(path / 'check')], check=True)


if __name__ == '__main__':
    unittest.main()
