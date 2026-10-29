import subprocess
import tempfile
import unittest
from pathlib import Path


class TestAudioRequestC(unittest.TestCase):
    def test_sequence_timer0_raw_mirrors(self):
        core = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''#include "msm5xxx-audio-request.h"
#include <assert.h>
#include <stddef.h>
static void bytes(MSM5xxxAudioPacketSink *s,const unsigned char *p,size_t n){for(size_t i=0;i<n;i++) assert(msm5xxx_audio_packet_sink_feed_sequence(s,p[i]));}
static void header(MSM5xxxAudioPacketSink *s,unsigned char a){assert(msm5xxx_audio_packet_sink_feed_sequence(s,a));assert(msm5xxx_audio_packet_sink_feed_sequence(s,0x82));}
static void unchanged(const MSM5xxxAudioPacketSink *s,const MSM5xxxAudioPacketSink *old){
 assert(s->timer0_timebase==old->timer0_timebase&&s->timer0_time==old->timer0_time&&s->timer0_control==old->timer0_control&&s->timer0_pending_time==old->timer0_pending_time);
 assert(s->timer0_timebase_valid==old->timer0_timebase_valid&&s->timer0_time_valid==old->timer0_time_valid&&s->timer0_control_valid==old->timer0_control_valid);
 assert(s->timer_time==old->timer_time&&s->timer_control==old->timer_control&&s->timer_time_valid==old->timer_time_valid&&s->timer_control_valid==old->timer_control_valid);
 assert(s->sequence_parameter==old->sequence_parameter&&s->sequence_config==old->sequence_config&&s->sequence_parameter_valid==old->sequence_parameter_valid&&s->sequence_config_valid==old->sequence_config_valid);
 assert(s->register_writes==old->register_writes&&s->memory_writes==old->memory_writes&&s->sequence_pending_stage==old->sequence_pending_stage);
}
int main(void){
 MSM5xxxAudioPacketSink s;
 const unsigned char packet[]={0x52,0x82,0x9b,0x54,0x82,0x14,0x80};
 msm5xxx_audio_packet_sink_reset(&s);bytes(&s,packet,sizeof(packet));
 assert(s.timer0_timebase_valid&&s.timer0_timebase==0x1b&&s.timer0_time_valid&&s.timer0_time==0x14&&s.timer0_control_valid&&s.timer0_control==0&&s.register_writes==3);
 for(unsigned t=0;t<128;t++){header(&s,0x54);assert(msm5xxx_audio_packet_sink_feed_sequence(&s,t));assert(!s.timer0_time_valid&&!s.timer0_control_valid);assert(msm5xxx_audio_packet_sink_feed_sequence(&s,0x80));assert(s.timer0_time==t&&s.timer0_control==0&&s.timer0_time_valid&&s.timer0_control_valid);}
 for(unsigned v=0;v<256;v++) if(v!=0x80){msm5xxx_audio_packet_sink_reset(&s);header(&s,0x54);assert(msm5xxx_audio_packet_sink_feed_sequence(&s,0x14));assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,v));assert(s.reject&&!s.timer0_time_valid&&!s.timer0_control_valid);assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,0x80));}
 for(unsigned v=0;v<256;v++) if(v!=0x9b){msm5xxx_audio_packet_sink_reset(&s);header(&s,0x52);assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,v));assert(!s.timer0_timebase_valid);}
 for(unsigned v=128;v<256;v++){msm5xxx_audio_packet_sink_reset(&s);header(&s,0x54);assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,v));}
 for(unsigned a=0x52;a<=0x55;a++){msm5xxx_audio_packet_sink_reset(&s);assert(msm5xxx_audio_packet_sink_feed(&s,a));assert(msm5xxx_audio_packet_sink_feed(&s,0x82));assert(!msm5xxx_audio_packet_sink_feed(&s,a==0x52?0x9b:0x80));}
 msm5xxx_audio_packet_sink_reset(&s);header(&s,0x55);assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,0x80));
 msm5xxx_audio_packet_sink_reset(&s);header(&s,0x53);assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,0x80));
 msm5xxx_audio_packet_sink_reset(&s);bytes(&s,packet,sizeof(packet));header(&s,0x54);assert(msm5xxx_audio_packet_sink_feed_sequence(&s,0x15));assert(s.timer0_time==0x14&&!s.timer0_time_valid);msm5xxx_audio_packet_reset(&s.packet);header(&s,0x55);assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,0x80));assert(s.timer0_time==0x14&&!s.timer0_time_valid);
 msm5xxx_audio_packet_sink_reset(&s);header(&s,0x54);assert(msm5xxx_audio_packet_sink_feed_sequence(&s,0x14));assert(!msm5xxx_audio_packet_sink_feed(&s,0x80));
 for(unsigned a=0x57;a<=0x5e;a+=7){msm5xxx_audio_packet_sink_reset(&s);header(&s,0x54);assert(msm5xxx_audio_packet_sink_feed_sequence(&s,0x14));msm5xxx_audio_packet_reset(&s.packet);header(&s,a);assert(msm5xxx_audio_packet_sink_feed_sequence(&s,1));msm5xxx_audio_packet_reset(&s.packet);header(&s,0x55);assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,0x80));}
 msm5xxx_audio_packet_sink_reset(&s);assert(!s.timer0_timebase_valid&&!s.timer0_time_valid&&!s.timer0_control_valid&&!s.sequence_pending_stage);
 /* Nonmutation is measured immediately before the rejected byte, including
  * prior committed mirrors and validity. Accepted pending high already clears
  * pair validity; rejection must preserve that exact state too. */
 for(unsigned a=0x52;a<=0x55;a++) for(unsigned v=0;v<256;v++){
  if((a==0x52&&v==0x9b)||(a==0x54&&v<128)) continue;
  msm5xxx_audio_packet_sink_reset(&s);bytes(&s,packet,sizeof(packet));
  header(&s,(unsigned char)a);MSM5xxxAudioPacketSink old=s;
  assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,(unsigned char)v));unchanged(&s,&old);
  assert(s.reject);assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,0x80));unchanged(&s,&old);
 }
 for(unsigned v=0;v<256;v++) if(v!=0x80){
  msm5xxx_audio_packet_sink_reset(&s);bytes(&s,packet,sizeof(packet));header(&s,0x54);
  assert(msm5xxx_audio_packet_sink_feed_sequence(&s,0x33));MSM5xxxAudioPacketSink old=s;
  assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,(unsigned char)v));unchanged(&s,&old);
 }
 for(unsigned a=0x52;a<=0x55;a++){
  msm5xxx_audio_packet_sink_reset(&s);bytes(&s,packet,sizeof(packet));
  assert(msm5xxx_audio_packet_sink_feed(&s,(unsigned char)a));assert(msm5xxx_audio_packet_sink_feed(&s,0x82));
  MSM5xxxAudioPacketSink old=s;assert(!msm5xxx_audio_packet_sink_feed(&s,a==0x52?0x9b:0x80));unchanged(&s,&old);
 }
 /* The pair and timebase are independently valid raw mirrors. */
 msm5xxx_audio_packet_sink_reset(&s);header(&s,0x54);assert(msm5xxx_audio_packet_sink_feed_sequence(&s,0x2a));assert(msm5xxx_audio_packet_sink_feed_sequence(&s,0x80));
 assert(s.timer0_time==0x2a&&s.timer0_time_valid&&s.timer0_control_valid&&!s.timer0_timebase_valid);
 header(&s,0x52);assert(msm5xxx_audio_packet_sink_feed_sequence(&s,0x9b));assert(s.timer0_timebase==0x1b&&s.timer0_timebase_valid&&s.timer0_time==0x2a&&s.timer0_time_valid&&s.timer0_control_valid);
 assert(!msm5xxx_audio_packet_sink_feed_sequence(NULL,0));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                            "-I", str(core), str(path / "check.c"),
                            str(core / "msm5xxx-audio-request.c"), "-o", str(path / "check")],
                           check=True, timeout=30)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_sequence_timer_pair_raw_mirrors(self):
        core = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''#include "msm5xxx-audio-request.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void header(MSM5xxxAudioPacketSink *s, unsigned address, bool typed)
{
    assert((typed ? msm5xxx_audio_packet_sink_feed_sequence(s, address & 127) :
                    msm5xxx_audio_packet_sink_feed(s, address & 127)));
    assert((typed ? msm5xxx_audio_packet_sink_feed_sequence(s, 0x80 | (address >> 7)) :
                    msm5xxx_audio_packet_sink_feed(s, 0x80 | (address >> 7))));
}

static void rejected(MSM5xxxAudioPacketSink *s, uint8_t byte, bool typed)
{
    MSM5xxxAudioPacketSink before = *s;
    assert(!(typed ? msm5xxx_audio_packet_sink_feed_sequence(s, byte) :
                     msm5xxx_audio_packet_sink_feed(s, byte)));
    assert(s->reject && s->timer_time == before.timer_time &&
           s->timer_control == before.timer_control &&
           s->timer_time_valid == before.timer_time_valid &&
           s->timer_control_valid == before.timer_control_valid);
    assert(s->register_writes == before.register_writes);
    assert(!memcmp(s->channel, before.channel, sizeof(s->channel)));
    assert(!memcmp(s->memory, before.memory, sizeof(s->memory)));
    before = *s;
    assert(!msm5xxx_audio_packet_sink_feed_sequence(s, 0x85));
    assert(!memcmp(s, &before, sizeof(*s)));
}

int main(void)
{
    MSM5xxxAudioPacketSink s;
    for (unsigned raw = 0; raw < 128; raw++) {
        msm5xxx_audio_packet_sink_reset(&s);
        header(&s, 0x157, true);
        assert(msm5xxx_audio_packet_sink_feed_sequence(&s, raw));
        assert(!s.timer_time_valid && !s.timer_control_valid);
        assert(s.sequence_pending_stage == 3 && !s.timer_time && !s.timer_control);
        assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x85));
        assert(s.timer_time == raw && s.timer_control == 5 &&
               s.timer_time_valid && s.timer_control_valid && !s.sequence_pending_stage);
        assert(s.register_writes == 2);
        header(&s, 0x158, true);
        assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x80));
        assert(s.timer_time == raw && s.timer_time_valid &&
               !s.timer_control && s.timer_control_valid);
    }
    msm5xxx_audio_packet_sink_reset(&s);
    header(&s, 0x158, true);
    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x80));
    assert(!s.timer_time_valid && s.timer_control_valid && !s.timer_control);
    header(&s, 0x157, true);
    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 100));
    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x85));
    header(&s, 0x157, true);
    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 99));
    assert(s.timer_time == 100 && s.timer_control == 5 &&
           !s.timer_time_valid && !s.timer_control_valid);
    rejected(&s, 0x80, true); /* Pending pair cannot become independent rollback. */

    for (unsigned address = 0x157; address <= 0x158; address++) {
        msm5xxx_audio_packet_sink_reset(&s);
        header(&s, address, false);
        rejected(&s, address == 0x157 ? 100 : 0x80, false);
    }
    for (unsigned byte = 0; byte < 256; byte++) {
        if (byte == 0x85) { continue; }
        msm5xxx_audio_packet_sink_reset(&s);
        header(&s, 0x157, true);
        assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 100));
        rejected(&s, byte, true); /* Wrong/nonterminal config, including pair rollback. */
    }
    for (unsigned byte = 128; byte < 256; byte++) {
        msm5xxx_audio_packet_sink_reset(&s);
        header(&s, 0x157, true);
        rejected(&s, byte, true); /* A terminal/non7bit time never starts a pair. */
    }
    for (unsigned kind = 0; kind < 4; kind++) {
        msm5xxx_audio_packet_sink_reset(&s);
        header(&s, 0x157, true);
        assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 100));
        if (kind == 0) {
            msm5xxx_audio_packet_reset(&s.packet);
            header(&s, 0x158, true);
            assert(!s.sequence_pending_stage);
            rejected(&s, 0x85, true); /* Stale pair after external parser reset/new header. */
        } else if (kind == 1) {
            rejected(&s, 0x85, false); /* Cross API cannot complete opt-in state. */
        } else if (kind == 2) {
            s.packet.address = 0x159;
            rejected(&s, 0x85, true); /* Intermediate unknown address. */
        } else {
            msm5xxx_audio_packet_sink_reset(&s);
            header(&s, 0x158, true);
            rejected(&s, 0x85, true); /* Full reset drops pending dependency. */
        }
    }
    for (unsigned address = 0x15f; address <= 0x160; address++) {
        msm5xxx_audio_packet_sink_reset(&s);
        header(&s, 0x157, true);
        assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 100));
        msm5xxx_audio_packet_reset(&s.packet);
        header(&s, address, true);
        if (address == 0x15f) {
            rejected(&s, 0, true);
        } else {
            assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x84));
            assert(s.sequence_config_valid && s.sequence_config == 4);
            assert(!s.sequence_parameter_valid && !s.timer_time_valid && !s.timer_control_valid);
        }
    }
    msm5xxx_audio_packet_sink_reset(&s);
    header(&s, 0x15e, true);
    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x1b));
    msm5xxx_audio_packet_reset(&s.packet);
    header(&s, 0x158, true);
    rejected(&s, 0x85, true); /* Sequence parameter pending cannot authorize timer. */
    msm5xxx_audio_packet_sink_reset(&s);
    header(&s, 0x15e, true);
    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x1b));
    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0));
    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x84));
    assert(s.sequence_parameter_valid && s.sequence_parameter == 3456 && s.sequence_config == 4);
    header(&s, 0x157, true);
    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 100));
    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x85));
    assert(s.sequence_parameter == 3456 && s.sequence_config == 4 && s.timer_time == 100);
    msm5xxx_audio_packet_sink_reset(&s);
    assert(!s.timer_time_valid && !s.timer_control_valid && !s.sequence_pending_stage);
    assert(!msm5xxx_audio_packet_sink_feed_sequence(NULL, 0));
    puts("timer candidate: atomic pair / rollback / legacy / stale / boundaries PASS");
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                            "-I", str(core), str(path / "check.c"),
                            str(core / "msm5xxx-audio-request.c"),
                            "-o", str(path / "check")], check=True, timeout=30)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_timed_packet_streams(self):
        core = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
        #include <assert.h>
        #include <stddef.h>
        #include <string.h>
        #include "msm5xxx-audio-request.h"

        static void partial(MSM5xxxAudioTimedPacket *p, uint8_t value)
        {
            MSM5xxxAudioTimedPacketWrite w = {{123, 45, true}, 678};
            assert(msm5xxx_audio_timed_packet_feed(p, value, &w) == 0);
            assert(w.write.address == 123 && w.write.value == 45 && w.write.last);
            assert(w.delta == 678);
        }

        static void payload(MSM5xxxAudioTimedPacket *p, uint8_t value, int kind,
                            unsigned address, unsigned delta, bool last)
        {
            MSM5xxxAudioTimedPacketWrite w = {0};
            assert(msm5xxx_audio_timed_packet_feed(p, value, &w) == kind);
            assert(w.write.address == address && w.write.value == value);
            assert(w.write.last == last && w.delta == delta);
        }

        int main(void)
        {
            MSM5xxxAudioTimedPacket p = {0};
            /* Mixed timed register runs, raw memory, empty memory then another
             * register. Only a run's first write advances the relative clock. */
            const uint8_t stream[] = {
                0xca,0x0b,0x80,0x83,                /* delta74, REG B=83 */
                0x80,0x66,0x82,0x00,0x81,           /* delta0, REG166..167 */
                0,0x81,0,0,0x81,0x82,0xff,0,       /* delta128, MEM4000 */
                0xff,0,0,0x80,0x80,                /* empty MEM, discard127 */
                0x81,0x90,0x80,                     /* delta1, REG10=80 */
            };
            const unsigned addresses[] = {11,0x166,0x167,0x4000,0x4001,0x10};
            const unsigned deltas[] = {74,0,0,128,0,1};
            const uint8_t values[] = {0x83,0,0x81,0xff,0,0x80};
            const bool lasts[] = {true,false,true,false,true,true};
            for (unsigned cut = 0; cut <= sizeof(stream); cut++) {
                msm5xxx_audio_timed_packet_reset(&p);
                unsigned n = 0;
                for (unsigned i = 0; i < sizeof(stream); i++) {
                    if (i == cut) {
                        MSM5xxxAudioTimedPacket saved = p;
                        memset(&p, 0, sizeof(p)); p = saved;
                    }
                    MSM5xxxAudioTimedPacketWrite w = {{123,45,true},678};
                    int result = msm5xxx_audio_timed_packet_feed(&p, stream[i], &w);
                    if (!result) {
                        assert(w.write.address == 123 && w.write.value == 45);
                        assert(w.write.last && w.delta == 678);
                        continue;
                    }
                    assert(n < 6 && result == (n == 3 || n == 4 ? 2 : 1));
                    assert(w.write.address == addresses[n] && w.write.value == values[n]);
                    assert(w.write.last == lasts[n] && w.delta == deltas[n]);
                    n++;
                }
                assert(n == 6);
            }
            /* Delta width boundaries; byte3 always ends, with either bit7. */
            const unsigned deltas_to_test[] = {0,127,128,16383,16384,0x1fffff};
            for (unsigned k = 0; k < 6; k++) {
                for (unsigned high = 0; high <= 128; high += 128) {
                    msm5xxx_audio_timed_packet_reset(&p);
                    unsigned d = deltas_to_test[k], left = d, groups = 1;
                    while (left >= 128) {
                        partial(&p, left & 127); left >>= 7; groups++;
                    }
                    partial(&p, left | (groups == 3 ? high : 128));
                    partial(&p, 0x80);
                    payload(&p, 0, 1, 0, d, false);
                    payload(&p, 0x80, 1, 1, 0, true);
                    partial(&p, 0x81); partial(&p, 0x82);
                    payload(&p, 0x83, 1, 2, 1, true);
                }
            }
            /* Reset at every partial phase discards unfinished delta/body. */
            for (unsigned cut = 0; cut < sizeof(stream); cut++) {
                msm5xxx_audio_timed_packet_reset(&p);
                MSM5xxxAudioTimedPacketWrite w;
                for (unsigned i = 0; i < cut; i++)
                    assert(msm5xxx_audio_timed_packet_feed(&p, stream[i], &w) >= 0);
                msm5xxx_audio_timed_packet_reset(&p);
                partial(&p, 0x85); partial(&p, 0x82);
                payload(&p, 0x80, 1, 2, 5, true);
            }
            /* Invalid nested framing remains invalid, emits no partial event. */
            msm5xxx_audio_timed_packet_reset(&p);
            partial(&p, 0x81); p.packet.phase = 255;
            MSM5xxxAudioTimedPacketWrite w = {{123,45,true},678};
            assert(msm5xxx_audio_timed_packet_feed(&p, 0x80, &w) == -1);
            assert(msm5xxx_audio_timed_packet_feed(&p, 0x80, &w) == -1);
            assert(w.write.address == 123 && w.write.value == 45 && w.write.last && w.delta == 678);
            msm5xxx_audio_timed_packet_reset(NULL);
            assert(msm5xxx_audio_timed_packet_feed(NULL, 0, &w) == -1);
            MSM5xxxAudioTimedPacket saved = p;
            assert(msm5xxx_audio_timed_packet_feed(&p, 0, NULL) == -1);
            assert(!memcmp(&p, &saved, sizeof(p)));
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=undefined", "-fno-sanitize-recover=all",
                            "-I", str(core), str(path / "check.c"),
                            str(core / "msm5xxx-audio-request.c"),
                            "-o", str(path / "check")], check=True, timeout=30)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_sequence_packet_consumer(self):
        core = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
        #include <assert.h>
        #include <string.h>
        #include "msm5xxx-audio-request.h"

        static void prefix(MSM5xxxAudioPacketSink *s, unsigned high,
                           unsigned low)
        {
            assert(msm5xxx_audio_packet_sink_feed_sequence(s, 0x5e));
            assert(msm5xxx_audio_packet_sink_feed_sequence(s, 0x82));
            assert(msm5xxx_audio_packet_sink_feed_sequence(s, high));
            assert(!s->sequence_parameter_valid && !s->sequence_config_valid);
            assert(msm5xxx_audio_packet_sink_feed_sequence(s, low));
        }

        static void unchanged(MSM5xxxAudioPacketSink *s,
                              const MSM5xxxAudioPacketSink *before)
        {
            assert(s->sequence_parameter == before->sequence_parameter);
            assert(s->sequence_config == before->sequence_config);
            assert(s->sequence_parameter_valid == before->sequence_parameter_valid);
            assert(s->sequence_config_valid == before->sequence_config_valid);
            assert(s->sequence_pending_parameter == before->sequence_pending_parameter);
            assert(s->sequence_pending_stage == before->sequence_pending_stage);
            assert(s->register_writes == before->register_writes);
            assert(!memcmp(s->channel, before->channel, sizeof(s->channel)));
            assert(!memcmp(s->memory, before->memory, sizeof(s->memory)));
        }

        int main(void)
        {
            MSM5xxxAudioPacketSink s = {0}, saved;
            /* Every 14-bit value is raw; no timing or IRQ interpretation. */
            for (unsigned high = 0; high < 128; high++) {
                for (unsigned low = 0; low < 128; low++) {
                    prefix(&s, high, low);
                    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x84));
                    assert(s.sequence_parameter == (high << 7 | low));
                    assert(s.sequence_config == 4 && s.sequence_parameter_valid);
                    assert(s.sequence_config_valid && !s.sequence_pending_stage);
                }
            }
            /* Every other config, including nonterminal 04, rejects atomically. */
            for (unsigned config = 0; config < 256; config++) {
                if (config == 0x84) continue;
                msm5xxx_audio_packet_sink_reset(&s);
                prefix(&s, 0x1b, 0);
                saved = s;
                assert(!msm5xxx_audio_packet_sink_feed_sequence(&s, config));
                assert(s.reject == MSM5XXX_AUDIO_PACKET_REJECT_DEPENDENCY);
                unchanged(&s, &saved);
                saved = s;
                assert(!msm5xxx_audio_packet_sink_feed_sequence(&s, 0x84));
                assert(!memcmp(&s, &saved, sizeof(s)));
            }
            /* Terminal high/low cannot form the required same-packet triple. */
            for (unsigned which = 0; which < 2; which++) {
                msm5xxx_audio_packet_sink_reset(&s);
                assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x5e));
                assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x82));
                if (which) assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x1b));
                saved = s;
                assert(!msm5xxx_audio_packet_sink_feed_sequence(&s, 0x80));
                unchanged(&s, &saved);
            }
            /* Parser reset and either API's new header invalidate stale latches. */
            for (unsigned legacy = 0; legacy < 2; legacy++) {
                for (unsigned address = 0x5f; address <= 0x60; address++) {
                    msm5xxx_audio_packet_sink_reset(&s);
                    prefix(&s, 0x1b, 0);
                    msm5xxx_audio_packet_reset(&s.packet);
                    bool (*feed)(MSM5xxxAudioPacketSink *, uint8_t) = legacy ?
                        msm5xxx_audio_packet_sink_feed :
                        msm5xxx_audio_packet_sink_feed_sequence;
                    assert(feed(&s, address)); assert(feed(&s, 0x82));
                    assert(!s.sequence_pending_stage);
                    saved = s;
                    if (!legacy && address == 0x60) {
                        assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x84));
                        assert(s.sequence_config_valid && s.sequence_config == 4);
                        assert(!s.sequence_parameter_valid && s.sequence_parameter == saved.sequence_parameter);
                    } else {
                        assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,
                                                                      address == 0x60 ? 0x84 : 0));
                        unchanged(&s, &saved);
                    }
                }
            }
            /* Independent 0160 preserves a committed or invalid parameter. */
            for (unsigned committed = 0; committed < 2; committed++) {
                msm5xxx_audio_packet_sink_reset(&s);
                if (committed) {
                    prefix(&s, 0x1b, 0);
                    assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x84));
                }
                saved = s;
                assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x60));
                assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x82));
                assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x84));
                assert(s.sequence_config_valid && s.sequence_config == 4);
                assert(s.sequence_parameter == saved.sequence_parameter);
                assert(s.sequence_parameter_valid == saved.sequence_parameter_valid);
                assert(s.register_writes == saved.register_writes + 1);
                assert(!memcmp(s.channel, saved.channel, sizeof(s.channel)));
                assert(!memcmp(s.memory, saved.memory, sizeof(s.memory)));
            }
            /* Wrong standalone values and partial stages reject without committing. */
            for (unsigned value = 0; value < 256; value++) {
                if (value == 0x84) continue;
                msm5xxx_audio_packet_sink_reset(&s);
                assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x60));
                assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x82));
                saved = s;
                assert(!msm5xxx_audio_packet_sink_feed_sequence(&s, value));
                unchanged(&s, &saved);
            }
            for (unsigned stage = 1; stage <= 4; stage++) {
                if (stage == 2) continue;
                msm5xxx_audio_packet_sink_reset(&s);
                assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x60));
                assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x82));
                s.sequence_pending_stage = stage;
                saved = s;
                assert(!msm5xxx_audio_packet_sink_feed_sequence(&s, 0x84));
                unchanged(&s, &saved);
            }
            /* A legacy byte anywhere in a typed header withdraws ownership. */
            const unsigned addresses[] = {0x52, 0x54, 0x57, 0x60};
            for (unsigned i = 0; i < sizeof(addresses)/sizeof(addresses[0]); i++) {
                for (unsigned legacy_first = 0; legacy_first < 2; legacy_first++) {
                    msm5xxx_audio_packet_sink_reset(&s);
                    bool (*first)(MSM5xxxAudioPacketSink *, uint8_t) = legacy_first ?
                        msm5xxx_audio_packet_sink_feed : msm5xxx_audio_packet_sink_feed_sequence;
                    bool (*second)(MSM5xxxAudioPacketSink *, uint8_t) = legacy_first ?
                        msm5xxx_audio_packet_sink_feed_sequence : msm5xxx_audio_packet_sink_feed;
                    assert(first(&s, addresses[i])); assert(second(&s, 0x82));
                    saved = s;
                    assert(!msm5xxx_audio_packet_sink_feed_sequence(&s,
                        addresses[i] == 0x52 ? 0x9b : addresses[i] == 0x60 ? 0x84 : 1));
                    unchanged(&s, &saved);
                }
            }
            /* Legacy still rejects 015E; smoothing and reset retain their contract. */
            msm5xxx_audio_packet_sink_reset(&s);
            assert(msm5xxx_audio_packet_sink_feed(&s, 0x5e));
            assert(msm5xxx_audio_packet_sink_feed(&s, 0x82));
            assert(!msm5xxx_audio_packet_sink_feed(&s, 0x1b));
            assert(s.reject == MSM5XXX_AUDIO_PACKET_REJECT_REGISTER);
            msm5xxx_audio_packet_sink_reset(&s);
            prefix(&s, 0x1b, 0);
            assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x84));
            assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x63));
            assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0x82));
            assert(msm5xxx_audio_packet_sink_feed_sequence(&s, 0xbf));
            assert(s.smoothing_config_valid && s.smoothing_config == 0x3f);
            assert(s.sequence_parameter_valid && s.sequence_parameter == 3456);
            msm5xxx_audio_packet_sink_reset(&s);
            assert(!s.sequence_parameter_valid && !s.sequence_config_valid);
            assert(!s.sequence_pending_stage && !s.sequence_pending_parameter);
            assert(!msm5xxx_audio_packet_sink_feed_sequence(NULL, 0));
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=undefined", "-fno-sanitize-recover=all",
                            "-I", str(core), str(path / "check.c"),
                            str(core / "msm5xxx-audio-request.c"),
                            "-o", str(path / "check")], check=True, timeout=30)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_partial_packet_consumer(self):
        core = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
        #include <assert.h>
        #include <stddef.h>
        #include <string.h>
        #include "msm5xxx-audio-request.h"

        static void reg(MSM5xxxAudioPacketSink *s, unsigned address,
                        unsigned value, bool accepted)
        {
            if (address >= 128) {
                assert(msm5xxx_audio_packet_sink_feed(s, address & 127));
                address >>= 7;
            }
            assert(msm5xxx_audio_packet_sink_feed(s, address | 128));
            assert(msm5xxx_audio_packet_sink_feed(s, value | 128) == accepted);
        }

        static void mem_header(MSM5xxxAudioPacketSink *s,
                               unsigned address, unsigned count)
        {
            assert(msm5xxx_audio_packet_sink_feed(s, address & 127));
            assert(msm5xxx_audio_packet_sink_feed(s, (address >> 7) & 127));
            assert(msm5xxx_audio_packet_sink_feed(s, (address >> 14) | 128));
            assert(msm5xxx_audio_packet_sink_feed(s, count | 128));
        }

        int main(void)
        {
            MSM5xxxAudioPacketSink s = {0}, saved;
            const uint8_t packet[] = {0x2e, 0x82, 0x1b, 0, 0x84};
            unsigned i, slot, address;
            reg(&s, 0x133, 0x3f, true); /* BF is terminal data, independent of pitch/pointer. */
            assert(s.register_writes == 1 && !s.reject && s.channel[29].control_valid);
            assert(s.channel[29].control == 0x3f && !(s.channel[29].control & 0x40));
            assert(!s.channel[29].pitch_valid && !s.channel[29].pointer_valid);
            msm5xxx_audio_packet_sink_reset(&s);
            for (i = 0; i < sizeof(packet); i++) {
                assert(msm5xxx_audio_packet_sink_feed(&s, packet[i]));
            }
            assert(s.register_writes == 3 && !s.memory_writes && !s.reject);
            assert(s.channel[29].high_valid && s.channel[29].high == 0x1b);
            assert(s.channel[29].pointer_valid && s.channel[29].pointer == 0x1b00);
            assert(s.channel[29].level_valid && s.channel[29].level == 1);
            /* Same bounded register class at every slot in both physical windows. */
            for (slot = 0; slot < 32; slot++) {
                address = slot < 16 ? 6 * slot : 0xe0 + 6 * (slot - 16);
                reg(&s, address, 0x7f, true);
                reg(&s, address + 1, 0x7f, true);
                reg(&s, address + 2, 0x7c, true);
                assert(s.channel[slot].pointer == 0x7ffe);
                assert(s.channel[slot].level == 31);
            }
            /* Capacity is not implied: unsupported effects reject, stay rejected,
             * and leave previously consumed channel/memory state intact. */
            saved = s;
            reg(&s, 0x140, 0, false);
            assert(s.reject == MSM5XXX_AUDIO_PACKET_REJECT_REGISTER);
            assert(s.rejected_address == 0x140 && s.rejected_value == 0x80);
            assert(!memcmp(s.channel, saved.channel, sizeof(s.channel)));
            assert(s.register_writes == saved.register_writes);
            saved = s;
            assert(!msm5xxx_audio_packet_sink_feed(&s, 0xff));
            assert(!memcmp(&s, &saved, sizeof(s)));
            msm5xxx_audio_packet_sink_reset(&s);
            reg(&s, 1, 0, false); /* No invented reset timbre/high-byte value. */
            assert(s.reject == MSM5XXX_AUDIO_PACKET_REJECT_POINTER);
            assert(!s.channel[0].pointer_valid && !s.register_writes);
            for (address = 0; address < 0x235; address++) {
                bool supported = (address < 0x60 ||
                                  (address >= 0xe0 && address < 0x140));
                unsigned offset = address < 0x60 ? address % 6 :
                                  address >= 0xe0 ? (address-0xe0) % 6 : 5;
                supported = supported && (offset == 0 || offset == 2 || offset == 3 || offset == 5);
                supported = supported || address == 0x163;
                msm5xxx_audio_packet_sink_reset(&s);
                reg(&s, address, 0, supported);
                assert(s.register_writes == (supported ? 1 : 0));
            }
            /* Every channel in both windows, every 7-bit high/low pitch pair. */
            msm5xxx_audio_packet_sink_reset(&s);
            for (slot = 0; slot < 32; slot++) {
                address = slot < 16 ? 6 * slot : 0xe0 + 6 * (slot - 16);
                reg(&s, address, 0x1b, true); reg(&s, address + 1, 0, true);
                reg(&s, address + 2, 0x7c, true); reg(&s, address + 5, 0x7f, true);
                for (unsigned high = 0; high < 128; high++) {
                    for (unsigned low = 0; low < 128; low++) {
                        MSM5xxxAudioPacketChannel prior = s.channel[slot];
                        reg(&s, address + 3, high, true);
                        assert(s.channel[slot].pitch_high_valid && s.channel[slot].pitch_high == high);
                        assert(s.channel[slot].pitch == prior.pitch);
                        assert(s.channel[slot].pitch_valid == prior.pitch_valid);
                        reg(&s, address + 4, low, true);
                        assert(s.channel[slot].pitch_valid && s.channel[slot].pitch == 128 * high + low);
                        assert(s.channel[slot].pitch <= 0x3fff);
                        assert(s.channel[slot].pointer == 0x1b00 && s.channel[slot].level == 31);
                        assert(s.channel[slot].control_valid && s.channel[slot].control == 0x7f);
                    }
                }
                /* Control may change gate bits; committed/pending pitch remain independent. */
                MSM5xxxAudioPacketChannel prior = s.channel[slot];
                for (unsigned control = 0; control < 128; control++) {
                    reg(&s, address + 5, control, true);
                    prior.control = control; prior.control_valid = true;
                    assert(!memcmp(&prior, &s.channel[slot], sizeof(prior)));
                }
            }
            assert(s.register_writes == 32u * (4u + 2u * 128u * 128u + 128u));
            assert(!s.memory_writes && !s.reject);
            /* Missing high latch rejects atomically, retaining unrelated consumed state. */
            for (slot = 0; slot < 32; slot++) {
                msm5xxx_audio_packet_sink_reset(&s);
                address = slot < 16 ? 6 * slot : 0xe0 + 6 * (slot - 16);
                reg(&s, address, 0x1b, true); reg(&s, address + 1, 0, true);
                reg(&s, address + 2, 4, true); reg(&s, address + 5, 0x3f, true);
                mem_header(&s, 0x4000, 1); assert(msm5xxx_audio_packet_sink_feed(&s, 0xaa));
                saved = s;
                reg(&s, address + 4, 0x7f, false);
                assert(s.reject == MSM5XXX_AUDIO_PACKET_REJECT_DEPENDENCY);
                assert(s.rejected_address == address + 4 && s.rejected_value == 0xff);
                assert(!memcmp(s.channel, saved.channel, sizeof(s.channel)));
                assert(!memcmp(s.memory, saved.memory, sizeof(s.memory)));
                assert(s.register_writes == saved.register_writes && s.memory_writes == saved.memory_writes);
                saved = s; assert(!msm5xxx_audio_packet_sink_feed(&s, 0));
                assert(!memcmp(&s, &saved, sizeof(s)));
            }
            /* One streaming pair+control with all pauses, nonterminal high/low and BF end. */
            const uint8_t controls[] = {0x31,0x82,0x51,0x23,0xbf};
            for (unsigned cut = 0; cut <= sizeof(controls); cut++) {
                msm5xxx_audio_packet_sink_reset(&s);
                for (i = 0; i < sizeof(controls); i++) {
                    if (i == cut) { saved = s; memset(&s, 0, sizeof(s)); s = saved; }
                    assert(msm5xxx_audio_packet_sink_feed(&s, controls[i]));
                }
                assert(s.register_writes == 3 && !s.memory_writes && !s.reject);
                assert(s.channel[29].pitch == 0x28a3);
                assert(s.channel[29].control == 0x3f);
                assert(s.channel[29].pitch_valid && s.channel[29].control_valid);
                saved = s; msm5xxx_audio_packet_reset(&s.packet);
                assert(!memcmp(s.channel, saved.channel, sizeof(s.channel)));
                assert(s.register_writes == saved.register_writes);
                /* Pending high changes latch only; next low replaces committed tuple. */
                reg(&s, 0x131, 8, true);
                assert(s.channel[29].pitch == 0x28a3);
                reg(&s, 0x132, 0, true);
                assert(s.channel[29].pitch == 0x400);
                assert(s.channel[29].control == 0x3f && !s.memory_writes);
            }
            /* Smoothing configuration is independent of every voice and MEM.
             * Preserve all raw field combinations without inventing curves. */
            msm5xxx_audio_packet_sink_reset(&s);
            assert(!s.smoothing_config_valid);
            reg(&s, 0x12e, 0x1b, true);
            mem_header(&s, 0x4000, 1);
            assert(msm5xxx_audio_packet_sink_feed(&s, 0xaa));
            saved = s;
            for (unsigned config = 0; config < 64; config++) {
                reg(&s, 0x163, config, true);
                assert(s.smoothing_config_valid && s.smoothing_config == config);
                assert(s.register_writes == saved.register_writes + config + 1);
                assert(!memcmp(s.channel, saved.channel, sizeof(s.channel)));
                assert(!memcmp(s.memory, saved.memory, sizeof(s.memory)));
                assert(s.memory_writes == saved.memory_writes && !s.reject);
            }
            reg(&s, 0x12f, 0, true);
            assert(s.smoothing_config_valid && s.smoothing_config == 0x3f);
            assert(msm5xxx_audio_packet_sink_feed(&s, 0x63));
            msm5xxx_audio_packet_reset(&s.packet);
            assert(s.smoothing_config_valid && s.smoothing_config == 0x3f);
            s.register_writes = UINT32_MAX;
            reg(&s, 0x163, 0, true);
            assert(s.register_writes == UINT32_MAX && s.smoothing_config_valid);
            assert(!s.smoothing_config);
            msm5xxx_audio_packet_sink_reset(&s);
            assert(!s.smoothing_config_valid);
            /* A nonterminal value commits 0163; the next register stays unsupported. */
            assert(msm5xxx_audio_packet_sink_feed(&s, 0x63));
            assert(msm5xxx_audio_packet_sink_feed(&s, 0x82));
            assert(msm5xxx_audio_packet_sink_feed(&s, 0x3f));
            assert(s.smoothing_config_valid && s.smoothing_config == 0x3f);
            assert(!msm5xxx_audio_packet_sink_feed(&s, 0x80));
            assert(s.rejected_address == 0x164 && s.register_writes == 1);
            assert(s.smoothing_config_valid && s.smoothing_config == 0x3f);
            /* Unsupported shared control / reserved smoothing bit cannot alias a voice. */
            const uint8_t shared[][5] = {{0x5e,0x82,0x1b,0,0x84},
                                         {0x63,0x82,0xff,0,0}};
            for (unsigned which = 0; which < 2; which++) {
                msm5xxx_audio_packet_sink_reset(&s);
                reg(&s, 0, 2, true); reg(&s, 1, 3, true);
                reg(&s, 0x163, 0x15, true);
                mem_header(&s, 0x4000, 1);
                assert(msm5xxx_audio_packet_sink_feed(&s, 0xaa));
                saved = s;
                assert(msm5xxx_audio_packet_sink_feed(&s, shared[which][0]));
                assert(msm5xxx_audio_packet_sink_feed(&s, shared[which][1]));
                assert(!msm5xxx_audio_packet_sink_feed(&s, shared[which][2]));
                assert(s.reject == MSM5XXX_AUDIO_PACKET_REJECT_REGISTER);
                assert(s.rejected_address == (which ? 0x163 : 0x15e));
                assert(!memcmp(s.channel, saved.channel, sizeof(s.channel)));
                assert(!memcmp(s.memory, saved.memory, sizeof(s.memory)));
                assert(s.smoothing_config_valid && s.smoothing_config == saved.smoothing_config);
                assert(s.register_writes == saved.register_writes && s.memory_writes == saved.memory_writes);
                saved = s;
                assert(!msm5xxx_audio_packet_sink_feed(&s, 0x84));
                assert(!memcmp(&s, &saved, sizeof(s)));
            }
            /* The overlapping old address110 now belongs to physical slot24. */
            msm5xxx_audio_packet_sink_reset(&s);
            reg(&s, 0x110, 0x12, true);
            assert(s.channel[24].high_valid && s.channel[24].high == 0x12);
            assert(!s.channel[16].high_valid && s.register_writes == 1);
            /* Raw MEM bytes, exact endpoints; reject crossing without wrap or
             * rolling back a prefix already consumed by the device. */
            msm5xxx_audio_packet_sink_reset(&s);
            mem_header(&s, 0x4000, 2);
            assert(msm5xxx_audio_packet_sink_feed(&s, 0xff));
            assert(msm5xxx_audio_packet_sink_feed(&s, 0x80));
            assert(s.memory[0] == 0xff && s.memory[1] == 0x80);
            mem_header(&s, 0x5fff, 2);
            assert(msm5xxx_audio_packet_sink_feed(&s, 0xab));
            assert(!msm5xxx_audio_packet_sink_feed(&s, 0xcd));
            assert(s.memory_writes == 3 && s.memory[0x1fff] == 0xab);
            assert(s.reject == MSM5XXX_AUDIO_PACKET_REJECT_MEMORY);
            assert(s.rejected_address == 0x6000 && s.rejected_value == 0xcd);
            for (address = 0x3fff; address <= 0x6000; address += 0x2001) {
                msm5xxx_audio_packet_sink_reset(&s);
                mem_header(&s, address, 1);
                assert(!msm5xxx_audio_packet_sink_feed(&s, 0xff));
                assert(!s.memory_writes);
            }
            /* Partial packet survives a parser pause; explicit full reset drops it. */
            msm5xxx_audio_packet_sink_reset(&s);
            assert(msm5xxx_audio_packet_sink_feed(&s, 0x2e));
            saved = s;
            s = saved;
            for (i = 1; i < sizeof(packet); i++) {
                assert(msm5xxx_audio_packet_sink_feed(&s, packet[i]));
            }
            s.register_writes = UINT32_MAX;
            reg(&s, 0, 1, true);
            assert(s.register_writes == UINT32_MAX);
            s.memory_writes = UINT32_MAX;
            mem_header(&s, 0x4000, 1);
            assert(msm5xxx_audio_packet_sink_feed(&s, 2));
            assert(s.memory_writes == UINT32_MAX && s.memory[0] == 2);
            s.packet.phase = 255;
            assert(!msm5xxx_audio_packet_sink_feed(&s, 0));
            assert(s.reject == MSM5XXX_AUDIO_PACKET_REJECT_SYNTAX);
            msm5xxx_audio_packet_sink_reset(&s);
            assert(!s.reject && !s.register_writes && !s.memory_writes);
            assert(!s.smoothing_config_valid);
            for (i = 0; i < sizeof(s.memory); i++) assert(!s.memory[i]);
            for (slot = 0; slot < 32; slot++) {
                assert(!s.channel[slot].high_valid && !s.channel[slot].pointer_valid);
                assert(!s.channel[slot].level_valid);
                assert(!s.channel[slot].pitch_high_valid && !s.channel[slot].pitch_valid);
                assert(!s.channel[slot].control_valid);
                assert(!s.channel[slot].pitch_high && !s.channel[slot].pitch && !s.channel[slot].control);
            }
            msm5xxx_audio_packet_sink_reset(NULL);
            assert(!msm5xxx_audio_packet_sink_feed(NULL, 0));
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=undefined", "-fno-sanitize-recover=all",
                            "-I", str(core), str(path / "check.c"),
                            str(core / "msm5xxx-audio-request.c"),
                            "-o", str(path / "check")], check=True, timeout=30)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_command_packet_streams_and_reset(self):
        core = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
        #include <assert.h>
        #include <stddef.h>
        #include <string.h>
        #include "msm5xxx-audio-request.h"

        static void partial(MSM5xxxAudioPacket *p, unsigned value)
        {
            MSM5xxxAudioPacketWrite w = {0xdeadbeef, 0xa5, true};
            assert(msm5xxx_audio_packet_feed(p, value, &w) == 0);
            assert(w.address == 0xdeadbeef && w.value == 0xa5 && w.last);
        }

        static void payload(MSM5xxxAudioPacket *p, unsigned value, int kind,
                            unsigned address, bool last)
        {
            MSM5xxxAudioPacketWrite w = {0};
            assert(msm5xxx_audio_packet_feed(p, value, &w) == kind);
            assert(w.address == address && w.value == value && w.last == last);
        }

        int main(void)
        {
            MSM5xxxAudioPacket p = {0};
            MSM5xxxAudioPacketWrite w;
            const uint8_t stream[] = {0x5e,0x82,0x1b,0,0x84,0x90,0x80,
                                      0,0x20,0x80,0x82,0xff,0,0x81,0x83};
            const unsigned addresses[] = {0x15e,0x15f,0x160,0x10,
                                           0x1000,0x1001,1};
            const uint8_t values[] = {0x1b,0,0x84,0x80,0xff,0,0x83};
            const bool endings[] = {false,false,true,true,false,true,true};
            unsigned cut, i, n;
            /* Mixed register/memory packets, including every possible pause.
             * The last register byte is data, not a query type. */
            for (cut = 0; cut <= sizeof(stream); cut++) {
                msm5xxx_audio_packet_reset(&p);
                n = 0;
                for (i = 0; i < sizeof(stream); i++) {
                    if (i == cut) {
                        MSM5xxxAudioPacket saved = p;
                        memset(&p, 0, sizeof(p));
                        p = saved;
                    }
                    int result = msm5xxx_audio_packet_feed(&p, stream[i], &w);
                    if (result) {
                        assert(n < 7 && result == (n == 4 || n == 5 ? 2 : 1));
                        assert(w.address == addresses[n] && w.value == values[n]);
                        assert(w.last == endings[n]);
                        n++;
                    }
                }
                assert(n == 7);
            }
            /* One/two length groups; third address/second length bit7 is ignored.
             * Memory bytes keep all eight bits and never terminate by bit7. */
            const unsigned lengths[] = {0,1,127,128,16383};
            unsigned high, form, j;
            for (high = 0; high <= 0x80; high += 0x80) {
                for (form = 0; form < 2; form++) {
                    for (j = 0; j < sizeof(lengths)/sizeof(lengths[0]); j++) {
                        unsigned length = lengths[j];
                        if (!form && length > 127) continue;
                        msm5xxx_audio_packet_reset(&p);
                        partial(&p, 0x7f); partial(&p, 0x7f);
                        partial(&p, 0x7f | high);
                        partial(&p, (length & 0x7f) | (form ? 0 : 0x80));
                        if (form) partial(&p, (length >> 7) | high);
                        for (i = 0; i < length; i++) {
                            payload(&p, i & 0xff, 2, 0x1fffff + i, i+1 == length);
                        }
                        partial(&p, 0x80);
                        payload(&p, 0x91, 1, 0, true);
                    }
                }
            }
            /* Discard partial address, length, register and memory only on reset. */
            const uint8_t interrupted[][5] = {
                {0x7f}, {0x7f,0x7f}, {0,0,0x80}, {0,0,0x80,1},
                {0x81,0}, {0,0,0x80,0x82,0xff},
            };
            const unsigned sizes[] = {1,2,3,4,2,5};
            for (j = 0; j < 6; j++) {
                msm5xxx_audio_packet_reset(&p);
                for (i = 0; i < sizes[j]; i++) {
                    assert(msm5xxx_audio_packet_feed(&p, interrupted[j][i], &w) >= 0);
                }
                msm5xxx_audio_packet_reset(&p);
                partial(&p, 0x82); payload(&p, 0x85, 1, 2, true);
            }
            /* Zero-count packets emit nothing; overflow cannot wrap to address0. */
            msm5xxx_audio_packet_reset(&p);
            partial(&p, 0x80);
            p.address = UINT32_MAX;
            w = (MSM5xxxAudioPacketWrite){7,8,true};
            assert(msm5xxx_audio_packet_feed(&p, 0, &w) == -1);
            assert(w.address == 7 && w.value == 8 && w.last);
            assert(msm5xxx_audio_packet_feed(&p, 0x80, &w) == -1);
            msm5xxx_audio_packet_reset(&p);
            partial(&p, 0x80); p.address = UINT32_MAX;
            payload(&p, 0x80, 1, UINT32_MAX, true);
            partial(&p, 0x81); payload(&p, 0x80, 1, 1, true);
            msm5xxx_audio_packet_reset(NULL);
            assert(msm5xxx_audio_packet_feed(NULL, 0, &w) == -1);
            MSM5xxxAudioPacket saved = p;
            assert(msm5xxx_audio_packet_feed(&p, 0, NULL) == -1);
            assert(p.address == saved.address && p.remaining == saved.remaining &&
                   p.phase == saved.phase);
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=undefined", "-fno-sanitize-recover=all",
                            "-I", str(core), str(path / "check.c"),
                            str(core / "msm5xxx-audio-request.c"),
                            "-o", str(path / "check")], check=True, timeout=30)
            subprocess.run([str(path / "check")], check=True, timeout=10)

    def test_typed_request_boundaries_and_restart(self):
        core = Path(__file__).resolve().parents[1] / "native/qemu"
        harness = r'''
        #include <assert.h>
        #include <stddef.h>
        #include "msm5xxx-audio-request.h"

        static void request(MSM5xxxAudioReadback *s, unsigned address, unsigned type)
        {
            msm5xxx_audio_readback_index(s, 3);
            while (address >= 0x80) {
                assert(msm5xxx_audio_readback_write(s, address & 0x7f));
                address >>= 7;
            }
            assert(msm5xxx_audio_readback_write(s, address | 0x80));
            assert(msm5xxx_audio_readback_write(s, type | 0x80));
        }

        static void reset(MSM5xxxAudioReadback *s)
        {
            msm5xxx_audio_readback_index(s, 4);
            assert(msm5xxx_audio_readback_write(s, 0x80));
            assert(msm5xxx_audio_readback_status(s) == 0);
            assert(msm5xxx_audio_readback_write(s, 0));
            assert(msm5xxx_audio_readback_status(s) == 1);
        }

        static void check_readback(void)
        {
            MSM5xxxAudioReadback s = {0};
            uint8_t value = 0xee;
            unsigned address;
            msm5xxx_audio_readback_index(&s, 4);
            assert(msm5xxx_audio_readback_write(&s, 0));
            request(&s, 0x90, 2); /* Release without assertion seeds nothing. */
            assert(msm5xxx_audio_readback_status(&s) == 1);
            msm5xxx_audio_readback_index(&s, 0x43);
            assert(!msm5xxx_audio_readback_read(&s, &value) && value == 0xee);
            reset(&s);
            for (address = 0; address < 512; address++) {
                bool known = (address >= 0x90 && address <= 0xaf) ||
                             (address >= 0x14a && address <= 0x151);
                request(&s, address, 2);
                assert(msm5xxx_audio_readback_status(&s) == (known ? 0x41 : 1));
                assert(!msm5xxx_audio_readback_read(&s, &value)); /* Wrong index. */
                msm5xxx_audio_readback_index(&s, 0x43);
                assert(msm5xxx_audio_readback_read(&s, &value) == known);
                if (known) {
                    assert(value == (address < 0xa0 ? 0x60 :
                                     address <= 0xaf ? 0x3c : 0x40));
                }
                assert(!msm5xxx_audio_readback_read(&s, &value));
                assert(msm5xxx_audio_readback_status(&s) == 1);
            }
            request(&s, 0x90, 1);
            assert(!s.result_valid && msm5xxx_audio_readback_status(&s) == 1);
            request(&s, 0x90, 2);
            assert(s.result_valid);
            reset(&s); /* Pending response must not survive a reset. */
            assert(!s.result_valid);
            request(&s, 0x90, 2);
            assert(!msm5xxx_audio_readback_write(&s, 0x82));
            assert(!s.result_valid && msm5xxx_audio_readback_status(&s) == 0);
            request(&s, 0x90, 2); /* Explicit request restart recovers capacity. */
            assert(s.result_valid);
            msm5xxx_audio_readback_index(&s, 2);
            assert(msm5xxx_audio_readback_write(&s, 0));
            assert(!s.result_valid && !s.reset_known);
            request(&s, 0x90, 2);
            assert(!s.result_valid);
            /* Unknown write interrupts reset: later release cannot re-seed. */
            msm5xxx_audio_readback_index(&s, 4);
            assert(msm5xxx_audio_readback_write(&s, 0x80));
            msm5xxx_audio_readback_index(&s, 2);
            assert(msm5xxx_audio_readback_write(&s, 0));
            msm5xxx_audio_readback_index(&s, 4);
            assert(msm5xxx_audio_readback_write(&s, 0));
            assert(!s.reset_known);
        }

        int main(void)
        {
            check_readback();
            MSM5xxxAudioRequest r;
            const uint32_t addresses[] = {0, 0x7f, 0x80, 0x90, 0x14a,
                                         0x3fff, 0x4000, 0x1fffff};
            unsigned i, type;
            assert(msm5xxx_audio_request_feed(NULL, 0) == -1);
            msm5xxx_audio_request_begin(NULL);
            for (i = 0; i < sizeof(addresses)/sizeof(addresses[0]); i++) {
                for (type = 0; type < 128; type++) {
                    uint32_t address = addresses[i];
                    msm5xxx_audio_request_begin(&r);
                    while (address >= 0x80) {
                        assert(msm5xxx_audio_request_feed(&r, address & 0x7f) == 0);
                        address >>= 7;
                    }
                    assert(msm5xxx_audio_request_feed(&r, address | 0x80) == 0);
                    assert(!r.finished);
                    assert(msm5xxx_audio_request_feed(&r, type | 0x80) == 1);
                    assert(r.finished && !r.invalid);
                    assert(r.address == addresses[i] && r.type == type);
                    assert(msm5xxx_audio_request_feed(&r, 0x82) == -1);
                }
            }
            /* Actual observed packet: address90/type2. */
            msm5xxx_audio_request_begin(&r);
            assert(msm5xxx_audio_request_feed(&r, 0x10) == 0);
            assert(msm5xxx_audio_request_feed(&r, 0x81) == 0);
            assert(msm5xxx_audio_request_feed(&r, 0x82) == 1);
            assert(r.address == 0x90 && r.type == 2);
            /* Unterminated, nonminimal, missing type markers. */
            const uint8_t bad[][3] = {{0, 0, 0}, {0, 0x80, 0},
                                     {0x90, 2, 0}, {0x90, 0x7f, 0}};
            for (i = 0; i < 4; i++) {
                msm5xxx_audio_request_begin(&r);
                assert(msm5xxx_audio_request_feed(&r, bad[i][0]) == 0);
                if (i == 0) {
                    assert(msm5xxx_audio_request_feed(&r, bad[i][1]) == 0);
                    assert(msm5xxx_audio_request_feed(&r, bad[i][2]) == -1);
                } else {
                    assert(msm5xxx_audio_request_feed(&r, bad[i][1]) == -1);
                }
                assert(!r.finished && r.invalid);
                assert(msm5xxx_audio_request_feed(&r, 0x82) == -1);
            }
            msm5xxx_audio_request_begin(&r);
            assert(msm5xxx_audio_request_feed(&r, 0x10) == 0);
            msm5xxx_audio_request_begin(&r); /* discard interrupted address */
            assert(msm5xxx_audio_request_feed(&r, 0x81) == 0);
            assert(msm5xxx_audio_request_feed(&r, 0x82) == 1);
            assert(r.address == 1 && r.type == 2);
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-I", str(core), str(path / "check.c"),
                            str(core / "msm5xxx-audio-request.c"),
                            "-o", str(path / "check")], check=True, timeout=30)
            subprocess.run([str(path / "check")], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
