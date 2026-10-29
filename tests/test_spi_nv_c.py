import subprocess
import tempfile
import unittest
from pathlib import Path


class TestSPINVC(unittest.TestCase):
    def test_wire_readback_busy_reset_and_rejected_frames(self):
        core = Path(__file__).resolve().parents[1] / "experiments/qemu-tcg"
        harness = r'''#include "msm5xxx-spi-nv.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static MSM5xxxSPINV s;
static uint8_t image[65536], before[65536];
static uint64_t now;
static bool pin(bool cs, bool clock, bool data)
{
    return msm5xxx_spi_nv_step(&s, ++now, cs, clock, data);
}
static void select_device(void) { pin(false, false, false); }
static void deselect(void) { pin(true, false, false); }
static void tx(uint8_t value)
{
    for (int i = 7; i >= 0; i--) {
        bool bit = ((value >> i) & 1) != 0;
        pin(false, false, !bit); /* No edge: changing D must not latch it. */
        pin(false, true, bit);
        pin(false, false, bit);
    }
}
static uint8_t rx(void)
{
    uint8_t value = 0;
    for (unsigned i = 0; i < 8; i++) {
        bool bit;
        pin(false, true, false);
        assert(msm5xxx_spi_nv_miso(&s, &bit));
        value = (uint8_t)((value << 1) | bit);
        pin(false, false, false);
    }
    return value;
}
static void fresh(unsigned capacity)
{
    memset(image, 0xff, sizeof(image));
    assert(msm5xxx_spi_nv_init(&s, image, capacity, 10000));
    now = 0;
}
static void command(uint8_t op)
{
    select_device(); tx(op); deselect();
}
static void address(uint16_t at) { tx((uint8_t)(at >> 8)); tx((uint8_t)at); }
static void write_begin(uint16_t at) { select_device(); tx(2); address(at); }
static void complete(void)
{
    assert(s.wip);
    assert(!msm5xxx_spi_nv_advance(&s, s.deadline_ns - 1));
    now = s.deadline_ns;
    assert(msm5xxx_spi_nv_advance(&s, now));
}
static uint8_t status_wire(void)
{
    uint8_t value;
    select_device();tx(5);value=rx();deselect();return value;
}
static void tx3(uint8_t value)
{
    for(int i=7;i>=0;i--){bool bit=((value>>i)&1)!=0;pin(false,false,bit);pin(false,true,bit);}
}
static uint8_t rx3(void)
{
    uint8_t value=0;
    for(unsigned i=0;i<8;i++){
        bool bit;pin(false,false,false);assert(msm5xxx_spi_nv_miso(&s,&bit));
        value=(uint8_t)((value<<1)|bit);pin(false,true,false);
    }
    return value;
}
int main(void)
{
    fresh(8192);
    MSM5xxxSPINV saved = s;
    for (unsigned capacity = 0; capacity < 80; capacity++) {
        if (capacity == 32 || capacity == 64) continue;
        assert(!msm5xxx_spi_nv_init(&s, image, capacity, 1));
        assert(!memcmp(&s, &saved, sizeof(s)));
    }
    assert(!msm5xxx_spi_nv_init(&s, image, 65537, 1));
    assert(!msm5xxx_spi_nv_init(&s, image, 8192, 0));
    assert(!msm5xxx_spi_nv_init(&s, NULL, 8192, 1));
    assert(!msm5xxx_spi_nv_init(NULL, image, 8192, 1));
    bool level = true;
    assert(!msm5xxx_spi_nv_miso(&s, &level) && level);
    write_begin(0x1360);tx(0x9a);deselect();
    assert(s.rejected && s.last_reject == MSM5XXX_SPI_NV_WEL_REQUIRED && !s.wip && !s.commits);
    command(6);assert(s.wel && status_wire()==2);
    write_begin(0x1360);tx(0x9a);
    assert(image[0x1360]==0xff && !s.wip);
    deselect();assert(s.wip && s.wel && image[0x1360]==0xff && status_wire()==3);
    uint64_t deadline=s.deadline_ns;
    select_device();tx(3);address(0x1360);assert(s.rejected && s.last_reject==MSM5XXX_SPI_NV_BUSY_OPCODE);
    assert(!msm5xxx_spi_nv_miso(&s,&level));deselect();
    assert(s.wip && s.deadline_ns==deadline);
    complete();assert(image[0x1360]==0x9a && s.commits==1 && s.last_commit_page==0x1360 && !s.wel && !s.wip);
    assert(!msm5xxx_spi_nv_advance(&s,now) && status_wire()==0);
    select_device();tx(3);address(0x1360);assert(rx()==0x9a && rx()==0xff);deselect();
    assert(!msm5xxx_spi_nv_miso(&s,&level));
    puts("actual9A@1360/edge/WEL/WIP/busy/CS/read PASS");

    /* Last-byte-wins within one staged page, including >32 payload bytes. */
    fresh(8192);command(6);write_begin(0x137e);
    for (unsigned i=0;i<70;i++) tx((uint8_t)i);
    deselect();complete();
    uint8_t expected[32];memset(expected,0xff,sizeof(expected));
    for(unsigned i=0;i<70;i++)expected[(30+i)&31]=(uint8_t)i;
    assert(!memcmp(image+0x1360,expected,32) && image[0x135f]==0xff && image[0x1380]==0xff);
    image[8191]=0x12;image[0]=0x34;
    select_device();tx(3);address(0xffff);assert(rx()==0x12 && rx()==0x34);deselect();
    assert(msm5xxx_spi_nv_init(&s,image,65536,10000));
    image[65535]=0x56;image[0]=0x78;
    select_device();tx(3);address(0xffff);assert(rx()==0x56 && rx()==0x78);deselect();
    puts("page32 wrap/lastbytewins/16bit address/capacity/sequential wrap PASS");

    for(unsigned partial=0;partial<8;partial++) {
        fresh(8192);command(6);memcpy(before,image,sizeof(image));write_begin(0x1360);
        if(partial)tx(0x9a);
        for(unsigned i=0;i<partial;i++){pin(false,true,true);pin(false,false,true);}
        deselect();assert(s.rejected && s.last_reject==MSM5XXX_SPI_NV_TRUNCATED);
        assert(!s.wip && s.wel && !memcmp(image,before,sizeof(image)));
    }
    fresh(8192);select_device();tx(0x9f);assert(s.rejected && !msm5xxx_spi_nv_miso(&s,&level));
    tx(6);deselect();assert(!s.wel && !s.commits);
    command(6);assert(s.wel && !s.rejected);command(4);assert(!s.wel);
    select_device();tx(6);tx(0);deselect();assert(s.rejected && !s.wel);
    select_device();deselect();assert(s.rejected);
    fresh(8192);select_device();tx(3);tx(0);deselect();assert(s.rejected);
    fresh(8192);command(6);write_begin(0x1360);tx(0x9a);deselect();
    msm5xxx_spi_nv_power_reset(&s);assert(!s.wip && !s.wel && !s.commits && image[0x1360]==0xff);
    assert(!msm5xxx_spi_nv_advance(&s,UINT64_MAX));
    command(6);write_begin(0x1360);tx(0x9a);deselect();complete();
    msm5xxx_spi_nv_power_reset(&s);assert(s.commits==1 && image[0x1360]==0x9a && !s.wel);
    puts("truncated frame/unknown/recovery/WRDI/extra bytes/power abort+preserve PASS");

    fresh(8192);command(6);select_device();tx(1);tx(0);deselect();
    assert(s.wip && s.wel && !s.commits && status_wire()==3);
    now=s.deadline_ns;assert(!msm5xxx_spi_nv_advance(&s,now));
    assert(!s.wip && !s.wel && !s.commits && status_wire()==0 && image[0x1360]==0xff);
    command(6);select_device();tx(1);tx(0x0c);deselect();
    assert(s.rejected && s.last_reject==MSM5XXX_SPI_NV_STATUS_VALUE && s.wel && !s.wip);
    select_device();tx(1);deselect();assert(s.rejected && !s.wip);
    select_device();tx(1);tx(0);tx(0);deselect();assert(s.rejected && !s.wip);
    fresh(8192);select_device();tx(1);tx(0);deselect();assert(s.rejected && !s.wip);
    puts("WRSR00-only/WEL/cycle/no-image-event/unsupported protection PASS");

    fresh(8192);command(6);write_begin(0x1360);tx(0x9a);
    now=UINT64_MAX-1;
    assert(!msm5xxx_spi_nv_step(&s,now,true,false,false));
    assert(s.rejected && s.last_reject==MSM5XXX_SPI_NV_TIME_OVERFLOW && !s.wip && s.wel && image[0x1360]==0xff);
    fresh(32);command(6);write_begin(0xffff);tx(0x55);deselect();
    now=s.deadline_ns;assert(msm5xxx_spi_nv_step(&s,now,true,false,false));
    assert(image[31]==0x55 && s.last_commit_page==0 && s.commits==1);
    s.commits=UINT64_MAX;command(6);write_begin(1);tx(0x42);deselect();
    now=s.deadline_ns;assert(msm5xxx_spi_nv_advance(&s,now) && s.commits==UINT64_MAX && image[1]==0x42);
    puts("deadline overflow/capacity32/commit-before-reply/counter saturation PASS");
    fresh(8192);pin(true,true,false);pin(false,true,false);tx3(6);pin(true,true,false);
    assert(s.wel);
    pin(false,true,false);tx3(2);tx3(0x13);tx3(0x60);tx3(0x9a);pin(true,true,false);complete();
    pin(false,true,false);tx3(3);tx3(0x13);tx3(0x60);assert(rx3()==0x9a);
    pin(false,false,false);pin(true,false,false);assert(!s.rejected && !msm5xxx_spi_nv_miso(&s,&level));
    fresh(8192);command(6);select_device();tx(1);tx(0);deselect();
    msm5xxx_spi_nv_power_reset(&s);assert(!s.wip && !s.wel && !s.commits && !s.pending_status);
    assert(!msm5xxx_spi_nv_advance(&s,UINT64_MAX));
    s.rejections=UINT64_MAX;command(0x9f);assert(s.rejections==UINT64_MAX && s.rejected);
    fresh(8192);command(6);write_begin(0x1360);tx(0x9a);
    msm5xxx_spi_nv_abort_frame(&s);deselect();
    assert(s.rejected && s.last_reject==MSM5XXX_SPI_NV_INVALID_ACCESS);
    assert(!s.wip && image[0x1360]==0xff && !s.commits);
    command(6);write_begin(0x1360);tx(0x9a);deselect();
    deadline=s.deadline_ns;msm5xxx_spi_nv_abort_frame(&s);
    assert(s.wip && s.deadline_ns==deadline);complete();
    assert(image[0x1360]==0x9a && s.commits==1);
    puts("mode3 edges/partial-read termination/WRSRpowerabort/reject-counter saturation PASS");
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "check.c").write_text(harness)
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                "-I", str(core), str(path / "check.c"),
                str(core / "msm5xxx-spi-nv.c"), "-o", str(path / "check"),
            ], check=True, timeout=30)
            subprocess.run([str(path / "check")], check=True, timeout=10)
