/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Standalone: cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined
 * -fno-sanitize-recover=all test_protected_nor.c -o test_protected_nor */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "msm5xxx-protected-nor.h"

#define BASE 0xb00000u
#define LENGTH 0xf0000u
static uint8_t seed[LENGTH], image[LENGTH], before[LENGTH];
static const uint32_t sectors[15] = {
    0x10000,0x10000,0x10000,0x10000,0x10000,0x10000,0x10000,0x10000,
    0x10000,0x10000,0x10000,0x10000,0x10000,0x10000,0x10000
};
static MSM5xxxProtectedNOR p;

static void setup(void)
{
    memset(seed, 0xff, sizeof(seed));
    assert(msm5xxx_protected_nor_init(&p, seed, image, LENGTH, BASE, sectors, 15, 10));
}
static bool wr(uint32_t address, uint32_t value)
{
    return msm5xxx_protected_nor_write(&p, address, 2, value);
}
static uint16_t rd(uint32_t address)
{
    uint16_t value = 0x1234;
    assert(msm5xxx_protected_nor_read(&p, address, 2, &value));
    return value;
}
static void prefix(uint32_t address)
{
    unsigned mask = address >= 0x800000 ? 0x3f : 0x7f;
    assert(wr(address, 0x60));
    assert(wr(address, (address >> 16) & mask));
    assert(wr(address, 0xac));
    assert(wr(address, mask & ~(address >> 16)));
    assert(wr(address, 0x7b));
}
static void finish(uint32_t address, uint16_t status)
{
    assert(wr(address, 0x70));
    assert(rd(address) == status);
    assert(wr(address, 0x50));
    assert(wr(address, 0xff));
}
static void single(uint32_t address, uint16_t value)
{
    prefix(address);assert(wr(address, 0x40));assert(wr(address, value));
    finish(address, 0x80);
}
static void stream(unsigned count)
{
    for (unsigned i = 0; i < count; i++) {
        unsigned value = i == 0 ? 0x70 : i == 1 ? 0x50 : i == 2 ? 0xff : i;
        assert(wr(BASE + i * 2, value));
    }
}
static void untouched(void)
{
    assert(!memcmp(image, before, sizeof(image)));
}
static void test_init(void)
{
    uint32_t bad[15];
    setup();MSM5xxxProtectedNOR saved = p;memcpy(before, image, sizeof(image));
#define BAD_INIT(S,W,L,B,G,N,T) do { \
    assert(!msm5xxx_protected_nor_init(&p,(S),(W),(L),(B),(G),(N),(T))); \
    assert(!memcmp(&p,&saved,sizeof(p)));untouched(); \
} while (0)
    BAD_INIT(seed,image,LENGTH,BASE,sectors,15,0);
    BAD_INIT(seed,image,LENGTH,BASE+1,sectors,15,10);
    BAD_INIT(seed,image,LENGTH-1,BASE,sectors,15,10);
    BAD_INIT(seed,image,LENGTH,0xffff0000,sectors,15,10);
    BAD_INIT(seed,image,LENGTH,BASE,sectors,0,10);
    BAD_INIT(seed,image,LENGTH,BASE,sectors,65,10);
    BAD_INIT(seed,seed,LENGTH,BASE,sectors,15,10);
    BAD_INIT(seed,seed+2,LENGTH-256,BASE,sectors,15,10);
    BAD_INIT((const uint8_t *)&p,image,LENGTH,BASE,sectors,15,10);
    BAD_INIT(seed,(uint8_t *)&p,LENGTH,BASE,sectors,15,10);
    BAD_INIT(seed,image,LENGTH,BASE,(const uint32_t *)&p,15,10);
    BAD_INIT(seed,image,LENGTH,BASE,(const uint32_t *)image,15,10);
    memcpy(bad,sectors,sizeof(bad));bad[14]++;
    BAD_INIT(seed,image,LENGTH,BASE,bad,15,10);
    memcpy(bad,sectors,sizeof(bad));bad[14]=0;
    BAD_INIT(seed,image,LENGTH,BASE,bad,15,10);
    BAD_INIT(seed,image,SIZE_MAX,BASE,sectors,15,10);
#undef BAD_INIT
    assert(!msm5xxx_protected_nor_init(NULL,seed,image,LENGTH,BASE,sectors,15,10));
    /* A bounded aperture ending at 2^32 is valid; crossing it is not. */
    uint8_t small_seed[256], small_work[256];uint32_t size=256;MSM5xxxProtectedNOR small;
    memset(small_seed,0xff,sizeof(small_seed));
    assert(msm5xxx_protected_nor_init(&small,small_seed,small_work,256,0xffffff00,&size,1,1));
    uint16_t value;assert(msm5xxx_protected_nor_read(&small,0xfffffffe,2,&value) && value==0xffff);
    assert(!msm5xxx_protected_nor_write(&small,0xfffffffe,4,0));
    assert(!memcmp(small_seed,small_work,256));
}
static void test_single_and_source_checkpoint(void)
{
    setup();seed[0x7600]=0xed;seed[0x7601]=0;
    assert(msm5xxx_protected_nor_init(&p,seed,image,LENGTH,BASE,sectors,15,10));
    assert(rd(BASE+0x7600)==0x00ed);
    /* Reconstructed from source + checkpoint, not a captured MMIO transcript. */
    prefix(BASE+0x7600);assert(wr(BASE+0x7600,0x40));assert(wr(BASE+0x7600,0x006d));
    assert(image[0x7600]==0xed && !p.programs);finish(BASE+0x7600,0x80);
    assert(rd(BASE+0x7600)==0x006d && seed[0x7600]==0xed && seed[0x7601]==0);
    setup();image[0x7600]=0xa5;image[0x7601]=0xf0;
    single(BASE+0x7600,0xf005);assert(rd(BASE+0x7600)==0xf005);
    single(BASE+0x7600,0x0005);assert(rd(BASE+0x7600)==5 && p.programs==2);
    single(BASE+0x7602,0x0070);single(BASE+0x7604,0x0050);single(BASE+0x7606,0x00ff);
    assert(rd(BASE+0x7602)==0x70 && rd(BASE+0x7604)==0x50 && rd(BASE+0x7606)==0xff);
    /* Physical 0->1 behavior unknown: virtual rejection, never partial commit. */
    memcpy(before,image,sizeof(image));prefix(BASE+0x7600);assert(wr(BASE+0x7600,0x40));
    assert(wr(BASE+0x7600,0xffff));assert(!wr(BASE+0x7600,0x70));untouched();
}
static void test_stream(void)
{
    setup();memcpy(before,image,sizeof(image));prefix(BASE);assert(wr(BASE,0x41));stream(128);
    untouched();assert(!p.programs);finish(BASE,0x80);assert(p.programs==1);
    assert(rd(BASE)==0x70 && rd(BASE+2)==0x50 && rd(BASE+4)==0xff && rd(BASE+254)==127);
    assert(rd(BASE+256)==0xffff);prefix(BASE+256);assert(wr(BASE+256,0x41));
    for(unsigned i=0;i<128;i++) { assert(wr(BASE+256+2*i,0x1234)); }
    finish(BASE+256,0x80);
    assert(p.programs==2 && rd(BASE+256)==0x1234);
    setup();memcpy(before,image,sizeof(image));prefix(BASE);assert(wr(BASE,0x41));stream(127);
    assert(!wr(BASE,0x70));untouched();
    prefix(BASE);assert(wr(BASE,0x41));stream(128);assert(!wr(BASE+256,0));untouched();
    prefix(BASE);assert(wr(BASE,0x41));assert(wr(BASE,0));assert(!wr(BASE,0));untouched();
    prefix(BASE+2);assert(!wr(BASE+2,0x41));untouched();
    prefix(BASE);assert(wr(BASE,0x41));stream(64);msm5xxx_protected_nor_reset(&p);
    assert(!wr(BASE,0x70));untouched();
    /* Entire page validates before committing even one byte. */
    image[254]=0;memcpy(before,image,sizeof(image));prefix(BASE);assert(wr(BASE,0x41));stream(128);
    assert(!wr(BASE,0x70));untouched();
}
static void test_prefix_and_foreign(void)
{
    const unsigned correct[5]={0x60,0x30,0xac,0x0f,0x7b};
    for(unsigned fail=0;fail<5;fail++) {
        setup();memcpy(before,image,sizeof(image));
        for(unsigned i=0;i<fail;i++)assert(wr(BASE+0x7600,correct[i]));
        assert(!wr(BASE+0x7600,correct[fail]^1));untouched();
    }
    setup();memcpy(before,image,sizeof(image));assert(wr(BASE+0x7600,0x60));
    assert(wr(BASE+0x7600,0x30));assert(wr(BASE+0x7600,0xac));
    assert(!wr(BASE+0x7600,0x80));untouched();
    uint8_t low_seed[256],low_work[256];uint32_t size=256;MSM5xxxProtectedNOR low;
    memset(low_seed,0xff,sizeof(low_seed));
    assert(msm5xxx_protected_nor_init(&low,low_seed,low_work,256,0x10000,&size,1,1));
    const unsigned commands[]={0x60,1,0xac,0x7e,0x7b,0x40,0x1234,0x70};
    for(unsigned i=0;i<sizeof(commands)/sizeof(*commands);i++)assert(msm5xxx_protected_nor_write(&low,0x10000,2,commands[i]));
    uint16_t status;assert(msm5xxx_protected_nor_read(&low,0x10000,2,&status) && status==0x80);
    assert(low_work[0]==0x34 && low_work[1]==0x12 && low_seed[0]==0xff);
}
static void test_errors(void)
{
    uint16_t value=0x1234;
    const unsigned widths[]={0,1,3,4,8};
    for(unsigned i=0;i<5;i++) { setup();memcpy(before,image,sizeof(image));assert(!msm5xxx_protected_nor_write(&p,BASE,widths[i],0x60));untouched();assert(!msm5xxx_protected_nor_read(&p,BASE,widths[i],&value)); }
    setup();memcpy(before,image,sizeof(image));assert(!wr(BASE+1,0x60));assert(!wr(BASE,0x10000));
    prefix(BASE+0x7600);assert(!wr(BASE+0x7602,0x40));untouched();
    assert(!wr(BASE,0x90));assert(!wr(BASE,0xd0));assert(!wr(BASE,0x70));assert(!wr(BASE,0x77));
    assert(rd(BASE)==0xffff);assert(wr(BASE,0x60));assert(!msm5xxx_protected_nor_read(&p,BASE,2,&value));untouched();
    prefix(BASE);assert(wr(BASE,0x40));assert(wr(BASE,0x1234));assert(!msm5xxx_protected_nor_read(&p,BASE,2,&value));untouched();
    assert(wr(BASE,0x60));MSM5xxxProtectedNOR saved=p;
    assert(!wr(BASE+LENGTH,0x30));assert(!msm5xxx_protected_nor_read(&p,BASE-2,2,&value));
    assert(!memcmp(&saved,&p,sizeof(p)));untouched();
    msm5xxx_protected_nor_reset(&p);prefix(BASE+2);assert(!wr(BASE+2,0x20));untouched();
    prefix(BASE);assert(!wr(BASE,0x77));untouched();
}
static void test_erase_suspend_verify(void)
{
    setup();memset(image,0x12,0x10000);image[0x10000]=0x34;memcpy(before,image,sizeof(image));
    prefix(BASE);assert(wr(BASE,0x20));assert(wr(BASE,0xd0));assert(wr(BASE,0x70));
    for(unsigned i=0;i<20;i++) { assert(rd(BASE)==0); }
    untouched();
    msm5xxx_protected_nor_advance(&p,4);assert(p.remaining==6);assert(wr(BASE,0xb0));assert(rd(BASE)==0xc0);
    assert(wr(BASE,0xff));assert(rd(BASE)==0x1212);assert(rd(BASE+0x10000)==0xff34);
    msm5xxx_protected_nor_advance(&p,UINT64_MAX);untouched();assert(p.remaining==6 && p.suspended);
    assert(wr(BASE,0xd0));assert(wr(BASE,0x70));assert(rd(BASE)==0);
    msm5xxx_protected_nor_advance(&p,5);untouched();assert(rd(BASE)==0);
    msm5xxx_protected_nor_advance(&p,1);assert(rd(BASE)==0x80 && p.erases==1);
    for(unsigned i=0;i<0x10000;i++)assert(image[i]==0xff);
    assert(image[0x10000]==0x34);finish(BASE,0x80);
    prefix(BASE);assert(wr(BASE,0x77));assert(wr(BASE,0xd0));finish(BASE,0x80);assert(p.verifies==1);
    prefix(BASE+0x10000);assert(!wr(BASE+0x10000,0x77));
    /* Real readback test: corruption is observed, not unconditional ready-success. */
    prefix(BASE);assert(wr(BASE,0x20));assert(wr(BASE,0xd0));msm5xxx_protected_nor_advance(&p,10);finish(BASE,0x80);
    image[10]=0;prefix(BASE);assert(wr(BASE,0x77));assert(wr(BASE,0xd0));assert(wr(BASE,0x70));assert(rd(BASE)==0xa0);assert(wr(BASE,0x50));assert(wr(BASE,0xff));
    memcpy(before,image,sizeof(image));prefix(BASE);assert(wr(BASE,0x20));assert(wr(BASE,0xd0));msm5xxx_protected_nor_reset(&p);msm5xxx_protected_nor_advance(&p,UINT64_MAX);untouched();assert(!wr(BASE,0xd0));
    prefix(BASE);assert(wr(BASE,0x20));assert(wr(BASE,0xd0));assert(!wr(BASE,0x90));msm5xxx_protected_nor_advance(&p,UINT64_MAX);untouched();
    assert(seed[0]==0xff && seed[0x10000]==0xff);
}
int main(void)
{
    test_init();test_single_and_source_checkpoint();test_stream();
    test_prefix_and_foreign();test_errors();test_erase_suspend_verify();
    puts("protected NOR virtual contract selfcheck PASS");
    return 0;
}
