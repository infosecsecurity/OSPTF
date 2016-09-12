#include "arm_arch.h"

.text
.code	32

.align	5
#if __ARM_ARCH__ >= 7
.global	_armv7_neon_probe
.type	_armv7_neon_probe,%function
_armv7_neon_probe:
	.byte	0xf0,0x01,0x60,0xf2	@ vorr	q8,q8,q8
	.byte	0x1e,0xff,0x2f,0xe1	@ bx	lr
.size	_armv7_neon_probe,.-_armv7_neon_probe

.global	_armv7_tick
.type	_armv7_tick,%function
_armv7_tick:
	mrc	p15,0,r0,c9,c13,0
	.word	0xe12fff1e	@ bx	lr
.size	_armv7_tick,.-_armv7_tick
#endif

#if __ARM_ARCH__ >= 8
.global	_armv8_aes_probe
.type	_armv8_aes_probe,%function
_armv8_aes_probe:
	.byte	0x00,0x03,0xb0,0xf3	@ aese.8	q0,q0
	.byte	0x1e,0xff,0x2f,0xe1	@ bx	lr
.size	_armv8_aes_probe,.-_armv8_aes_probe

.global	_armv8_sha1_probe
.type	_armv8_sha1_probe,%function
_armv8_sha1_probe:
	.byte	0x40,0x0c,0x00,0xf2	@ sha1c.32	q0,q0,q0
	.byte	0x1e,0xff,0x2f,0xe1	@ bx	lr
.size	_armv8_sha1_probe,.-_armv8_sha1_probe

.global	_armv8_sha256_probe
.type	_armv8_sha256_probe,%function
_armv8_sha256_probe:
	.byte	0x40,0x0c,0x00,0xf3	@ sha256h.32	q0,q0,q0
	.byte	0x1e,0xff,0x2f,0xe1	@ bx lr
.size	_armv8_sha256_probe,.-_armv8_sha256_probe
.global	_armv8_pmull_probe
.type	_armv8_pmull_probe,%function
_armv8_pmull_probe:
	.byte	0x00,0x0e,0xa0,0xf2	@ vmull.p64	q0,d0,d0
	.byte	0x1e,0xff,0x2f,0xe1	@ bx	lr
.size	_armv8_pmull_probe,.-_armv8_pmull_probe
#endif