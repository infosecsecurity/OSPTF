#!/usr/bin/env perl

# ============================================================================
# Copyright (c) 2016, Kurt Cancemi (kurt@x64architecture.com)
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# ============================================================================

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

print<<___;
.text

# int vigortls_rdrand(uint8_t *buf)
.globl   vigortls_rdrand
.type    vigortls_rdrand,\@function
.align    16
vigortls_rdrand:
    rdrand %rdx
    setc   %al
    movzb  %al, %rax
    mov    %rdx, (%rdi)
    ret

# int vigortls_rdrand_mul_of_8(uint8_t *buf, size_t len)
.globl vigortls_rdrand_mul_of_8
.type vigortls_rdrand_mul_of_8,\@function,2
.align 16
vigortls_rdrand_mul_of_8:
    mov \$8, %rcx
.Loop:
    rdrand %rdx
    jnc .Lrand_unavailable
    mov %rdx, (%rdi)
    add %rcx, %rdi
    sub %rcx, %rsi
    jnz .Loop
    mov \$1, %rax
    ret
.Lrand_unavailable:
    xor %rax, %rax
    ret
___

close STDOUT;    # flush
