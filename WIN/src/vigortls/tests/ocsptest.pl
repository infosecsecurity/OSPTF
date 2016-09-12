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

use strict;
use warnings;

my ($openssl, $ocspdir) = @ARGV;

if (not defined $openssl) {
    die "Missing openssl arg";
}

if (not defined $ocspdir) {
    die "Missing ocspdir arg";
}

my $resp_file = 'resp314159';
my $check_time = "-attime 1355875200";

sub test_ocsp {
    my ($ors, $pem, $expected_ret) = @_;
    open(my $fh, '>:raw', $resp_file) or
        die "Could not open file '$resp_file' $!";
    print $fh `$openssl base64 -d -in $ocspdir/$ors`;
    close $fh;
    my $cmd =
        "$openssl ocsp -respin \"$resp_file\" -partial_chain $check_time".
        " -trusted_first -CAfile $ocspdir/$pem -verify_other $ocspdir/$pem".
        " -CApath .";
    if ((system("$cmd") >> 8) != $expected_ret) {
        unlink $resp_file;
        die "$cmd failed: $?\n";
    }
}

print("=== VALID OCSP RESPONSES ===\n");
print("NON-DELEGATED; Intermediate CA -> EE\n");
test_ocsp("ND1.ors", "ND1_Issuer_ICA.pem", 0);
print("NON-DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("ND2.ors", "ND2_Issuer_Root.pem", 0);
print("NON-DELEGATED; Root CA -> EE\n");
test_ocsp("ND3.ors", "ND3_Issuer_Root.pem", 0);
print("DELEGATED; Intermediate CA -> EE\n");
test_ocsp("D1.ors", "D1_Issuer_ICA.pem", 0);
print("DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("D2.ors", "D2_Issuer_Root.pem", 0);
print("DELEGATED; Root CA -> EE\n");
test_ocsp("D3.ors", "D3_Issuer_Root.pem", 0);

print("=== INVALID SIGNATURE on the OCSP RESPONSE ===\n");
print("NON-DELEGATED; Intermediate CA -> EE\n");
test_ocsp("ISOP_ND1.ors", "ND1_Issuer_ICA.pem", 1);
print("NON-DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("ISOP_ND2.ors", "ND2_Issuer_Root.pem", 1);
print("NON-DELEGATED; Root CA -> EE\n");
test_ocsp("ISOP_ND3.ors", "ND3_Issuer_Root.pem", 1);
print("DELEGATED; Intermediate CA -> EE\n");
test_ocsp("ISOP_D1.ors", "D1_Issuer_ICA.pem", 1);
print("DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("ISOP_D2.ors", "D2_Issuer_Root.pem", 1);
print("DELEGATED; Root CA -> EE\n");
test_ocsp("ISOP_D3.ors", "D3_Issuer_Root.pem", 1);

print("=== WRONG RESPONDERID in the OCSP RESPONSE ===\n");
print("NON-DELEGATED; Intermediate CA -> EE\n");
test_ocsp("WRID_ND1.ors", "ND1_Issuer_ICA.pem", 1);
print("NON-DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("WRID_ND2.ors", "ND2_Issuer_Root.pem", 1);
print("NON-DELEGATED; Root CA -> EE\n");
test_ocsp("WRID_ND3.ors", "ND3_Issuer_Root.pem", 1);
print("DELEGATED; Intermediate CA -> EE\n");
test_ocsp("WRID_D1.ors", "D1_Issuer_ICA.pem", 1);
print("DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("WRID_D2.ors", "D2_Issuer_Root.pem", 1);
print("DELEGATED; Root CA -> EE\n");
test_ocsp("WRID_D3.ors", "D3_Issuer_Root.pem", 1);

print("=== WRONG ISSUERNAMEHASH in the OCSP RESPONSE ===\n");
print("NON-DELEGATED; Intermediate CA -> EE\n");
test_ocsp("WINH_ND1.ors", "ND1_Issuer_ICA.pem", 1);
print("NON-DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("WINH_ND2.ors", "ND2_Issuer_Root.pem", 1);
print("NON-DELEGATED; Root CA -> EE\n");
test_ocsp("WINH_ND3.ors", "ND3_Issuer_Root.pem", 1);
print("DELEGATED; Intermediate CA -> EE\n");
test_ocsp("WINH_D1.ors", "D1_Issuer_ICA.pem", 1);
print("DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("WINH_D2.ors", "D2_Issuer_Root.pem", 1);
print("DELEGATED; Root CA -> EE\n");
test_ocsp("WINH_D3.ors", "D3_Issuer_Root.pem", 1);

print("=== WRONG ISSUERKEYHASH in the OCSP RESPONSE ===\n");
print("NON-DELEGATED; Intermediate CA -> EE\n");
test_ocsp("WIKH_ND1.ors", "ND1_Issuer_ICA.pem", 1);
print("NON-DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("WIKH_ND2.ors", "ND2_Issuer_Root.pem", 1);
print("NON-DELEGATED; Root CA -> EE\n");
test_ocsp("WIKH_ND3.ors", "ND3_Issuer_Root.pem", 1);
print("DELEGATED; Intermediate CA -> EE\n");
test_ocsp("WIKH_D1.ors", "D1_Issuer_ICA.pem", 1);
print("DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("WIKH_D2.ors", "D2_Issuer_Root.pem", 1);
print("DELEGATED; Root CA -> EE\n");
test_ocsp("WIKH_D3.ors", "D3_Issuer_Root.pem", 1);

print("=== WRONG KEY in the DELEGATED OCSP SIGNING CERTIFICATE ===\n");
print("DELEGATED; Intermediate CA -> EE\n");
test_ocsp("WKDOSC_D1.ors", "D1_Issuer_ICA.pem", 1);
print("DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("WKDOSC_D2.ors", "D2_Issuer_Root.pem", 1);
print("DELEGATED; Root CA -> EE\n");
test_ocsp("WKDOSC_D3.ors", "D3_Issuer_Root.pem", 1);

print("=== INVALID SIGNATURE on the DELEGATED OCSP SIGNING CERTIFICATE ===\n");
print("DELEGATED; Intermediate CA -> EE\n");
test_ocsp("ISDOSC_D1.ors", "D1_Issuer_ICA.pem", 1);
print("DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("ISDOSC_D2.ors", "D2_Issuer_Root.pem", 1);
print("DELEGATED; Root CA -> EE\n");
test_ocsp("ISDOSC_D3.ors", "D3_Issuer_Root.pem", 1);

print("=== WRONG SUBJECT NAME in the ISSUER CERTIFICATE ===\n");
print("NON-DELEGATED; Intermediate CA -> EE\n");
test_ocsp("ND1.ors", "WSNIC_ND1_Issuer_ICA.pem", 1);
print("NON-DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("ND2.ors", "WSNIC_ND2_Issuer_Root.pem", 1);
print("NON-DELEGATED; Root CA -> EE\n");
test_ocsp("ND3.ors", "WSNIC_ND3_Issuer_Root.pem", 1);
print("DELEGATED; Intermediate CA -> EE\n");
test_ocsp("D1.ors", "WSNIC_D1_Issuer_ICA.pem", 1);
print("DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("D2.ors", "WSNIC_D2_Issuer_Root.pem", 1);
print("DELEGATED; Root CA -> EE\n");
test_ocsp("D3.ors", "WSNIC_D3_Issuer_Root.pem", 1);

print("=== WRONG KEY in the ISSUER CERTIFICATE ===\n");
print("NON-DELEGATED; Intermediate CA -> EE\n");
test_ocsp("ND1.ors", "WKIC_ND1_Issuer_ICA.pem", 1);
print("NON-DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("ND2.ors", "WKIC_ND2_Issuer_Root.pem", 1);
print("NON-DELEGATED; Root CA -> EE\n");
test_ocsp("ND3.ors", "WKIC_ND3_Issuer_Root.pem", 1);
print("DELEGATED; Intermediate CA -> EE\n");
test_ocsp("D1.ors", "WKIC_D1_Issuer_ICA.pem", 1);
print("DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("D2.ors", "WKIC_D2_Issuer_Root.pem", 1);
print("DELEGATED; Root CA -> EE\n");
test_ocsp("D3.ors", "WKIC_D3_Issuer_Root.pem", 1);

print("=== INVALID SIGNATURE on the ISSUER CERTIFICATE ===\n");
# Expect success, because we're explicitly trusting the issuer certificate.
print("NON-DELEGATED; Intermediate CA -> EE\n");
test_ocsp("ND1.ors", "ISIC_ND1_Issuer_ICA.pem", 0);
print("NON-DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("ND2.ors", "ISIC_ND2_Issuer_Root.pem", 0);
print("NON-DELEGATED; Root CA -> EE\n");
test_ocsp("ND3.ors", "ISIC_ND3_Issuer_Root.pem", 0);
print("DELEGATED; Intermediate CA -> EE\n");
test_ocsp("D1.ors", "ISIC_D1_Issuer_ICA.pem", 0);
print("DELEGATED; Root CA -> Intermediate CA\n");
test_ocsp("D2.ors", "ISIC_D2_Issuer_Root.pem", 0);
print("DELEGATED; Root CA -> EE\n");
test_ocsp("D3.ors", "ISIC_D3_Issuer_Root.pem", 0);

print("ALL OCSP TESTS SUCCESSFUL\n");

unlink $resp_file;

