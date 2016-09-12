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

my ($ssltestexe, $testdir, $openssl) = @ARGV;

if (not defined $ssltestexe) {
    die "Missing ssltestexe arg";
}

if (not defined $testdir) {
    die "Missing testdir arg";
}

if (not defined $openssl) {
    die "Missing openssl arg";
}

my $key         = "$testdir/server.pem";
my $cert        = "$testdir/server.pem";
my $CA          = "-CAfile $testdir/ca.pem";
my $serverinfo  = "$testdir/serverinfo.pem";
my $extra       = "";

my $ssltestcmd = "$ssltestexe -key $key -cert $cert -c_key $key -c_cert $cert";

sub ssltest {
    my ($args) = shift;
    system("$ssltestcmd $args") == 0 or
        die "$ssltestcmd $args failed: $?";
}

sub test_cipher {
    my $cipher   = shift;
    my $protoarg = shift;
    if (not defined $protoarg) {
        $protoarg = "";
    }
    print("Testing $cipher\n");
    ssltest("$protoarg -cipher $cipher");
}

print("Testing TLS\n");
ssltest("$extra");

print("Testing TLS with server authentication\n");
ssltest("-server_auth $CA $extra");

print("Testing TLS with client authentication\n");
ssltest("-client_auth $CA $extra");

print("Testing TLS with both client and server authentication\n");
ssltest("-server_auth -client_auth $CA $extra");

print("Testing TLS w/o (EC)DHE via BIO pair\n");
ssltest("-bio_pair -no_dhe -no_ecdhe $extra");

print("Testing TLS with 1024-bit DHE via BIO pair\n");
ssltest("-bio_pair -dhe1024dsa -v $extra");

print("Testing TLS with server authentication via BIO pair\n");
ssltest("-bio_pair -server_auth $CA $extra");

print("Testing TLS with client authentication via BIO pair\n");
ssltest("-bio_pair -client_auth $CA $extra");

print("Testing TLS with both client and server authentication via BIO pair\n");
ssltest("-bio_pair -server_auth -client_auth $CA $extra");

print("Testing TLS with both client and server authentication via BIO pair and app verify\n");
ssltest("-bio_pair -server_auth -client_auth -app_verify $CA $extra");

print("Testing TLSv1 with 1024-bit anonymous DH, multiple handshakes\n");
ssltest("-v -bio_pair -tls1 -cipher ADH -dhe1024dsa -num 10 -f -time $extra");

print("Testing TLSv1 with 1024-bit RSA, no (EC)DHE, multiple handshakes\n");
ssltest("-v -bio_pair -tls1 -no_dhe -no_ecdhe -num 10 -f -time $extra");

print("Testing TLSv1 with 1024-bit RSA, 1024-bit DHE, multiple handshakes\n");
ssltest("-v -bio_pair -tls1 -dhe1024dsa -num 10 -f -time $extra");

print("Testing TLS ciphersuites\n");
my @protocols = ("TLSv1", "TLSv1.2");
foreach (@protocols) {
    my $protocol = $_;
    print("Testing ciphersuites for $protocol\n");
    my $ciphers;
    $ciphers = `$openssl ciphers "RSA+$protocol"`;
    test_cipher $_, for split(':', $ciphers);
    $ciphers = `$openssl ciphers "EDH+aRSA+$protocol:-EXP"`;
    test_cipher $_, for split(':', $ciphers);
    $ciphers = `$openssl ciphers "EECDH+aRSA+$protocol:-EXP"`;
    test_cipher $_, for split(':', $ciphers);
}

# DTLS Tests

print("Testing DTLSv1\n");
ssltest("-dtls1 $extra");

print("Testing DTLSv1 with server authentication\n");
ssltest("-dtls1 -server_auth $CA $extra");

print("Testing DTLSv1 with client authentication\n");
ssltest("-dtls1 -client_auth $CA $extra");

print("Testing DTLSv1 with both client and server authentication\n");
ssltest("-dtls1 -server_auth -client_auth $CA $extra");

print("Testing DTLSv1.2");
ssltest("-dtls12 $extra");

print("Testing DTLSv1.2 with server authentication\n");
ssltest("-dtls12 -server_auth $CA $extra");

print("Testing DTLSv1.2 with client authentication\n");
ssltest("-dtls12 -client_auth $CA $extra");

print("Testing DTLSv1.2 with both client and server authentication\n");
ssltest("-dtls12 -server_auth -client_auth $CA $extra");

print("Testing DTLS ciphersuites\n");
@protocols = ("TLSv1", "TLSv1.2");
foreach (@protocols) {
    my $protocol = $_;
    my $protoarg;
    if ($protocol eq "TLSv1") {
        $protoarg = "-dtls1";
    } elsif ($protocol eq "TLSv1.2") {
        $protoarg = "-dtls12";
    }

    print("Testing ciphersuites for D$protocol\n");
    my $ciphers;
    $ciphers = `$openssl ciphers "RSA+$protocol:!RC4"`;
    test_cipher($_, $protoarg), for split(':', $ciphers);
    $ciphers = `$openssl ciphers "EDH+aRSA+$protocol:-EXP:!RC4"`;
    test_cipher($_, $protoarg), for split(':', $ciphers);
    $ciphers = `$openssl ciphers "EECDH+aRSA+$protocol:-EXP:!RC4"`;
    test_cipher($_, $protoarg), for split(':', $ciphers);
}

# Custom Extension tests

print("Testing TLSv1 with custom extensions\n");
ssltest("-bio_pair -tls1 -custom_ext");

# Serverinfo tests

print("Testing TLSv1 with serverinfo\n");
ssltest("-bio_pair -tls1 -serverinfo_file $serverinfo");
ssltest("-bio_pair -tls1 -serverinfo_file $serverinfo -serverinfo_sct");
ssltest("-bio_pair -tls1 -serverinfo_file $serverinfo -serverinfo_tack");
ssltest("-bio_pair -tls1 -serverinfo_file $serverinfo -serverinfo_sct -serverinfo_tack");
ssltest("-bio_pair -tls1 -custom_ext -serverinfo_file $serverinfo".
        " -serverinfo_sct -serverinfo_tack");

# Next Protocol Negotiation tests

print("Testing NPN...\n");
ssltest("-bio_pair -tls1 -npn_client");
ssltest("-bio_pair -tls1 -npn_server");
ssltest("-bio_pair -tls1 -npn_server_reject");
ssltest("-bio_pair -tls1 -npn_client -npn_server_reject");
ssltest("-bio_pair -tls1 -npn_client -npn_server");
ssltest("-bio_pair -tls1 -npn_client -npn_server -num 2");
ssltest("-bio_pair -tls1 -npn_client -npn_server -num 2 -reuse");

# SNI tests

print("Testing SNI...\n");
ssltest("-bio_pair -sn_client foo");
ssltest("-bio_pair -sn_server1 foo");
ssltest("-bio_pair -sn_client foo -sn_server1 foo -sn_expect1");
ssltest("-bio_pair -sn_client foo -sn_server1 bar -sn_expect1");
ssltest("-bio_pair -sn_client foo -sn_server1 foo -sn_server2 bar -sn_expect1");
ssltest("-bio_pair -sn_client bar -sn_server1 foo -sn_server2 bar -sn_expect2");
# Negative test - make sure it doesn't crash, and doesn't switch contexts
ssltest("-bio_pair -sn_client foobar -sn_server1 foo -sn_server2 bar -sn_expect1");

# ALPN tests

print("Testing ALPN...\n");
ssltest("-bio_pair -tls1 -alpn_client foo -alpn_server bar");
ssltest("-bio_pair -tls1 -alpn_client foo -alpn_server foo -alpn_expected foo");
ssltest("-bio_pair -tls1 -alpn_client foo,bar -alpn_server foo -alpn_expected foo");
ssltest("-bio_pair -tls1 -alpn_client bar,foo -alpn_server foo -alpn_expected foo");
ssltest("-bio_pair -tls1 -alpn_client bar,foo -alpn_server foo,bar -alpn_expected foo");
ssltest("-bio_pair -tls1 -alpn_client bar,foo -alpn_server bar,foo -alpn_expected bar");
ssltest("-bio_pair -tls1 -alpn_client foo,bar -alpn_server bar,foo -alpn_expected bar");
ssltest("-bio_pair -tls1 -alpn_client baz -alpn_server bar,foo");

# ALPN + SNI

print("Testing ALPN + SNI...\n");
ssltest("-bio_pair -alpn_client foo,bar -sn_client alice -alpn_server1 foo,123".
        " -sn_server1 alice -alpn_server2 bar,456 -sn_server2 bob -alpn_expected foo");
ssltest("-bio_pair -alpn_client foo,bar -sn_client bob -alpn_server1 foo,123".
        " -sn_server1 alice -alpn_server2 bar,456 -sn_server2 bob -alpn_expected bar");
ssltest("-bio_pair -alpn_client foo,bar -sn_client bob -sn_server1 alice".
        " -alpn_server2 bar,456 -sn_server2 bob -alpn_expected bar");

# Multi-buffer tests
my $arch = `uname -m`;
$arch =~ s/\n//;
if ($arch eq "x86_64") {
    print("Testing multi-buffer...\n");
    ssltest("-cipher AES128-SHA -bytes 8m");
    ssltest("-cipher AES128-SHA256 -bytes 8m");
}

