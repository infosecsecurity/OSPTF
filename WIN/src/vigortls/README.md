VigorTLS
========

VigorTLS is a fork of OpenSSL developed by Kurt Cancemi.

Some new features added:
*   ChaCha20-Poly1305 Support
*   Support for GOST in the EVP interface

[![Build Status](https://secure.travis-ci.org/vigortls/vigortls.svg)](https://travis-ci.org/vigortls/vigortls)

Goal
====

The goal of the VigorTLS Project is to improve the original OpenSSL codebase
by using modern C features, removing support for ancient operating systems
that are rarely used/hard to support, replacing potentially dangerous
functions/calls with secure ones, replacing the unreadable coding style,
adding in some new features, etc.

Currently tested operating systems
==================================

* Windows: x86, x86_64
* Linux: x86, x86_64, armv6
* Mac OS X: x86_64
* FreeBSD: x86_64
