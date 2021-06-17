# Secure messaging

[![CodeFactor](https://www.codefactor.io/repository/github/seraogianluca/secure-messaging/badge)](https://www.codefactor.io/repository/github/seraogianluca/secure-messaging)

## Introduction

Secure messaging is a chatting application that offers confidentiality, integrity and reliability. It achieves confidentiality and integrity through authenticated encryption, whereas reliability with TCP communications.
Secure messaging works on Unix-like systems; we tested it on x86_64 Linux and intel/apple-silicon Mac.

## Compile and test
Just `make` (or `make all`) to compile the code. We tested it on gcc 9.3.0 and clang 12.0.5. Openssl >= 1.1 is required (check the makefile for the install path on mac). After compiling, two files are created (`server_main.out` and `client_main.out`). Just open at least two terminal windows and execute them.
