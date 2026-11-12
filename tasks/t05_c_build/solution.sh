#!/bin/sh
cd "$1" && sed -i "s/    return 1$/    return 1;/" primes.c
