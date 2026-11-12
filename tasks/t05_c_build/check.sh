#!/bin/sh
cd "$1" && make -s >/dev/null 2>&1 && [ "$(./primes 30)" = "2 3 5 7 11 13 17 19 23 29" ]
