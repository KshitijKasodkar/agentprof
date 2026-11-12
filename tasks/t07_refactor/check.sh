#!/bin/sh
cd "$1" && python3 run_tests.py && ! grep -rn --include=*.py "\bcalc(" .
