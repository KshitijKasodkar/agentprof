#!/bin/sh
cd "$1" && python3 test_stats.py && grep -q "assert median(\[4, 1, 3, 2\]) == 2.5" test_stats.py
