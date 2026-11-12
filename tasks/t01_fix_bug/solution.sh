#!/bin/sh
cd "$1" && sed -i "s/return (s\[mid\] + s\[mid + 1\]) \/ 2/return (s[mid - 1] + s[mid]) \/ 2/" stats.py
