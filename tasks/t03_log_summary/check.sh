#!/bin/sh
cd "$1" && diff -bq summary.txt "$(dirname "$0")/expected.txt" >/dev/null
