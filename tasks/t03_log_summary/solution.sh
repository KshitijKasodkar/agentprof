#!/bin/sh
cd "$1" && awk "{print \$9}" access.log | sort -n | uniq -c | awk "{print \$2, \$1}" > summary.txt
