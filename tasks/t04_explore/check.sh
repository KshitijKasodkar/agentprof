#!/bin/sh
cd "$1" && grep -Eq "^(\./)?src/core/integrity\.py +65521 *$" answer.txt
