#!/bin/sh
cd "$1" && git add app.py && git commit -qm "fix greeting"
