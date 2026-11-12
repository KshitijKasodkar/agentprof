#!/bin/sh
cd "$1" && [ "$(git log -1 --format=%s)" = "fix greeting" ] && git show --stat HEAD | grep -q app.py && ! git show --stat HEAD | grep -q notes.txt && [ -n "$(git status --porcelain notes.txt)" ]
