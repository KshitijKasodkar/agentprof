#!/bin/sh
cd "$1" && git init -q && git config user.email t@t && git config user.name t && git add app.py notes.txt && git commit -qm init && printf 'print("hello, world")\n' > app.py && printf 'scratch more\n' >> notes.txt
