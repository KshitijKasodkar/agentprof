#!/bin/sh
cd "$1" && [ -x .venv/bin/python ] && .venv/bin/python -c "import tabulate" && grep -q "+-------" table.txt && grep -q "meera" table.txt
