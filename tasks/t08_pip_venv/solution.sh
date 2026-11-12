#!/bin/sh
cd "$1" && python3 -m venv .venv && .venv/bin/pip -q install tabulate && .venv/bin/python -c "import csv,tabulate;r=list(csv.reader(open(\"data.csv\")));open(\"table.txt\",\"w\").write(tabulate.tabulate(r[1:],headers=r[0],tablefmt=\"grid\"))"
