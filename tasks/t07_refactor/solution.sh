#!/bin/sh
cd "$1" && sed -i "s/\bcalc\b/calculate_total/g" pricing.py billing.py cart.py
