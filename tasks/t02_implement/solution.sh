#!/bin/sh
cd "$1" && cat > words.py <<'PY'
import re
from collections import Counter


def top_words(text, k):
    c = Counter(re.findall(r"[a-z]+", text.lower()))
    return sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:k]
PY
