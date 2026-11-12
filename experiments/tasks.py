"""Benchmark task helpers: load, prepare a fresh working copy, check."""
import json
import os
import shutil
import subprocess

TASKS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tasks")


def load_tasks(ids=None):
    out = []
    for name in sorted(os.listdir(TASKS_DIR)):
        d = os.path.join(TASKS_DIR, name)
        p = os.path.join(d, "task.json")
        if not os.path.exists(p):
            continue
        t = json.load(open(p))
        t["dir"] = d
        if ids and t["id"] not in ids and not any(t["id"].startswith(i) for i in ids):
            continue
        out.append(t)
    return out


def prepare(task, work):
    """Fresh copy of the task's files in `work` (+ optional setup.sh)."""
    if os.path.exists(work):
        shutil.rmtree(work)
    shutil.copytree(os.path.join(task["dir"], "files"), work)
    setup = os.path.join(task["dir"], "setup.sh")
    if os.path.exists(setup):
        subprocess.run([setup, work], check=True, capture_output=True)


def check(task, work):
    # the checker runs as root on files owned by the agent's user: tell git that is fine
    env = {**os.environ, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"}
    r = subprocess.run([os.path.join(task["dir"], "check.sh"), work], capture_output=True, timeout=300, env=env)
    return r.returncode == 0
