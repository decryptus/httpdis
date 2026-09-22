#!/usr/bin/env bash
set -euo pipefail
python -m pip install --upgrade pip
python - <<'BOOT'
import subprocess, sys
if sys.version_info < (3,):
    deps = ['setuptools<45', 'wheel<0.35', 'PyYAML<6']
elif sys.version_info < (3, 6):
    deps = ['setuptools<51', 'wheel<0.35', 'PyYAML<6']
elif sys.version_info < (3, 8):
    deps = ['setuptools<60', 'wheel', 'PyYAML<6']
else:
    deps = ['setuptools<81', 'wheel', 'PyYAML']
subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + deps)
BOOT
# Copy before building: the source checkout is read-only.
cp -R /src /tmp/source
# Seed the package under test before pip 20 resolves circular dependencies.
python -m pip install --no-build-isolation --no-deps /tmp/source
python -m pip install --no-build-isolation /tmp/source "sonicprobe==0.3.52" "dwho==0.3.61" mock
cd /tmp
python -B -m unittest discover -s /tmp/source/tests -v
