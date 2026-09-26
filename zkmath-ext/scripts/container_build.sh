#!/usr/bin/env bash
# Runs inside the zkmath-ext container. Assembles emp-zk + ZKMath + our overlay in /build and builds.
set -euo pipefail
SRC=/build/emp-zk
if [ ! -d "$SRC" ]; then
    cp -r /opt/emp-zk "$SRC"
    cp -rf /opt/ZKMath/src/* "$SRC/emp-zk/"
    cp -rf /opt/ZKMath/test/math "$SRC/test/"
fi
cp -f /ext/src/emp-zk.h "$SRC/emp-zk/emp-zk.h"
cp -f /ext/src/ZKmath-ext* /ext/src/LUT-multi.h "$SRC/emp-zk/emp-zk-math/"
cp -f /ext/src/bench_ext.cpp "$SRC/test/math/"
cp -f /ext/CMakeLists.txt "$SRC/CMakeLists.txt"
cd "$SRC"
cmake -DCMAKE_BUILD_TYPE=Release . > /dev/null
make -j"$(nproc)" "$@"
