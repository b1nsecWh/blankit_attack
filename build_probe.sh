#!/bin/bash
set -e
PIN_ROOT=`pwd`/pin-3.6-gcc-linux

pushd $PIN_ROOT/source/tools/Probes
make obj-ia32/decrypt_probe.so  TARGET=ia32
if [ ! -f obj-ia32/decrypt_probe.so ];then
    echo "[-] !!! make errors"
    exit -1
else
    echo "[+] make success."
fi
popd