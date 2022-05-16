#!/bin/bash
set -e


function build(){
    echo "================[build blankit]================="

    echo  "[1] building libblankit.so...."
    if [ ! -f ./blankit/libblankit.so ];then
        pushd ./blankit
        make
        popd
    fi

    if [ ! -d ./build ];then
        mkdir ./build
    fi

    echo "[2] embedding decision tree...."
    ./build_llvm.sh

    echo "[3] building runtime pin probe...."
    ./build_probe.sh

    echo "------------------ success ----------------------"
}

function clean(){
    rm -rf ./blankit/blankit.o ./blankit/libblankit.so
    rm -rf ./build/*
    rm -rf ./pin-3.6-gcc-linux/source/tools/Probes/obj-ia32/decrypt_probe.o
    rm -rf pin-3.6-gcc-linux/source/tools/Probes/obj-ia32/decrypt_probe.so
}


if [ "$1" == "-clean" ];then
    clean
else
    build
fi

