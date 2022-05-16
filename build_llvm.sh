#!/bin/bash
set -e

if [ ! -d build ];then
    mkdir build
fi

pushd ./build
    rm -rf example example.ll example_opt.ll example.bc example_opt.bc example.o
popd

if [ "$1" == "-clean" ];then
    exit 0

fi


if [ ! -f ./blankit/libblankit.so ];then
    pushd ./blankit
        make
        if [ $? -ne 0 ]; then
            echo "make fail, exit"
            exit -1
        fi
    popd
fi


pushd ./llvm
    pushd ./build
        cmake ../
        make
        if [ $? -ne 0 ]; then
            echo "make fail, exit"
            exit -1
        fi
    popd
popd

if [ ! -f ./llvm/build/embedDtree/libembedDtree.so ];then
    echo "llvm error"
    exit 0
fi

pushd ./build
    if [ "$1" == "-debug" ];then
        clang -O0 -m32  -fno-stack-protector -emit-llvm -fno-builtin  ../example.c -c -o example.ll
        opt -S -o example_opt.ll -load ../llvm/build/embedDtree/libembedDtree.so -embedDtree < example.ll >/dev/null
    else
        # example.c         ------->     example.bc
        clang -O0 -m32  -fno-stack-protector -emit-llvm -fno-builtin  ../example.c -c -o example.bc 
        # example.bc        --pass->     example_opt.bc
        opt -o example_opt.bc -load ../llvm/build/embedDtree/libembedDtree.so -embedDtree < example.bc 
        # example_opt.bc    ------->     example.o
        llc -filetype=obj example_opt.bc -o example.o
        # example.o         ------->     example
        clang -m32 -z execstack -o example_embedpin example.o /root/blankit_attack/blankit/libblankit.so
        # # show
        # objdump -S example_embedpin |grep -A100 "<main>"
    fi
popd