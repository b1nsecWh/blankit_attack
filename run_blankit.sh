#!/bin/bash

PIN_ROOT=`pwd`/pin-3.6-gcc-linux


function run(){
    echo "run()"

    export LD_LIBRARY_PATH=`pwd`/blankit
    export BLANKIT_APP_NAME=`pwd`/build/example_embedpin
    export BLANKIT_APPROVED_LIST=`pwd`/data/approved_list.txt
    export BLANKIT_PREDICT_SETS=`pwd`/data/string2id_map.csv

    $PIN_ROOT/pin -t $PIN_ROOT/source/tools/Probes/obj-ia32/decrypt_probe.so -- ./build/example_embedpin
}

run