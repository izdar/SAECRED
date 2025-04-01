#!/bin/bash

DIR1="./WiFiPacketGen/"
CMD1="dune exec sbf"

DIR2="../sae-learn/"
CMD2="sudo python3 Driver.py"

run_and_terminate() {
    cd "$1" || exit

    if [[ "$1" == "$DIR1" ]]; then
        eval $(opam env)
    fi

    $2 &
    PID1=$!

    cd "$3" || exit
    $4 &
    PID2=$!

    sleep 86400

    kill -SIGINT $PID1
    kill -SIGINT $PID2
}

run_and_terminate "$DIR1" "$CMD1" "$DIR2" "$CMD2"
