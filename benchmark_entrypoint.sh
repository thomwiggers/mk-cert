#!/bin/bash -e

if [[ $1 != "kem" && $1 != "sign" && $1 != "xmss" && $1 != "nike" ]]; then
    echo "Usage: $0 <kem/sign> <oqs-algorithm>"
    exit 1;
fi

if [[ "$1" == "kem" ]]; then
    cd /usr/src/kemutil
    echo "pub use oqs::kem::Algorithm::$2 as thealgorithm;" > src/kem.rs
    cargo run --quiet --release --example speed
elif [[ $1 == "sign" ]]; then
    cd /usr/src/signutil
    echo "pub use oqs::sig::Algorithm::$2 as alg;" > src/lib.rs
    cargo run --quiet --release --example speed
elif [[ $1 == "xmss" ]]; then
    cd /usr/src/xmss-rs
    if [[ $2 == "XMSS1" ]]; then
        level="level1"
    elif [[ $2 == "XMSS3" ]]; then
        level="level3"
    elif [[ $2 == "XMSS5" ]]; then
        level="level5"
    else
        echo "WTF unknown xmss $2" 1>&2
        exit 1
    fi
    cargo run --quiet --release --features $level --example speed
elif [[ $1 == "nike" ]]; then
    cd /usr/src/csidhutil
    echo "pub use secsidh::csidh2047k221 as csidh;" > src/instance.rs
    cargo run --quiet --release --example speed
fi
