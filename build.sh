#!/bin/bash

DIR=$(pwd)
# Target: aarch64-linux, arm-linux
TARGET="aarch64-linux"

# Download zigcc
if [ ! -d "$DIR/zig" ]; then
    curl -L https://ziglang.org/download/0.14.1/zig-x86_64-linux-0.14.1.tar.xz -o zig.tar.xz
    mkdir zig && tar -xf zig.tar.xz -C zig --strip-components=1 && rm -f zig.tar.xz
fi

export PATH=$DIR/zig:$PATH

# Download openssl latest stable release
if [ ! -d "$DIR/openssl" ]; then
    OPENSSL_URL=$(curl -Ls https://api.github.com/repos/openssl/openssl/releases/latest | jq -r '.assets[] | select(.name | endswith(".tar.gz")) | .browser_download_url')
    wget "$OPENSSL_URL" -O openssl.tar.gz
    mkdir openssl && tar -xvf openssl.tar.gz -C openssl --strip-components=1 && rm -f openssl.tar.gz
fi

# Build OpenSSL
if [ ! -d "$DIR/out" ] || [ "$1" = "clean" ]; then
    rm -rf out
    mkdir out
    cd openssl
    make clean

    # Compile OpenSSL with zig cc
    CC="zig cc -target $TARGET" ./config --prefix="$DIR/out" -fPIC no-shared no-module no-autoload-config no-asm no-ui-console \
        no-dh no-dsa no-ec2m no-sm2 no-sm3 no-sm4 \
        no-ssl no-tls no-dtls no-engine no-ocsp no-cms no-ts no-psk no-srp no-async no-comp no-nextprotoneg \
        no-aria no-bf no-camellia no-cast no-des no-idea no-rc2 no-rc4 no-rc5 no-seed no-chacha no-poly1305
    make -j$(nproc)
    make install

    cd ..
    mv out/lib* out/lib
fi

# Build keygen
rm -rf build
mkdir build && cd build

export CC="zig cc -target $TARGET"
export CXX="zig c++ -target $TARGET"

cmake ..
cmake --build .
