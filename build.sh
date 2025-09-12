#!/bin/bash

DIR=$(readlink -f .)
if [ -d "/opt/android-ndk" ]; then
    NDK_HOME="/opt/android-ndk"
else
    NDK_HOME="$DIR/android-ndk"
fi

if [ ! -d "$NDK_HOME" ]; then
    LATEST_NDK_URL=$(curl -s https://developer.android.com/ndk/downloads | grep -oP 'https://dl.google.com/android/repository/android-ndk-r[0-9]+[a-z]?-linux\.zip' | head -n 1)
    [ -z "$LATEST_NDK_URL" ] && LATEST_NDK_URL="https://dl.google.com/android/repository/android-ndk-r27c-linux.zip"
    NDK_ZIP="android-ndk.zip"
    wget "$LATEST_NDK_URL" -O "$NDK_ZIP"
    TEMP_DIR=$(mktemp -d)
    unzip "$NDK_ZIP" -d "$TEMP_DIR"
    EXTRACTED_DIR=$(find "$TEMP_DIR" -maxdepth 1 -name "android-ndk-*" -type d | head -n 1)
    mv -f "$EXTRACTED_DIR" "$NDK_HOME"

    # Clean up
    rm -rf "$TEMP_DIR" "$NDK_ZIP"
fi

# Download openssl latest stable release
if [ ! -d "$DIR/openssl" ]; then
    OPENSSL_URL=$(curl -Ls https://api.github.com/repos/openssl/openssl/releases/latest | jq -r '.assets[] | select(.name | endswith(".tar.gz")) | .browser_download_url')
    wget "$OPENSSL_URL" -O openssl.tar.gz
    mkdir openssl && tar -xvf openssl.tar.gz -C openssl --strip-components=1 && rm -rf openssl.tar.gz
fi

mkdir -p "$DIR/out"
cd openssl
make clean

export ANDROID_NDK_ROOT="$NDK_HOME"
PATH=$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$NDK_HOME/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH

# Compile for android arm64
./Configure android-arm64 -D__ANDROID_API__=29 -DOPENSSL_NO_CONF --prefix="$DIR/out" \
    no-shared no-module no-autoload-config no-asm no-ui-console \
    no-dh no-dsa no-ec2m no-sm2 no-sm3 no-sm4 \
    no-ssl no-tls no-dtls no-engine no-ocsp no-cms no-ts no-psk no-srp no-async no-comp no-nextprotoneg \
    no-aria no-bf no-camellia no-cast no-des no-idea no-rc2 no-rc4 no-rc5 no-seed no-chacha no-poly1305
make -j$(nproc)
make install

# Build keygen
cmake .. \
    -DCMAKE_TOOLCHAIN_FILE=$NDK_HOME/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI="arm64-v8a" \
    -DANDROID_NATIVE_API_LEVEL="29"

cmake --build .
